#include "PtraceController.h"

namespace DebuggerEngine
{
    // --- Lifecycle and Process Control ---

    PtraceController::PtraceController()
        : m_pid(-1),
          m_is_tracer_thread_active(false),
          m_tracee_state(TraceeState::NotStarted),
          m_ptrace_request(static_cast<__ptrace_request>(0))
    {
    }

    PtraceController::~PtraceController()
    {
        // Signal the tracer thread to stop (non-blocking)
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_is_tracer_thread_active = false;
            // Don't wait here - just signal it to stop
        }

        // Kill the process if it exists (this will cause tracer thread to exit)
        pid_t pid_to_kill = -1;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            if (m_pid > 0 && m_tracee_state != TraceeState::Exited) {
                pid_to_kill = m_pid;
            }
        }
        
        if (pid_to_kill > 0) {
            // Kill without holding the mutex to avoid deadlock
            kill(pid_to_kill, SIGKILL);
        }

        // Wait for tracer thread to finish (it will exit when the process dies)
        if (m_tracer_thread.joinable()) {
            m_tracer_thread.join();
        }

        // Final cleanup - reap any remaining zombie process
        if (pid_to_kill > 0) {
            int status;
            // Use WNOHANG in case the process was already reaped by the tracer thread
            while (waitpid(pid_to_kill, &status, WNOHANG) > 0) {
                // Process was reaped
            }
            // If WNOHANG didn't work, try one blocking wait with short timeout
            // This handles the case where the process just died
            waitpid(pid_to_kill, &status, 0);
        }
    }

    bool PtraceController::launch(const std::string &path, const std::vector<std::string> &args)
    {
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            if (m_pid != -1)
            {
                std::cerr << "Error: A process is already being traced." << std::endl;
                return false;
            }
        }

        m_pid = fork();

        if (m_pid == -1)
        {
            perror("fork");
            return false;
        }

        if (m_pid == 0) // Child process
        {
            // Allow the parent process to trace this child
            if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) < 0)
            {
                perror("ptrace(TRACEME)");
                exit(1);
            }

            // Convert std::vector<std::string> to char* const* for execvp
            std::vector<char*> argv;
            for (const auto& arg : args)
            {
                argv.push_back(const_cast<char*>(arg.c_str()));
            }
            argv.push_back(nullptr);

            // Replace the child process image with the target program
            execvp(path.c_str(), argv.data());

            // execvp only returns on error
            perror("execvp");
            exit(1);
        }
        else // Parent process
        {
            // Wait for the child to stop on its initial SIGTRAP from execvp
            int status;
            if (waitpid(m_pid, &status, 0) < 0) {
                perror("waitpid in launch");
                kill(m_pid, SIGKILL);
                waitpid(m_pid, nullptr, 0);
                m_pid = -1;
                return false;
            }

            if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP)
            {
                // Successfully stopped, set up the tracer thread and initial state
                std::lock_guard<std::mutex> lock(m_mutex);
                m_is_tracer_thread_active = true;
                m_tracee_state = TraceeState::Stopped;
                m_tracer_thread = std::thread(&PtraceController::tracerLoop, this);
                return true;
            }
            else
            {
                // Something went wrong, kill the child and clean up
                std::cerr << "Error: Failed to stop child process after launch. Status: " << status << std::endl;
                kill(m_pid, SIGKILL);
                waitpid(m_pid, nullptr, 0);
                m_pid = -1;
                return false;
            }
        }
    }

    bool PtraceController::terminate()
    {
        std::unique_lock<std::mutex> lock(m_mutex);
        
        if (m_pid <= 0 || m_tracee_state == TraceeState::Exited)
        {
            return true; // Nothing to do
        }

        pid_t target_pid = m_pid; // Copy PID before releasing lock
        lock.unlock();

        // Send the kill signal without holding the lock
        if (kill(target_pid, SIGKILL) < 0)
        {
            perror("kill");
            return false;
        }

        // Wait for the process to actually exit
        lock.lock();
        auto timeout = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        bool exited = m_cv_tracee_stopped.wait_until(lock, timeout, [this] {
            return m_tracee_state == TraceeState::Exited;
        });

        if (!exited) {
            std::cerr << "Warning: Process didn't exit within timeout" << std::endl;
            return false;
        }

        return true;
    }

    bool PtraceController::detach()
    {
        std::unique_lock<std::mutex> lock(m_mutex);

        if (m_tracee_state != TraceeState::Stopped) {
            std::cerr << "Error: Can only detach from a stopped process." << std::endl;
            return false;
        }

        if (ptrace(PTRACE_DETACH, m_pid, nullptr, nullptr) < 0) {
            perror("ptrace(DETACH)");
            return false;
        }
        
        // Update state and stop tracer thread
        m_tracee_state = TraceeState::Exited;
        m_pid = -1;
        lock.unlock();
        
        stopTracerThread();
        return true;
    }


    // --- Execution Control ---

    bool PtraceController::continueExecution()
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        if (m_tracee_state != TraceeState::Stopped) {
            std::cerr << "Error: Cannot continue - process state is not Stopped (current: " 
                      << static_cast<int>(m_tracee_state) << ")" << std::endl;
            return false;
        }

        // Execute ptrace directly - no thread communication needed
        if (ptrace(PTRACE_CONT, m_pid, nullptr, nullptr) < 0) {
            perror("ptrace(CONT)");
            return false;
        }

        // Update state immediately
        m_tracee_state = TraceeState::Running;
        return true;
    }

    bool PtraceController::step()
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        if (m_tracee_state != TraceeState::Stopped) {
            std::cerr << "Error: Cannot step - process state is not Stopped" << std::endl;
            return false;
        }

        // Execute ptrace directly
        if (ptrace(PTRACE_SINGLESTEP, m_pid, nullptr, nullptr) < 0) {
            perror("ptrace(SINGLESTEP)");
            return false;
        }

        // PTRACE_SINGLESTEP executes one instruction and then stops automatically
        // So we briefly transition to Running, but the tracerLoop will soon
        // detect the stop and update back to Stopped
        m_tracee_state = TraceeState::Running;
        return true;
    }

    bool PtraceController::interrupt()
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        if (m_pid <= 0 || m_tracee_state != TraceeState::Running) {
            std::cerr << "Error: Cannot interrupt - invalid PID or process not running" << std::endl;
            return false;
        }

        // Use SIGSTOP signal instead of PTRACE_INTERRUPT for better compatibility
        if (kill(m_pid, SIGSTOP) < 0)
        {
            perror("kill(SIGSTOP)");
            return false;
        }

        return true;
    }

    bool PtraceController::waitForStop()
    {
        std::unique_lock<std::mutex> lock(m_mutex);
        m_cv_tracee_stopped.wait(lock, [this] {
            return m_tracee_state != TraceeState::Running;
        });
        return m_tracee_state == TraceeState::Stopped;
    }


    // --- State Inspection and Manipulation ---

    template <typename Func>
    inline bool PtraceController::executeIfStopped(Func ptrace_op, const char *op_name) const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_tracee_state != TraceeState::Stopped) {
            std::cerr << "Error: Process must be in Stopped state for " << op_name << std::endl;
            return false;
        }
        if (ptrace_op()) {
            perror(op_name);
            return false;
        }
        return true;
    }

    bool PtraceController::getRegisters(Registers &regs) const
    {
        return executeIfStopped([&]() {
            return ptrace(PTRACE_GETREGS, m_pid, nullptr, &regs) != 0;
        }, "PTRACE_GETREGS");
    }

    bool PtraceController::setRegisters(const Registers &regs) const
    {
        return executeIfStopped([&]() {
            return ptrace(PTRACE_SETREGS, m_pid, nullptr, const_cast<Registers*>(&regs)) != 0;
        }, "PTRACE_SETREGS");
    }

    bool PtraceController::readMemory(uint64_t addr, size_t size, void *buffer) const
    {
        return executeIfStopped([&]() {
            struct iovec local_iov = { buffer, size };
            struct iovec remote_iov = { (void*)addr, size };
            return process_vm_readv(m_pid, &local_iov, 1, &remote_iov, 1, 0) < 0;
        }, "process_vm_readv");
    }

    bool PtraceController::writeMemory(uint64_t addr, size_t size, const void *buffer) const
    {
        return executeIfStopped([&]() {
            struct iovec local_iov = { const_cast<void*>(buffer), size };
            struct iovec remote_iov = { (void*)addr, size };
            return process_vm_writev(m_pid, &local_iov, 1, &remote_iov, 1, 0) < 0;
        }, "process_vm_writev");
    }

    long PtraceController::peekData(uint64_t addr) const
    {
        long data = -1;
        executeIfStopped([&]() {
            errno = 0;
            data = ptrace(PTRACE_PEEKDATA, m_pid, addr, nullptr);
            return errno != 0;
        }, "PTRACE_PEEKDATA");
        return data;
    }

    bool PtraceController::pokeData(uint64_t addr, long value) const
    {
        return executeIfStopped([&]() {
            return ptrace(PTRACE_POKEDATA, m_pid, addr, value) != 0;
        }, "PTRACE_POKEDATA");
    }


    // --- Getters ---

    TraceeState PtraceController::getTraceeState() const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_tracee_state;
    }


    // --- Private Helpers ---

    void PtraceController::tracerLoop()
    {
        // This thread only monitors the child process for state changes
        // It doesn't handle ptrace commands - those are executed directly
        
        while (true) {
            int status;
            pid_t result = waitpid(m_pid, &status, 0);
            
            if (result < 0) {
                if (errno == ECHILD) {
                    // Child process no longer exists
                    std::lock_guard<std::mutex> lock(m_mutex);
                    updateTraceeState(TraceeState::Exited);
                    m_is_tracer_thread_active = false;
                    break;
                } else {
                    perror("waitpid in tracerLoop");
                    std::lock_guard<std::mutex> lock(m_mutex);
                    updateTraceeState(TraceeState::Error);
                    m_is_tracer_thread_active = false;
                    break;
                }
            }

            // Process state change
            std::lock_guard<std::mutex> lock(m_mutex);
            
            if (!m_is_tracer_thread_active) {
                // Thread was told to stop
                break;
            }
            
            if (WIFSTOPPED(status)) {
                // Process stopped (breakpoint, signal, step, interrupt, etc.)
                updateTraceeState(TraceeState::Stopped);
            }
            else if (WIFEXITED(status) || WIFSIGNALED(status)) {
                // Process has terminated
                updateTraceeState(TraceeState::Exited);
                m_is_tracer_thread_active = false;
                break;
            }
        }
    }

    void PtraceController::updateTraceeState(TraceeState newState)
    {
        m_tracee_state = newState;
        // Always notify - any state change might be relevant to waiting threads
        m_cv_tracee_stopped.notify_all();
    }

    void PtraceController::stopTracerThread()
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_is_tracer_thread_active) return;
        
        m_is_tracer_thread_active = false;
        // The tracer thread will exit when it next checks this flag
        // or when the process exits
    }

} // namespace DebuggerEngine