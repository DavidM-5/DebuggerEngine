#include "IOManager.h"
#include <sys/ioctl.h>
#include <sys/select.h>
#include <chrono>

namespace DebuggerEngine
{
    IOManager::IOManager() 
        : m_pid(-1), 
          m_master_fd(-1), 
          m_slave_fd(-1), 
          m_threads_active(false), 
          m_process_state(ProcessIOState::NotStarted),
          m_prompt_received(false)
    {
    }

    IOManager::~IOManager()
    {
        shutdown();
    }

    bool IOManager::createPtyPair()
    {
        return createPTY();
    }

    IOProcessHooks IOManager::getProcessSetupHooks()
    {
        IOProcessHooks hooks;

        hooks.child_setup = [this]() {
            // Close the master end in the child
            if (m_master_fd >= 0) close(m_master_fd);

            // --- THE CORRECT FIX: Put the PTY into raw mode from C++ ---
            struct termios tty_attrs;
            if (tcgetattr(m_slave_fd, &tty_attrs) == 0) {
                // Turn OFF canonical mode (line-based input) and echoing.
                // This is the key to reliable, clean, character-by-character I/O.
                tty_attrs.c_lflag &= ~(ICANON | ECHO);
                // Apply the new settings immediately.
                tcsetattr(m_slave_fd, TCSANOW, &tty_attrs);
            }
            // --- END OF FIX ---

            // Create a new session and set the PTY as the controlling terminal
            if (setsid() < 0) _exit(1);
            if (ioctl(m_slave_fd, TIOCSCTTY, 0) < 0) _exit(1);

            // Redirect stdio
            dup2(m_slave_fd, STDIN_FILENO);
            dup2(m_slave_fd, STDOUT_FILENO);
            dup2(m_slave_fd, STDERR_FILENO);

            // Close original slave descriptor
            if (m_slave_fd > STDERR_FILENO) close(m_slave_fd);
        };

        hooks.parent_setup = [this](pid_t child_pid) {
            m_pid = child_pid;
            if (m_slave_fd >= 0) {
                close(m_slave_fd);
                m_slave_fd = -1;
            }
            updateProcessState(ProcessIOState::Running);
            m_threads_active = true;
            m_io_thread = std::thread(&IOManager::ioLoop, this);
            m_monitor_thread = std::thread(&IOManager::monitorLoop, this);
        };

        return hooks;
    }

    bool IOManager::terminate()
    {
        if (m_pid <= 0) return false;

        if (kill(m_pid, SIGTERM) == 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            if (kill(m_pid, 0) == 0) {
                kill(m_pid, SIGKILL);
            }
            return true;
        }
        return false;
    }

    bool IOManager::detach()
    {
        stopThreads();
        shutdown();
        
        std::lock_guard<std::mutex> lock(m_state_mutex);
        m_pid = -1;
        updateProcessState(ProcessIOState::NotStarted);
        return true;
    }

    bool IOManager::sendInput(const std::string& data)
    {
        if (getProcessState() != ProcessIOState::Running) return false;

        {
            std::lock_guard<std::mutex> lock(m_io_buffer.queue_mutex);
            m_io_buffer.input_queue.push(data);
        }
        m_io_buffer.data_available.notify_one();
        return true;
    }

    bool IOManager::readOutput(std::string& data, bool blocking)
    {
        std::unique_lock<std::mutex> lock(m_io_buffer.queue_mutex);
        
        if (blocking) {
            m_io_buffer.data_available.wait(lock, [this] {
                return !m_io_buffer.output_queue.empty() || 
                       m_process_state == ProcessIOState::Exited ||
                       m_process_state == ProcessIOState::Error;
            });
        }

        if (!m_io_buffer.output_queue.empty()) {
            data = m_io_buffer.output_queue.front();
            m_io_buffer.output_queue.pop();
            return true;
        }

        return false;
    }

    bool IOManager::hasOutput() const
    {
        std::lock_guard<std::mutex> lock(m_io_buffer.queue_mutex);
        return !m_io_buffer.output_queue.empty();
    }

    bool IOManager::sendSignal(int signal)
    {
        if (m_pid <= 0) return false;
        return kill(m_pid, signal) == 0;
    }

    bool IOManager::waitForStateChange()
    {
        std::unique_lock<std::mutex> lock(m_state_mutex);
        m_state_changed.wait(lock, [this] {
            return m_process_state == ProcessIOState::Stopped ||
                   m_process_state == ProcessIOState::Exited ||
                   m_process_state == ProcessIOState::Error;
        });
        return true;
    }

    bool IOManager::setTerminalAttributes(const struct termios& attrs)
    {
        if (m_master_fd < 0) return false;
        return tcsetattr(m_master_fd, TCSANOW, &attrs) == 0;
    }

    bool IOManager::getTerminalAttributes(struct termios& attrs) const
    {
        if (m_master_fd < 0) return false;
        return tcgetattr(m_master_fd, &attrs) == 0;
    }

    bool IOManager::resizeTerminal(unsigned short rows, unsigned short cols)
    {
        if (m_master_fd < 0) return false;

        struct winsize ws = {rows, cols, 0, 0};
        return ioctl(m_master_fd, TIOCSWINSZ, &ws) == 0;
    }
    
    pid_t IOManager::getPid() const { return m_pid; }
    int IOManager::getMasterFd() const { return m_master_fd; }
    
    ProcessIOState IOManager::getProcessState() const
    {
        std::lock_guard<std::mutex> lock(m_state_mutex);
        return m_process_state;
    }

    void IOManager::setDataReceivedHook(DataReceivedHook hook) { m_data_received_hook = hook; }
    void IOManager::setProcessExitHook(ProcessExitedHook hook) { m_process_exit_hook = hook; }

    void IOManager::ioLoop()
    {
        fd_set read_fds, write_fds;
        char buffer[4096];
        
        while (m_threads_active) {
            FD_ZERO(&read_fds);
            FD_ZERO(&write_fds);
            
            if (m_master_fd < 0) {
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                continue;
            }

            FD_SET(m_master_fd, &read_fds);
            
            {
                std::lock_guard<std::mutex> lock(m_io_buffer.queue_mutex);
                if (!m_io_buffer.input_queue.empty()) {
                    FD_SET(m_master_fd, &write_fds);
                }
            }
            
            struct timeval timeout = {0, 100000}; // 100ms
            int result = select(m_master_fd + 1, &read_fds, &write_fds, nullptr, &timeout);
            
            if (result < 0) {
                if (errno == EINTR) continue;
                break;
            }
            if (result == 0) continue;

            if (FD_ISSET(m_master_fd, &read_fds)) {
                ssize_t bytes_read = read(m_master_fd, buffer, sizeof(buffer));
                if (bytes_read > 0) {
                    handleOutputData(std::string(buffer, bytes_read));
                } else if (bytes_read == 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) {
                    break; // EOF or error
                }
            }
            
            if (FD_ISSET(m_master_fd, &write_fds)) {
                processInputQueue();
            }
        }
    }

    void IOManager::monitorLoop()
    {
        while (m_threads_active && m_pid > 0) {
            int status;
            pid_t result = waitpid(m_pid, &status, WNOHANG);
            
            if (result == m_pid) {
                if (WIFEXITED(status)) {
                    updateProcessState(ProcessIOState::Exited);
                    if (m_process_exit_hook) m_process_exit_hook(WEXITSTATUS(status), 0);
                    break;
                } else if (WIFSIGNALED(status)) {
                    updateProcessState(ProcessIOState::Exited);
                    if (m_process_exit_hook) m_process_exit_hook(-1, WTERMSIG(status));
                    break;
                } else if (WIFSTOPPED(status)) {
                    updateProcessState(ProcessIOState::Stopped);
                }
            } else if (result < 0 && errno != ECHILD) {
                updateProcessState(ProcessIOState::Error);
                break;
            }
            
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }

    void IOManager::updateProcessState(ProcessIOState newState)
    {
        {
            std::lock_guard<std::mutex> lock(m_state_mutex);
            if (m_process_state == newState) return;
            m_process_state = newState;
        }
        m_state_changed.notify_all();
    }

    void IOManager::stopThreads()
    {
        m_threads_active = false;
        m_io_buffer.data_available.notify_all();
        m_state_changed.notify_all();
        
        if (m_io_thread.joinable()) m_io_thread.join();
        if (m_monitor_thread.joinable()) m_monitor_thread.join();
    }

    void IOManager::processInputQueue()
    {
        std::lock_guard<std::mutex> lock(m_io_buffer.queue_mutex);
    
        while (!m_io_buffer.input_queue.empty() && m_master_fd >= 0) {
            std::string& data_to_send = m_io_buffer.input_queue.front();
            
            ssize_t bytes_written = write(m_master_fd, data_to_send.c_str(), data_to_send.length());
            
            if (bytes_written > 0) {
                // --- The next 2 lines can be removed as written_data is no longer used ---
                // std::string written_data = data_to_send.substr(0, bytes_written);
                
                if (static_cast<size_t>(bytes_written) == data_to_send.length()) {
                    m_io_buffer.input_queue.pop();
                } else {
                    data_to_send.erase(0, bytes_written);
                    break;
                }
            } else if (bytes_written < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                break; 
            } else {
                break; 
            }
        }
    }

    void IOManager::handleOutputData(const std::string& data)
    {
        // --- Internal conversation logic ---
        {
            std::lock_guard<std::mutex> lock(m_conversation_mutex);
            m_internal_buffer += data;
            // Check if the output contains the prompt we're currently waiting for
            if (!m_current_prompt.empty() && m_internal_buffer.find(m_current_prompt) != std::string::npos) {
                m_prompt_received = true;
                m_prompt_cv.notify_one(); // Wake up the waiting executeCommand method
            }
        }

        // --- External hook logic (for users who still want low-level callbacks) ---
        {
            std::lock_guard<std::mutex> lock(m_io_buffer.queue_mutex);
            m_io_buffer.output_queue.push(data);
        }
        m_io_buffer.data_available.notify_all();
        
        if (m_data_received_hook) {
            m_data_received_hook(data);
        }
    }

    bool IOManager::createPTY()
    {
        if (openpty(&m_master_fd, &m_slave_fd, nullptr, nullptr, nullptr) < 0) {
            perror("openpty");
            return false;
        }
        
        int flags = fcntl(m_master_fd, F_GETFL, 0);
        fcntl(m_master_fd, F_SETFL, flags | O_NONBLOCK);
        
        return true;
    }

    void IOManager::shutdown()
    {
        // This is the same logic as your old cleanup function.
        // It ensures threads are stopped and joined before any other cleanup.
        stopThreads();
        
        if (m_pid > 0 && getProcessState() == ProcessIOState::Running) {
            terminate();
        }
        
        if (m_master_fd >= 0) {
            close(m_master_fd);
            m_master_fd = -1;
        }
        if (m_slave_fd >= 0) {
            close(m_slave_fd);
            m_slave_fd = -1;
        }
    }

    std::string IOManager::executeCommand(const std::string &command, const std::string &prompt)
    {
        // This method runs on the caller's thread (e.g., main)
        {
            std::lock_guard<std::mutex> lock(m_conversation_mutex);
            m_internal_buffer.clear();
            m_prompt_received = false;
            m_current_prompt = prompt; // Remember the prompt we're waiting for
        }

        sendInput(command + "\n");

        // Wait until the I/O thread's callback signals that the prompt has arrived
        std::unique_lock<std::mutex> lock(m_conversation_mutex);
        m_prompt_cv.wait(lock, [&]{ return m_prompt_received; });

        // The command is finished, process the result
        std::string result = m_internal_buffer;
        size_t prompt_pos = result.find(m_current_prompt);
        if (prompt_pos != std::string::npos) {
            result.erase(prompt_pos, m_current_prompt.length());
        }
        return result;
    }

} // namespace DebuggerEngine