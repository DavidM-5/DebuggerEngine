#pragma once

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h> // For user_regs_struct
#include <sys/uio.h>  // For process_vm_readv/writev
#include <unistd.h>
#include <csignal>    // For kill()
#include <cerrno>
#include <cstring>    // For strerror
#include <iostream>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <functional>
#include <string>
#include <vector>

namespace DebuggerEngine
{
    using Registers = user_regs_struct;

    enum class TraceeState {
        NotStarted, // The debugger has not launched a process yet.
        Running,    // The child process is currently executing.
        Stopped,    // The child process is stopped and ready for inspection.
        Exited,     // The child process has exited.
        Error       // An unrecoverable error occurred.
    };

    // Forward declarations for hook system
    using ChildSetupHook = std::function<void()>;
    using ParentSetupHook = std::function<void(pid_t child_pid)>;

    struct ProcessHooks {
        ChildSetupHook child_setup;   // Called in child before exec
        ParentSetupHook parent_setup; // Called in parent after fork
    };
        
    class PtraceController
    {
    public:
        // --- Lifecycle and Process Control ---

        PtraceController();
        ~PtraceController();

        // This class manages a child process and a thread, so it should not be copyable.
        PtraceController(const PtraceController&) = delete;
        PtraceController& operator=(const PtraceController&) = delete;
        
        // Attaches to an existing process that was created with the hooks.
        // This replaces the old launch() method and should be called after
        // the process has been created and the hooks have been executed.
        // @param pid The PID of the process to attach to
        // @return true on successful attachment
        bool attachToProcess(pid_t pid);

        // This is the original monolithic method. Use getProcessHooks() + attachToProcess() instead. 
        // Launches the target executable as a child process and begins tracing it.
        // The function blocks until the child process is loaded and has reached its initial stop point
        // (immediately after the execv call), at which point it's ready for commands.
        // @param path Full path to the executable.
        // @param args Command-line arguments for the executable.
        // @return true on successful launch and initial stop, false otherwise.
        [[deprecated("Use getProcessHooks() + attachToProcess() instead")]]
        bool launch(const std::string& path, const std::vector<std::string>& args);

        // Terminates the traced child process.
        // This sends a SIGKILL signal to ensure termination and cleans up resources.
        // @return true on successful termination.
        bool terminate();
        
        // Detaches from the traced process, allowing it to continue execution freely.
        // The debugger will no longer be able to control it.
        // @return true on successful detachment.
        bool detach();

        // --- Execution Control (for a running or stopped tracee) ---

        // Resumes the execution of the traced process.
        // The tracee must be in a Stopped state. This method is non-blocking.
        bool continueExecution();

        // Executes a single instruction.
        // The tracee must be in a Stopped state. This method is non-blocking.
        bool step();
        
        // Interrupts a running tracee and forces it to stop.
        // This method blocks the calling thread until the tracee is confirmed stopped.
        bool interrupt();

        // Blocks the calling thread until the tracee enters a Stopped state.
        // @return true if the tracee successfully stopped, false if it exited or an error occurred.
        bool waitForStop();
        
        // --- State Inspection and Manipulation (for a stopped tracee) ---

        // Reads general-purpose registers from the tracee.
        // The tracee must be in a Stopped state.
        bool getRegisters(Registers& regs) const;

        // Writes general-purpose registers to the tracee.
        // The tracee must be in a Stopped state.
        bool setRegisters(const Registers& regs) const;

        // Reads a block of data from the tracee's memory.
        // The tracee must be in a Stopped state.
        bool readMemory(uint64_t addr, size_t size, void* buffer) const;

        // Writes a block of data into the tracee's memory.
        // The tracee must be in a Stopped state.
        bool writeMemory(uint64_t addr, size_t size, const void* buffer) const;

        // Convenience function to read a word from memory.
        // The tracee must be in a Stopped state.
        long peekData(uint64_t addr) const;

        // Convenience function to write a word to memory.
        // The tracee must be in a Stopped state.
        bool pokeData(uint64_t addr, long value) const;

        // --- Getters ---

        // Returns the PID of the traced child process.
        // Returns -1 if no process has been launched.
        pid_t getPid() const { return m_pid; }

        // Returns the current state of the traced process.
        TraceeState getTraceeState() const;

        // Returns hooks for the process creation system
        // These hooks handle ptrace setup during process creation
        ProcessHooks getProcessHooks();
    
    private:
        pid_t m_pid;

        // --- Threading and Synchronization ---
        std::thread m_tracer_thread;
        mutable std::mutex m_mutex;
        std::condition_variable m_cv_tracer_command;
        std::condition_variable m_cv_tracee_stopped;
        bool m_is_tracer_thread_active;
        TraceeState m_tracee_state;
        enum __ptrace_request m_ptrace_request; // The PTRACE request for the tracer thread (e.g., PTRACE_CONT)

        // --- Private Helpers ---

        // The main loop for the dedicated tracing thread.
        // This function blocks on waitpid() and manages the tracee's state.
        void tracerLoop();

        // Helper to safely update tracee state and notify waiting threads.
        // This function must be called with the mutex already locked.
        void updateTraceeState(TraceeState newState);

        // Safely stops the tracer thread and waits for it to join.
        void stopTracerThread();

        // Helper for executing ptrace operations that require the tracee to be stopped.
        template<typename Func>
        bool executeIfStopped(Func ptrace_op, const char* op_name) const;


        // --- Hook Implementation Helpers ---
        
        // Called in child process to set up ptrace tracing
        void setupChildPtrace();
        
        // Called in parent process after fork to initialize ptrace state
        void setupParentPtrace(pid_t child_pid);
    };

} // namespace DebuggerEngine
