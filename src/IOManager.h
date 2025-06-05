#pragma once

#include <pty.h>
#include <utmp.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>
#include <csignal>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <functional>
#include <string>
#include <vector>
#include <queue>
#include <atomic>

namespace DebuggerEngine
{
    enum class ProcessIOState {
        NotStarted, // No process has been launched yet
        Running,    // Process is running and IO is active
        Stopped,    // Process has stopped (via signal)
        Exited,     // Process has exited normally
        Error       // An unrecoverable error occurred
    };

    // REVISED HOOKS: The IOManager instance holds the necessary state (FDs),
    // so the hooks themselves can be simpler.
    using ChildIOSetupHook = std::function<void()>;
    using ParentIOSetupHook = std::function<void(pid_t child_pid)>;

    struct IOProcessHooks {
        ChildIOSetupHook  child_setup;  // Called in child process before exec
        ParentIOSetupHook parent_setup; // Called in parent process after fork
    };

    // EVENT HOOKS: Asynchronous callbacks for process lifetime events.
    using DataReceivedHook = std::function<void(const std::string& data)>;
    using ProcessExitedHook = std::function<void(int exit_code, int signal)>;

    struct IOBuffer {
        std::queue<std::string> output_queue;
        std::queue<std::string> input_queue;
        mutable std::mutex queue_mutex;
        std::condition_variable data_available;
    };
    
    class IOManager
    {
    public:
        // --- Lifecycle and Process Control ---

        IOManager();
        ~IOManager();

        // Non-copyable
        IOManager(const IOManager&) = delete;
        IOManager& operator=(const IOManager&) = delete;
        IOManager(IOManager&&) = default;
        IOManager& operator=(IOManager&&) = default;
        
        // --- NEW SETUP FLOW ---

        // Step 1: Create the PTY pair. Must be called before fork().
        bool createPtyPair();
        
        // Step 2: Get the hooks to be called after fork().
        IOProcessHooks getProcessSetupHooks();

        // --- PROCESS CONTROL ---

        // Terminates the child process
        bool terminate();

        // Shuts down threads and closes file descriptors synchronously.
        // Call this explicitly before main exits.
        void shutdown();

        // Detaches from the process, closing PTY connections
        bool detach();

        // --- IO Operations ---

        // Sends data to the child process's stdin
        bool sendInput(const std::string& data);

        // Reads available output from the child process
        bool readOutput(std::string& data, bool blocking = false);

        // Checks if output data is available to read
        bool hasOutput() const;

        // --- SIGNAL & STATE ---

        // Sends a signal to the child process
        bool sendSignal(int signal);

        // Waits for the process to change state
        bool waitForStateChange();

        // Sends a command, waits for the specified prompt, and returns the clean output.
        // This method is synchronous and encapsulates all the complex waiting logic.
        std::string executeCommand(const std::string& command, const std::string& prompt);

        // --- Terminal Control ---

        // Sets terminal attributes for the PTY
        bool setTerminalAttributes(const struct termios& attrs);

        // Gets current terminal attributes
        bool getTerminalAttributes(struct termios& attrs) const;

        // Resizes the terminal window
        bool resizeTerminal(unsigned short rows, unsigned short cols);

        // --- Getters ---

        pid_t getPid() const;
        int getMasterFd() const;
        ProcessIOState getProcessState() const;

        // --- HOOKS ---
        
        // Set custom hooks for IO events
        void setDataReceivedHook(DataReceivedHook hook);
        void setProcessExitHook(ProcessExitedHook hook);

    private:
        pid_t m_pid;
        int m_master_fd;  // PTY master file descriptor
        int m_slave_fd;   // PTY slave file descriptor

        // Threading and Synchronization
        std::thread m_io_thread;
        std::thread m_monitor_thread;
        mutable std::mutex m_state_mutex;
        std::condition_variable m_state_changed;
        std::atomic<bool> m_threads_active;
        ProcessIOState m_process_state;

        // Conversation Management
        std::mutex m_conversation_mutex;
        std::condition_variable m_prompt_cv;
        std::string m_internal_buffer;
        std::string m_current_prompt;
        bool m_prompt_received;

        // IO Buffering
        IOBuffer m_io_buffer;

        // Custom hooks
        DataReceivedHook m_data_received_hook;
        ProcessExitedHook m_process_exit_hook;

        // Private Helpers
        void ioLoop();

        void monitorLoop();
        
        void updateProcessState(ProcessIOState newState);
        
        void stopThreads();
        
        void processInputQueue();
        
        void handleOutputData(const std::string& data);
        
        bool createPTY();
    };

} // namespace DebuggerEngine