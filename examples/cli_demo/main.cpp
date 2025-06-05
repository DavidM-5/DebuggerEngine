#include "../../src/IOManager.h"
#include <iostream>
#include <string>
#include <vector>
#include <unistd.h>

using namespace DebuggerEngine;

int main(int argc, char const *argv[])
{
    IOManager ioManager;

    // --- Process Setup and Launch ---
    if (!ioManager.createPtyPair()) { return 1; }
    auto io_hooks = ioManager.getProcessSetupHooks();
    pid_t pid = fork();
    if (pid < 0) { perror("fork failed"); return 1; }

    if (pid == 0) { // Child Process
        io_hooks.child_setup();
        execlp("bash", "bash", nullptr);
        perror("execlp failed");
        _exit(1);
    }
    else { // Parent Process
        io_hooks.parent_setup(pid);
        std::cout << "Launched child process with PID: " << pid << std::endl;
        std::cout << "--- Initializing Interactive Session ---" << std::endl;

        // A unique string that we will set as the shell's prompt.
        const std::string MY_PROMPT = "PROMPT_READY_XYZ>";

        // --- Synchronize with the shell by setting our prompt ---
        // The new executeCommand method handles all the waiting internally.
        ioManager.executeCommand("export PS1='" + MY_PROMPT + "'", MY_PROMPT);

        std::cout << "Session synchronized. Ready for commands." << std::endl;
        
        // --- The Conversation (now incredibly simple) ---
        
        std::cout << "\n[1. Asking for current user...]" << std::endl;
        std::string whoami_output = ioManager.executeCommand("whoami", MY_PROMPT);
        std::cout << "Shell Response:\n" << whoami_output << std::endl;

        std::cout << "[2. Asking for current directory...]" << std::endl;
        std::string pwd_output = ioManager.executeCommand("pwd", MY_PROMPT);
        std::cout << "Shell Response:\n" << pwd_output << std::endl;
        
        std::cout << "[3. Echoing a message...]" << std::endl;
        std::string echo_output = ioManager.executeCommand("echo 'This is so much cleaner!'", MY_PROMPT);
        std::cout << "Shell Response:\n" << echo_output << std::endl;
        
        // --- Shutdown Sequence ---
        std::cout << "\n[4. Ending conversation...]" << std::endl;
        ioManager.sendInput("exit\n");
        ioManager.waitForStateChange();
        ioManager.shutdown();
        
        std::cout << "--- Conversation Over ---" << std::endl;
    }

    return 0;
}