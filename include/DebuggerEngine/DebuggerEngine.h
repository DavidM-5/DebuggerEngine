#pragma once

#include <memory>
#include <vector>
#include <sys/user.h>

namespace DebuggerEngine
{
    using Registers = user_regs_struct;

    class DebuggerEngine
    {
    public:
        DebuggerEngine();
        ~DebuggerEngine();

        // — Process control
        pid_t launch(const std::string& execPath,
               const std::vector<std::string>& args);
        bool attach(pid_t pid);
        bool detach(bool killProcess = false);

        // — Execution control
        bool run();   // continue until next breakpoint/signal
        bool step();  // single-step one instruction

        // — Breakpoints
        bool setBreakpoint(uintptr_t addr);
        bool removeBreakpoint(uintptr_t addr);

        // — Memory & I/O
        // forwards to IOManager internally:
        std::vector<uint8_t> readMemory(uintptr_t addr, size_t size);
        bool writeMemory(uintptr_t addr, const void* data, size_t size);

        // — Registers
        bool getRegisters(Registers& out);
        bool setRegisters(const Registers& regs);

        // — Generic I/O
        // Send raw bytes into the target process (e.g. to its stdin).
        bool sendInput(const std::vector<uint8_t>& data);

        // Retrieve up to `maxBytes` of output from the target (stdout/stderr).
        std::vector<uint8_t> getOutput(size_t maxBytes = 4096);

        // — Cleanup
        void shutdown();
    
    private:
        struct Impl;
        std::unique_ptr<Impl> pImpl;
    };

} // namespace DebuggerEngine

