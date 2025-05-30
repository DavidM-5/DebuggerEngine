# Project Structure

DebuggerEngine/
├── CMakeLists.txt
├── README.md
├── LICENSE
├── include/
│   └── DebuggerEngine/
│       ├── DebuggerEngine.h
├── src/
│   ├── DebuggerEngine.cpp
│   ├── TargetManager.h
│   ├── TargetManager.cpp
│   ├── IOManager.h
│   ├── IOManager.cpp
│   ├── PtraceController.h
│   ├── PtraceController.cpp
│   └── internal/
│       ├── DebuggerEngine_impl.h
├── tests/
│   ├── CMakeLists.txt
│   ├── DebuggerEngineTests.cpp
│   └── TargetManagerTests.cpp
├── examples/
│   ├── cli_demo/
│   │   ├── main.cpp
│   │   └── CMakeLists.txt
│   └── simple_target/
│       ├── vulnerable_app.c
│       └── run_example.sh
└── docs/
    ├── architecture.md
    └── usage.md


PtraceController
    attach(pid_t)

    detach()

    getRegisters()

    setRegisters()

    singleStep()

    continueExecution()

    peekData(addr)

    pokeData(addr, value)

MemoryReader
    readMemoryBlock(address, size)

    getStackRegion() ← uses /proc/<pid>/maps

    dumpRegionToFile(start, end, filename)

    readCString(address) (optional helper)

    DebuggerEngine
    .launchTarget(path, argv[])

    .pauseTarget(), .resumeTarget()

    .getStack() ← uses both

    .injectPayload(buffer, address)

    .stepAndVisualize()