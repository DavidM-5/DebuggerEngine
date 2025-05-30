cd /path/to/DebuggerEngine
mkdir build
cd build
cmake .. -DBUILD_TESTS=OFF -DBUILD_EXAMPLES=ON
cmake --build .