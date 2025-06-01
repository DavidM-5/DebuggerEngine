cd /path/to/DebuggerEngine
mkdir build
cd build
cmake .. -DBUILD_TESTS=ON -DBUILD_EXAMPLES=ON
cmake --build .

(sudo) ctest --verbose