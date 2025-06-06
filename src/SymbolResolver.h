#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <optional>
#include <memory>
#include <cstdint>
#include <functional>
#include <mutex>
#include <map>
#include <elfutils/libdw.h>
#include <dwarf.h>
#include <fcntl.h>
#include <unistd.h>
#include <algorithm>
#include <filesystem>
#include <iostream>
#include <cstring>

namespace DebuggerEngine
{
    // Represents a source location (file:line)
    struct SourceLocation {
        std::string filename;
        uint32_t line_number;
        std::optional<uint32_t> column;
        
        SourceLocation() = default;
        SourceLocation(const std::string& file, uint32_t line, std::optional<uint32_t> col = std::nullopt)
            : filename(file), line_number(line), column(col) {}
        
        bool operator==(const SourceLocation& other) const {
            return filename == other.filename && line_number == other.line_number;
        }
        
        bool operator<(const SourceLocation& other) const {
            if (filename != other.filename) return filename < other.filename;
            if (line_number != other.line_number) return line_number < other.line_number;
            return column.value_or(0) < other.column.value_or(0);
        }
    };

    // Represents a symbol (function, variable, etc.)
    struct Symbol {
        enum class Type { Function, Variable, Parameter, Label, Unknown };
        
        std::string name;
        uint64_t address; // Address relative to the binary's base
        uint64_t size;
        Type type;
        SourceLocation location;
        
        // For debugging
        std::string toString() const;
    };

    // Represents address range information
    struct AddressRange {
        uint64_t start_address;
        uint64_t end_address;
        SourceLocation location;
        std::string function_name; // Optional function name for this range
        
        bool contains(uint64_t address) const {
            return address >= start_address && address < end_address;
        }
        
        uint64_t size() const {
            return end_address - start_address;
        }
    };
    
    class SymbolResolver
    {
    public:
        enum class LogLevel { Info, Debug, Warning, Error };
        using LoggerCallback = std::function<void(LogLevel, const std::string&)>;

        SymbolResolver();
        ~SymbolResolver();

        // Non-copyable but movable
        SymbolResolver(const SymbolResolver&) = delete;
        SymbolResolver& operator=(const SymbolResolver&) = delete;
        SymbolResolver(SymbolResolver&&) noexcept;
        SymbolResolver& operator=(SymbolResolver&&) noexcept;

        // --- Core Loading and Configuration ---
        bool loadExecutable(const std::string& executable_path);
        void setLoadAddress(uint64_t load_address);
        void setLogger(LoggerCallback callback);
        bool isLoaded() const { std::lock_guard<std::mutex> lock(m_mutex); return m_is_loaded; }
        uint64_t getLoadAddress() const { std::lock_guard<std::mutex> lock(m_mutex); return m_load_address; }
        
        // --- Fast Lookups (thread-safe, using caches) ---
        std::optional<uint64_t> getFunctionAddress(const std::string& function_name) const;
        std::optional<Symbol> getFunction(const std::string& function_name) const;
        std::vector<Symbol> getAllFunctions() const;

        std::optional<uint64_t> getGlobalVariableAddress(const std::string& variable_name) const;
        std::vector<Symbol> getGlobalVariables() const;

        std::optional<SourceLocation> getSourceLocation(uint64_t absolute_address) const;
        std::vector<uint64_t> getAddressesForLine(const std::string& filename, uint32_t line_number);
        
        std::optional<Symbol> getFunctionAtAddress(uint64_t absolute_address) const;
        std::vector<AddressRange> getAddressRanges() const;
        std::vector<std::string> getSourceFiles() const;
        std::string getCompilationDirectoryForFile(const std::string& filename);
        
        // --- Statistics and Debugging ---
        size_t getFunctionCount() const;
        size_t getVariableCount() const;
        size_t getSourceFileCount() const;
        std::string getExecutablePath() const;
        std::string getLastError() const;

    private:
        // DWARF context management
        struct DwarfContext {
            std::unique_ptr<Dwarf, void(*)(Dwarf*)> dwarf;
            int fd = -1;
            
            DwarfContext() : dwarf(nullptr, nullptr) {}
            ~DwarfContext() { cleanup(); }
            void cleanup();
        };

        // Thread safety
        mutable std::mutex m_mutex;
        
        // DWARF context
        std::unique_ptr<DwarfContext> m_context;
        
        // State
        bool m_is_loaded = false;
        uint64_t m_load_address = 0;
        std::string m_executable_path;
        std::string m_last_error;
        LoggerCallback m_logger;

        // --- Optimized caches for performance ---
        std::vector<Symbol> m_functions;
        std::vector<Symbol> m_variables;
        std::unordered_map<std::string, size_t> m_function_name_to_index; // name -> index in m_functions
        std::unordered_map<std::string, size_t> m_variable_name_to_index; // name -> index in m_variables
        std::map<uint64_t, SourceLocation> m_addr_to_line; // Sorted map for range queries
        std::unordered_map<std::string, std::vector<uint64_t>> m_line_to_addr; // "file:line" -> {addrs}
        std::map<uint64_t, size_t> m_addr_to_function; // Sorted map: address -> function index

        // Path resolution caches
        std::unordered_map<std::string, std::vector<std::string>> m_basename_to_paths;
        std::unordered_map<std::string, std::string> m_file_to_comp_dir;
        std::unordered_map<std::string, std::string> m_path_resolution_cache;

        // --- Private Helper Methods ---
        void log(LogLevel level, const std::string& msg) const;
        void setError(const std::string& error);
        void cleanup();
        bool initializeDwarf();
        bool validateExecutable(const std::string& path);
        
        // Caching and indexing
        bool buildCaches();
        void visitDIEs(Dwarf_Die* start_die, const std::function<void(Dwarf_Die*)>& visitor) const;
        bool processFunctionDIE(Dwarf_Die* die, const std::string& comp_dir);
        bool processVariableDIE(Dwarf_Die* die, const std::string& comp_dir);
        bool processLineInfo(Dwarf_Die* cu_die);
        
        // Path resolution helpers
        static std::string getBasename(const std::string& path);
        std::string resolveSourcePath(const std::string& filename);
        void buildPathMappings(Dwarf_Die* cu_die, const std::string& comp_dir);
        
        // Symbol helpers
        static uint64_t getSymbolSize(Dwarf_Die* die, uint64_t low_pc);
        static SourceLocation extractSourceLocation(Dwarf_Die* die);
        
        // Validation helpers
        bool isValidAddress(uint64_t address) const;
        bool isValidFileName(const std::string& filename) const;
    };

} // namespace DebuggerEngine