#include "SymbolResolver.h"
#include <set>
#include <system_error>
#include <algorithm>
#include <sstream>

namespace DebuggerEngine
{
    // Anonymous namespace for internal helpers
    namespace {
        // Safe DWARF attribute reading with error checking
        template<typename T>
        bool getDwarfAttribute(Dwarf_Die* die, unsigned int attr_name, T& result) {
            Dwarf_Attribute attr;
            if (dwarf_attr(die, attr_name, &attr) == nullptr) {
                return false;
            }
            
            if constexpr (std::is_same_v<T, std::string>) {
                const char* str = dwarf_formstring(&attr);
                if (str) {
                    result = str;
                    return true;
                }
            } else if constexpr (std::is_same_v<T, uint64_t>) {
                Dwarf_Word value;
                if (dwarf_formudata(&attr, &value) == 0) {
                    result = value;
                    return true;
                }
                // Try as address
                Dwarf_Addr addr;
                if (dwarf_formaddr(&attr, &addr) == 0) {
                    result = addr;
                    return true;
                }
            }
            return false;
        }
        
        uint64_t calculateSymbolSize(Dwarf_Die* die, uint64_t low_pc) {
            Dwarf_Attribute attr;
            if (dwarf_attr(die, DW_AT_high_pc, &attr) == nullptr) {
                return 0;
            }
            
            Dwarf_Word value = 0;
            if (dwarf_formudata(&attr, &value) != 0) {
                return 0;
            }
            
            // Check if high_pc is an absolute address or an offset
            int form = dwarf_whatform(&attr);
            if (form == DW_FORM_addr) {
                return value > low_pc ? value - low_pc : 0;
            }
            
            // Otherwise, it's a size offset
            return value;
        }
        
        bool isExecutableFile(const std::string& path) {
            std::error_code ec;
            auto status = std::filesystem::status(path, ec);
            if (ec) return false;
            
            return std::filesystem::is_regular_file(status) && 
                   (status.permissions() & std::filesystem::perms::owner_exec) != std::filesystem::perms::none;
        }
    }

    // --- Symbol implementation ---
    std::string Symbol::toString() const {
        std::ostringstream oss;
        oss << "Symbol{name='" << name << "', addr=0x" << std::hex << address 
            << ", size=" << std::dec << size << ", type=";
        switch (type) {
            case Type::Function: oss << "Function"; break;
            case Type::Variable: oss << "Variable"; break;
            case Type::Parameter: oss << "Parameter"; break;
            case Type::Label: oss << "Label"; break;
            default: oss << "Unknown"; break;
        }
        oss << ", location=" << location.filename << ":" << location.line_number << "}";
        return oss.str();
    }

    // --- DwarfContext implementation ---
    void SymbolResolver::DwarfContext::cleanup() {
        if (dwarf) {
            dwarf.reset();
        }
        if (fd != -1) {
            close(fd);
            fd = -1;
        }
    }

    // --- SymbolResolver implementation ---
    SymbolResolver::SymbolResolver() 
        : m_context(std::make_unique<DwarfContext>()) {
    }

    SymbolResolver::~SymbolResolver() {
        cleanup();
    }

    SymbolResolver::SymbolResolver(SymbolResolver&& other) noexcept
        : m_context(std::move(other.m_context))
        , m_is_loaded(other.m_is_loaded)
        , m_load_address(other.m_load_address)
        , m_executable_path(std::move(other.m_executable_path))
        , m_last_error(std::move(other.m_last_error))
        , m_logger(std::move(other.m_logger))
        , m_functions(std::move(other.m_functions))
        , m_variables(std::move(other.m_variables))
        , m_function_name_to_index(std::move(other.m_function_name_to_index))
        , m_variable_name_to_index(std::move(other.m_variable_name_to_index))
        , m_addr_to_line(std::move(other.m_addr_to_line))
        , m_line_to_addr(std::move(other.m_line_to_addr))
        , m_addr_to_function(std::move(other.m_addr_to_function))
        , m_basename_to_paths(std::move(other.m_basename_to_paths))
        , m_file_to_comp_dir(std::move(other.m_file_to_comp_dir))
        , m_path_resolution_cache(std::move(other.m_path_resolution_cache)) {
        
        other.m_is_loaded = false;
        other.m_load_address = 0;
    }

    SymbolResolver& SymbolResolver::operator=(SymbolResolver&& other) noexcept {
        if (this != &other) {
            cleanup();
            
            std::lock_guard<std::mutex> lock1(m_mutex);
            std::lock_guard<std::mutex> lock2(other.m_mutex);
            
            m_context = std::move(other.m_context);
            m_is_loaded = other.m_is_loaded;
            m_load_address = other.m_load_address;
            m_executable_path = std::move(other.m_executable_path);
            m_last_error = std::move(other.m_last_error);
            m_logger = std::move(other.m_logger);
            m_functions = std::move(other.m_functions);
            m_variables = std::move(other.m_variables);
            m_function_name_to_index = std::move(other.m_function_name_to_index);
            m_variable_name_to_index = std::move(other.m_variable_name_to_index);
            m_addr_to_line = std::move(other.m_addr_to_line);
            m_line_to_addr = std::move(other.m_line_to_addr);
            m_addr_to_function = std::move(other.m_addr_to_function);
            m_basename_to_paths = std::move(other.m_basename_to_paths);
            m_file_to_comp_dir = std::move(other.m_file_to_comp_dir);
            m_path_resolution_cache = std::move(other.m_path_resolution_cache);
            
            other.m_is_loaded = false;
            other.m_load_address = 0;
        }
        return *this;
    }

    bool SymbolResolver::loadExecutable(const std::string& executable_path) {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        if (!validateExecutable(executable_path)) {
            return false;
        }
        
        cleanup();
        m_executable_path = executable_path;
        
        m_context->fd = open(executable_path.c_str(), O_RDONLY);
        if (m_context->fd == -1) {
            setError("Failed to open executable: " + executable_path + " (" + std::strerror(errno) + ")");
            return false;
        }
        
        if (!initializeDwarf()) {
            cleanup();
            return false;
        }
        
        log(LogLevel::Info, "Indexing DWARF information for: " + executable_path);
        if (!buildCaches()) {
            cleanup();
            return false;
        }
        
        log(LogLevel::Info, "Indexing complete. Found " + std::to_string(m_functions.size()) + 
            " functions, " + std::to_string(m_variables.size()) + " variables");

        m_is_loaded = true;
        return true;
    }

    void SymbolResolver::setLoadAddress(uint64_t load_address) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_load_address = load_address;
        log(LogLevel::Debug, "Set load address to: 0x" + std::to_string(load_address));
    }

    void SymbolResolver::setLogger(LoggerCallback callback) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_logger = callback;
    }

    // --- Fast Public API (thread-safe, uses caches) ---

    std::optional<uint64_t> SymbolResolver::getFunctionAddress(const std::string& function_name) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_is_loaded || function_name.empty()) return std::nullopt;
        
        auto it = m_function_name_to_index.find(function_name);
        if (it != m_function_name_to_index.end() && it->second < m_functions.size()) {
            return m_functions[it->second].address + m_load_address;
        }
        return std::nullopt;
    }

    std::optional<Symbol> SymbolResolver::getFunction(const std::string& function_name) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_is_loaded || function_name.empty()) return std::nullopt;
        
        auto it = m_function_name_to_index.find(function_name);
        if (it != m_function_name_to_index.end() && it->second < m_functions.size()) {
            Symbol result = m_functions[it->second];
            result.address += m_load_address;
            return result;
        }
        return std::nullopt;
    }

    std::vector<Symbol> SymbolResolver::getAllFunctions() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_is_loaded) return {};
        
        std::vector<Symbol> result = m_functions;
        for (auto& sym : result) {
            sym.address += m_load_address;
        }
        return result;
    }

    std::optional<uint64_t> SymbolResolver::getGlobalVariableAddress(const std::string& variable_name) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_is_loaded || variable_name.empty()) return std::nullopt;
        
        auto it = m_variable_name_to_index.find(variable_name);
        if (it != m_variable_name_to_index.end() && it->second < m_variables.size()) {
            return m_variables[it->second].address + m_load_address;
        }
        return std::nullopt;
    }
    
    std::vector<Symbol> SymbolResolver::getGlobalVariables() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_is_loaded) return {};
        
        std::vector<Symbol> result = m_variables;
        for (auto& sym : result) {
            sym.address += m_load_address;
        }
        return result;
    }

    std::optional<SourceLocation> SymbolResolver::getSourceLocation(uint64_t absolute_address) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_is_loaded || !isValidAddress(absolute_address)) return std::nullopt;
        
        uint64_t relative_address = absolute_address - m_load_address;
        auto it = m_addr_to_line.find(relative_address);
        if (it != m_addr_to_line.end()) {
            return it->second;
        }
        
        // Try to find the closest address (for inlined code, etc.)
        auto lower = m_addr_to_line.lower_bound(relative_address);
        if (lower != m_addr_to_line.begin()) {
            --lower;
            // Only return if within reasonable distance (e.g., same function)
            if (relative_address - lower->first < 1024) {
                return lower->second;
            }
        }
        
        return std::nullopt;
    }

    std::vector<uint64_t> SymbolResolver::getAddressesForLine(const std::string& filename, uint32_t line_number) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_is_loaded || !isValidFileName(filename) || line_number == 0) return {};
        
        std::string resolved_path = resolveSourcePath(filename);
        std::string key = resolved_path + ":" + std::to_string(line_number);
        
        auto it = m_line_to_addr.find(key);
        if (it != m_line_to_addr.end()) {
            std::vector<uint64_t> result = it->second;
            for (auto& addr : result) {
                addr += m_load_address;
            }
            return result;
        }
        return {};
    }

    std::optional<Symbol> SymbolResolver::getFunctionAtAddress(uint64_t absolute_address) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_is_loaded || !isValidAddress(absolute_address)) return std::nullopt;
        
        uint64_t relative_address = absolute_address - m_load_address;
        
        // Use the sorted map for efficient lookup
        auto it = m_addr_to_function.upper_bound(relative_address);
        if (it != m_addr_to_function.begin()) {
            --it;
            size_t func_index = it->second;
            if (func_index < m_functions.size()) {
                const Symbol& func = m_functions[func_index];
                if (relative_address >= func.address && 
                    relative_address < (func.address + func.size)) {
                    Symbol result = func;
                    result.address += m_load_address;
                    return result;
                }
            }
        }
        return std::nullopt;
    }

    std::vector<AddressRange> SymbolResolver::getAddressRanges() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_is_loaded) return {};
        
        std::vector<AddressRange> ranges;
        for (const auto& func : m_functions) {
            if (func.size > 0) {
                AddressRange range;
                range.start_address = func.address + m_load_address;
                range.end_address = range.start_address + func.size;
                range.location = func.location;
                range.function_name = func.name;
                ranges.push_back(range);
            }
        }
        return ranges;
    }
    
    std::vector<std::string> SymbolResolver::getSourceFiles() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_is_loaded) return {};
        
        std::set<std::string> files_set;
        for (const auto& [basename, paths] : m_basename_to_paths) {
            files_set.insert(paths.begin(), paths.end());
        }
        return {files_set.begin(), files_set.end()};
    }
    
    std::string SymbolResolver::getCompilationDirectoryForFile(const std::string& filename) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_is_loaded || filename.empty()) return "";
        
        std::string resolved_path = resolveSourcePath(filename);
        auto it = m_file_to_comp_dir.find(resolved_path);
        return (it != m_file_to_comp_dir.end()) ? it->second : "";
    }

    // --- Statistics and Debugging ---
    size_t SymbolResolver::getFunctionCount() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_functions.size();
    }

    size_t SymbolResolver::getVariableCount() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_variables.size();
    }

    size_t SymbolResolver::getSourceFileCount() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_basename_to_paths.size();
    }

    std::string SymbolResolver::getExecutablePath() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_executable_path;
    }

    std::string SymbolResolver::getLastError() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_last_error;
    }

    // --- Private Implementation ---

    bool SymbolResolver::validateExecutable(const std::string& path) {
        if (path.empty()) {
            setError("Empty executable path");
            return false;
        }
        
        if (!std::filesystem::exists(path)) {
            setError("Executable file does not exist: " + path);
            return false;
        }
        
        if (!isExecutableFile(path)) {
            setError("File is not executable: " + path);
            return false;
        }
        
        return true;
    }

    void SymbolResolver::cleanup() {
        if (m_context) {
            m_context->cleanup();
        }
        
        m_is_loaded = false;
        m_load_address = 0;
        m_executable_path.clear();
        m_last_error.clear();
        m_functions.clear();
        m_variables.clear();
        m_function_name_to_index.clear();
        m_variable_name_to_index.clear();
        m_addr_to_line.clear();
        m_line_to_addr.clear();
        m_addr_to_function.clear();
        m_basename_to_paths.clear();
        m_file_to_comp_dir.clear();
        m_path_resolution_cache.clear();
    }

    void SymbolResolver::log(LogLevel level, const std::string& msg) const {
        if (m_logger) {
            m_logger(level, msg);
        } else if (level == LogLevel::Error) {
            std::cerr << "SymbolResolver Error: " << msg << std::endl;
        }
    }

    void SymbolResolver::setError(const std::string& error) {
        m_last_error = error;
        log(LogLevel::Error, error);
    }
    
    bool SymbolResolver::initializeDwarf() {
        if (!m_context || m_context->fd == -1) {
            setError("Invalid file descriptor for DWARF initialization");
            return false;
        }
        
        Dwarf* dwarf = dwarf_begin(m_context->fd, DWARF_C_READ);
        if (!dwarf) {
            setError("Failed to initialize DWARF context: " + std::string(dwarf_errmsg(-1)));
            return false;
        }
        
        m_context->dwarf = std::unique_ptr<Dwarf, void(*)(Dwarf*)>(
            dwarf, [](Dwarf* d) { if (d) dwarf_end(d); }
        );
        
        return true;
    }

    bool SymbolResolver::buildCaches() {
        if (!m_context || !m_context->dwarf) {
            setError("DWARF context not initialized");
            return false;
        }
        
        Dwarf_Off cu_offset = 0, next_cu_offset = 0;
        size_t header_size;
        
        while (dwarf_nextcu(m_context->dwarf.get(), cu_offset, &next_cu_offset, 
                           &header_size, nullptr, nullptr, nullptr) == 0) {
            Dwarf_Die cu_die;
            if (dwarf_offdie(m_context->dwarf.get(), cu_offset + header_size, &cu_die) == nullptr) {
                cu_offset = next_cu_offset;
                continue;
            }

            std::string comp_dir;
            getDwarfAttribute(&cu_die, DW_AT_comp_dir, comp_dir);
            if (comp_dir.empty()) comp_dir = ".";

            // Build path mappings first
            buildPathMappings(&cu_die, comp_dir);
            
            // Process symbols
            visitDIEs(&cu_die, [&](Dwarf_Die* die) {
                int tag = dwarf_tag(die);
                switch (tag) {
                    case DW_TAG_subprogram:
                        processFunctionDIE(die, comp_dir);
                        break;
                    case DW_TAG_variable:
                        processVariableDIE(die, comp_dir);
                        break;
                }
            });

            // Process line information
            processLineInfo(&cu_die);
            
            cu_offset = next_cu_offset;
        }

        // Build index maps for fast lookups
        for (size_t i = 0; i < m_functions.size(); ++i) {
            const Symbol& func = m_functions[i];
            m_function_name_to_index[func.name] = i;
            m_addr_to_function[func.address] = i;
        }
        
        for (size_t i = 0; i < m_variables.size(); ++i) {
            const Symbol& var = m_variables[i];
            m_variable_name_to_index[var.name] = i;
        }

        return true;
    }

    void SymbolResolver::visitDIEs(Dwarf_Die* start_die, const std::function<void(Dwarf_Die*)>& visitor) const {
        if (!start_die) return;
        
        visitor(start_die);

        Dwarf_Die child_die;
        if (dwarf_child(start_die, &child_die) == 0) {
            do {
                visitDIEs(&child_die, visitor);
            } while (dwarf_siblingof(&child_die, &child_die) == 0);
        }
    }

    bool SymbolResolver::processFunctionDIE(Dwarf_Die* die, const std::string& comp_dir) {
        const char* name = dwarf_diename(die);
        if (!name) return false;
        
        Dwarf_Addr low_pc;
        if (dwarf_lowpc(die, &low_pc) != 0 || low_pc == 0) {
            return false; // No valid address
        }
        
        Symbol sym;
        sym.name = name;
        sym.address = low_pc;
        sym.size = calculateSymbolSize(die, low_pc);
        sym.type = Symbol::Type::Function;
        sym.location = extractSourceLocation(die);
        
        // Resolve relative paths in source location
        if (!sym.location.filename.empty()) {
            sym.location.filename = resolveSourcePath(sym.location.filename);
        }
        
        m_functions.push_back(sym);
        log(LogLevel::Debug, "Added function: " + sym.toString());
        return true;
    }

    bool SymbolResolver::processVariableDIE(Dwarf_Die* die, const std::string& comp_dir) {
        const char* name = dwarf_diename(die);
        if (!name) return false;
        
        // Check if it's a global variable (has DW_AT_location)
        Dwarf_Attribute loc_attr;
        if (!dwarf_attr(die, DW_AT_location, &loc_attr)) {
            return false; // Not a global variable
        }
        
        Dwarf_Op* ops;
        size_t op_count;
        if (dwarf_getlocation(&loc_attr, &ops, &op_count) != 0 || 
            op_count == 0 || ops[0].atom != DW_OP_addr) {
            return false; // Complex location expression or not a simple address
        }
        
        Symbol sym;
        sym.name = name;
        sym.address = ops[0].number;
        sym.type = Symbol::Type::Variable;
        sym.location = extractSourceLocation(die);
        
        // Try to get size from type information
        Dwarf_Attribute type_attr;
        if (dwarf_attr(die, DW_AT_type, &type_attr)) {
            Dwarf_Die type_offset;
            if (dwarf_formref_die(&type_attr, &type_offset) == 0) {
                // Could traverse type information here for size
                sym.size = 0; // Default for now
            }
        }
        
        // Resolve relative paths in source location
        if (!sym.location.filename.empty()) {
            sym.location.filename = resolveSourcePath(sym.location.filename);
        }
        
        m_variables.push_back(sym);
        log(LogLevel::Debug, "Added variable: " + sym.toString());
        return true;
    }

    bool SymbolResolver::processLineInfo(Dwarf_Die* cu_die) {
        Dwarf_Lines* lines;
        size_t line_count;
        if (dwarf_getsrclines(cu_die, &lines, &line_count) != 0) {
            return false;
        }
        
        for (size_t i = 0; i < line_count; ++i) {
            Dwarf_Line* line = dwarf_onesrcline(lines, i);
            if (!line) continue;
            
            Dwarf_Addr addr;
            int line_no_int;
            if (dwarf_lineaddr(line, &addr) != 0 || dwarf_lineno(line, &line_no_int) != 0) {
                continue;
            }
            
            const char* file_cstr = dwarf_linesrc(line, nullptr, nullptr);
            if (!file_cstr) continue;

            int col_int = 0;
            dwarf_linecol(line, &col_int);
            
            SourceLocation loc;
            loc.filename = resolveSourcePath(file_cstr);
            loc.line_number = static_cast<uint32_t>(line_no_int);
            if (col_int > 0) {
                loc.column = static_cast<uint32_t>(col_int);
            }

            m_addr_to_line[addr] = loc;
            std::string line_key = loc.filename + ":" + std::to_string(loc.line_number);
            m_line_to_addr[line_key].push_back(addr);
        }
        
        return true;
    }

    void SymbolResolver::buildPathMappings(Dwarf_Die* cu_die, const std::string& comp_dir) {
        Dwarf_Files* files;
        size_t file_count;
        if (dwarf_getsrcfiles(cu_die, &files, &file_count) != 0) {
            return;
        }
        
        for (size_t i = 0; i < file_count; ++i) {
            const char* file_cstr = dwarf_filesrc(files, i, nullptr, nullptr);
            if (!file_cstr) continue;
            
            std::filesystem::path file_path(file_cstr);
            if (file_path.is_relative()) {
                file_path = std::filesystem::path(comp_dir) / file_path;
            }
            
            std::error_code ec;
            auto canonical_path = std::filesystem::canonical(file_path, ec);
            std::string final_path;
            
            if (!ec) {
                final_path = canonical_path.string();
            } else {
                // Fallback for paths that might not exist on the current system
                final_path = file_path.lexically_normal().string();
                log(LogLevel::Debug, "Could not canonicalize path: " + file_path.string() + 
                    " (" + ec.message() + ")");
            }
            
            std::string basename = file_path.filename().string();
            m_basename_to_paths[basename].push_back(final_path);
            m_file_to_comp_dir[final_path] = comp_dir;
        }
    }

    std::string SymbolResolver::getBasename(const std::string& path) {
        size_t last_slash = path.find_last_of('/');
        return (last_slash != std::string::npos) ? path.substr(last_slash + 1) : path;
    }
    
    std::string SymbolResolver::resolveSourcePath(const std::string& filename) {
        if (filename.empty()) return filename;
        
        // Check cache first
        auto cache_it = m_path_resolution_cache.find(filename);
        if (cache_it != m_path_resolution_cache.end()) {
            return cache_it->second;
        }
        
        std::string result = filename;
        
        // Try to canonicalize if it's an absolute path
        if (std::filesystem::path(filename).is_absolute()) {
            std::error_code ec;
            auto canonical_path = std::filesystem::canonical(filename, ec);
            if (!ec) {
                result = canonical_path.string();
            }
        } else {
            // For relative paths, try to find in our basename mappings
            std::string basename = getBasename(filename);
            auto it = m_basename_to_paths.find(basename);
            if (it != m_basename_to_paths.end()) {
                // If we have exactly one match, use it
                if (it->second.size() == 1) {
                    result = it->second[0];
                } else if (it->second.size() > 1) {
                    // Multiple matches - try to find the best one
                    // Prefer paths that end with the original filename
                    for (const auto& path : it->second) {
                        if (path.ends_with(filename)) {
                            result = path;
                            break;
                        }
                    }
                    if (result == filename) {
                        // No exact match found, use the first one
                        result = it->second[0];
                        log(LogLevel::Warning, "Ambiguous path resolution for: " + filename + 
                            ", using: " + result);
                    }
                }
            }
        }
        
        // Cache the result
        m_path_resolution_cache[filename] = result;
        return result;
    }

    uint64_t SymbolResolver::getSymbolSize(Dwarf_Die* die, uint64_t low_pc) {
        return calculateSymbolSize(die, low_pc);
    }

    SourceLocation SymbolResolver::extractSourceLocation(Dwarf_Die* die) {
        SourceLocation loc;
        
        Dwarf_Attribute decl_file_attr, decl_line_attr, decl_col_attr;
        
        // Get file
        if (dwarf_attr(die, DW_AT_decl_file, &decl_file_attr)) {
            Dwarf_Word file_idx;
            if (dwarf_formudata(&decl_file_attr, &file_idx) == 0) {
                // Get the CU die to access file information
                Dwarf_Die cu_die;
                if (dwarf_diecu(die, &cu_die, nullptr, nullptr) == &cu_die) {
                    Dwarf_Files* files;
                    size_t file_count;
                    if (dwarf_getsrcfiles(&cu_die, &files, &file_count) == 0 && 
                        file_idx < file_count) {
                        const char* filename = dwarf_filesrc(files, file_idx, nullptr, nullptr);
                        if (filename) {
                            loc.filename = filename;
                        }
                    }
                }
            }
        }
        
        // Get line number
        if (dwarf_attr(die, DW_AT_decl_line, &decl_line_attr)) {
            Dwarf_Word line_no;
            if (dwarf_formudata(&decl_line_attr, &line_no) == 0) {
                loc.line_number = static_cast<uint32_t>(line_no);
            }
        }
        
        // Get column (optional)
        if (dwarf_attr(die, DW_AT_decl_column, &decl_col_attr)) {
            Dwarf_Word col_no;
            if (dwarf_formudata(&decl_col_attr, &col_no) == 0 && col_no > 0) {
                loc.column = static_cast<uint32_t>(col_no);
            }
        }
        
        return loc;
    }

    bool SymbolResolver::isValidAddress(uint64_t address) const {
        // Basic validation - address should be within reasonable bounds
        return address != 0 && address != UINT64_MAX;
    }

    bool SymbolResolver::isValidFileName(const std::string& filename) const {
        return !filename.empty() && filename.size() < 4096; // Reasonable path length limit
    }

} // namespace DebuggerEngine