#include "../../src/SymbolResolver.h"
#include <iostream>
#include <iomanip>
#include <functional>
#include <string>
#include <vector>
#include <sstream>

// Simple testing harness
int total_tests = 0;
int passed_tests = 0;

void run_test(const std::string& test_name, const std::function<std::pair<bool, std::string>()>& test_func) {
    total_tests++;
    std::cout << "--- " << test_name << " ---" << std::endl;
    auto [passed, details] = test_func();
    std::cout << details << std::endl;
    if (passed) {
        passed_tests++;
        std::cout << "[STATUS] PASS" << std::endl;
    } else {
        std::cout << "[STATUS] FAIL" << std::endl;
    }
    std::cout << std::endl;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <path_to_target_executable>" << std::endl;
        return 1;
    }

    std::string target_path = argv[1];
    DebuggerEngine::SymbolResolver resolver;

    std::cout << "--- Loading and Indexing ---" << std::endl;
    if (!resolver.loadExecutable(target_path)) {
        std::cerr << "Failed to load executable. Aborting tests." << std::endl;
        return 1;
    }
    std::cout << "Executable loaded and indexed successfully.\n" << std::endl;

    // ======================================================================
    //                        C TARGET TEST SUITE
    // ======================================================================

    uint64_t main_addr = 0;
    run_test("Function Lookup (Global Func: main)", [&]() {
        std::stringstream details;
        auto addr = resolver.getFunctionAddress("main");
        if (addr) main_addr = *addr;
        details << "  ACTION:  Searching for function 'main'\n";
        details << "  RESULT:  " << (addr ? "Found address 0x" + (std::stringstream() << std::hex << *addr).str() : "Not found.");
        return std::make_pair(addr.has_value(), details.str());
    });

    run_test("Function Lookup (Static Func: helper_func)", [&]() {
        std::stringstream details;
        std::string func_name = "helper_func";
        details << "  ACTION:  Searching for static function '" << func_name << "'\n";
        auto addr = resolver.getFunctionAddress(func_name);
        details << "  RESULT:  " << (addr ? "Found" : "Not found");
        return std::make_pair(addr.has_value(), details.str());
    });
    
    run_test("Function Lookup (Invalid Name)", [&]() {
        std::stringstream details;
        std::string func_name = "nonexistent_c_function";
        details << "  ACTION:  Searching for '" << func_name << "'\n";
        auto addr = resolver.getFunctionAddress(func_name);
        if (!addr) {
            details << "  RESULT:  Correctly not found.";
            return std::make_pair(true, details.str());
        }
        details << "  RESULT:  Incorrectly found at 0x" << std::hex << *addr << std::dec;
        return std::make_pair(false, details.str());
    });

    // --- Global Variable Address Lookups ---
    run_test("Global Var Lookup (Initialized: global_var)", [&]() {
        return std::make_pair(resolver.getGlobalVariableAddress("global_var").has_value(), "  ACTION: Searching for 'global_var'");
    });
    
    run_test("Global Var Lookup (Uninitialized: uninitialized_global)", [&]() {
        return std::make_pair(resolver.getGlobalVariableAddress("uninitialized_global").has_value(), "  ACTION: Searching for 'uninitialized_global'");
    });
    
    run_test("Global Var Lookup (Static: file_static_var)", [&]() {
        return std::make_pair(resolver.getGlobalVariableAddress("file_static_var").has_value(), "  ACTION: Searching for 'file_static_var'");
    });

    run_test("Global Var Lookup (Struct: origin)", [&]() {
        return std::make_pair(resolver.getGlobalVariableAddress("origin").has_value(), "  ACTION: Searching for 'origin'");
    });


    // --- Line <-> Address Lookups ---
    uint64_t line_addr = 0;
    run_test("Line -> Address (Valid Code Line)", [&]() {
        std::stringstream details;
        // Line 34 in target.c is: global_var++;
        int line = 35; 
        details << "  ACTION:  Searching for address of target.c:" << line << "\n";
        auto addrs = resolver.getAddressesForLine("target.c", line);
        if (!addrs.empty()) {
            line_addr = addrs[0];
            details << "  RESULT:  Found " << addrs.size() << " address(es), first is 0x" << std::hex << line_addr;
        } else {
            details << "  RESULT:  No addresses found.";
        }
        return std::make_pair(!addrs.empty(), details.str());
    });
    
    run_test("Address -> Source Location (Valid Address)", [&]() {
        std::stringstream details;
        if (line_addr == 0) {
            details << "  SKIPPED: Previous test failed to get a valid address.";
            return std::make_pair(false, details.str());
        }
        details << "  ACTION:  Searching for source location of 0x" << std::hex << line_addr << std::dec << "\n";
        auto loc = resolver.getSourceLocation(line_addr);
        if (loc) {
            details << "  RESULT:  Found " << loc->filename << ":" << loc->line_number;
            return std::make_pair(loc->line_number == 35, details.str());
        }
        details << "  RESULT:  No location found.";
        return std::make_pair(false, details.str());
    });

    // --- List and Verify ---
    run_test("List All Functions (Check for content)", [&]() {
        std::stringstream details;
        auto funcs = resolver.getAllFunctions();
        details << "  ACTION:  Listing all functions. Found " << funcs.size() << ".\n";
        bool found_main = false;
        bool found_add = false;
        for (const auto& func : funcs) {
            if (func.name == "main") found_main = true;
            if (func.name == "add") found_add = true;
        }
        details << "  RESULT:  Found 'main': " << (found_main ? "Yes" : "No")
                << ", Found 'add': " << (found_add ? "Yes" : "No");
        return std::make_pair(found_main && found_add, details.str());
    });

    run_test("List All Globals (Check for content)", [&]() {
        std::stringstream details;
        auto vars = resolver.getGlobalVariables();
        details << "  ACTION:  Listing all global variables. Found " << vars.size() << ".\n";
        bool found_gvar = false;
        bool found_origin = false;
        for (const auto& var : vars) {
            if (var.name == "global_var") found_gvar = true;
            if (var.name == "origin") found_origin = true;
        }
        details << "  RESULT:  Found 'global_var': " << (found_gvar ? "Yes" : "No")
                << ", Found 'origin': " << (found_origin ? "Yes" : "No");
        return std::make_pair(found_gvar && found_origin, details.str());
    });
    
    // --- Final Tally ---
    std::cout << "\n--- Test Summary ---\n" << std::endl;
    std::cout << "Passed " << passed_tests << " out of " << total_tests << " tests." << std::endl;

    return (passed_tests == total_tests) ? 0 : 1;
}