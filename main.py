#!/usr/bin/env python3

import angr
import claripy
import json
import re
import os
from functions import Function
from radar_extractor import FunctionExtractor
from executor import SymbolicExecutor
from debugger import Debugger

'''


def get_function_info(state):
    # Resolve the function address
    try:
        func_addr = state.solver.eval(state.inspect.function_address)
    except Exception:
        return "Function address could not be resolved."

    # Lookup the function in the knowledge base
    func = project.kb.functions.get(func_addr)

    # Provide detailed information
    if func:
        return f"Calling function: {func.name} (address: {hex(func_addr)}, size: {func.size} bytes, return type: {func.returning})"
    else:
        return f"Unknown function at address: {hex(func_addr)}"


main_list = [func for func in loaded_data if func['name'] == 'main']
main_function = main_list[0]
'''
#print(main_function)



def main():
    # Path to the binary
    binary_path = "test/bin/coreutils/cp"
    project = angr.Project(binary_path, auto_load_libs=False)
    program_name = os.path.basename(binary_path) 
    json_filename = f"{program_name}_functions.json"
    print(f"JSON: {json_filename}")

    if not os.path.exists(json_filename):
        print(f"JSON file '{json_filename}' not found. Extracting function details...")
        # Use FunctionExtractor to generate the JSON file
        extractor = FunctionExtractor(binary_path, json_filename)
        try:
            extractor.run()
        except Exception as e:
            print(f"Error during function extraction: {e}")
            return
    else:
            print(f"JSON file '{json_filename}' already exists. Loading functions...")

    # Load the functions from the JSON file
    try:
        with open(json_filename, 'r') as f:
            functions_data = json.load(f)
            functions = [Function.from_dict(data) for data in functions_data]
    except Exception as e:
        print(f"Error loading functions from JSON: {e}")
        return

    debugger = Debugger(enabled=False)
    
    SE = SymbolicExecutor(binary_path=binary_path, radar_functions=functions, debugger=debugger, simulation_timeout=60)
    SE.execute_all()

if __name__ == "__main__":
    main()
