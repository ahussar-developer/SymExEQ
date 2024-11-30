#!/usr/bin/env python3

import angr
import claripy
import json
import re
import os
import argparse
from functions import Function
from radar_extractor import FunctionExtractor
from executor import SymbolicExecutor
from debugger import Debugger

def process_binary(binary_path, debugger):
    project = angr.Project(binary_path, auto_load_libs=False)

    program_name = os.path.basename(binary_path) 
    json_filename = f"{program_name}_functions.json"
    debugger.info(f"The function json file for the binary is {json_filename}")

    if not os.path.exists(json_filename):
        debugger.info(f"JSON file '{json_filename}' not found. Extracting function details...")
        # Use FunctionExtractor to generate the JSON file
        extractor = FunctionExtractor(binary_path, json_filename, debugger)
        try:
            extractor.run()
        except Exception as e:
            debugger.error(f"function extraction failed with error: {e}")
            return
    else:
            debugger.info(f"JSON file '{json_filename}' already exists. Loading functions...")

    # Load the functions from the JSON file
    try:
        with open(json_filename, 'r') as f:
            functions_data = json.load(f)
            functions = [Function.from_dict(data,debugger) for data in functions_data]
    except Exception as e:
        debugger.error(f"Loading functions from JSON failed with error: {e}")
        return


    timeout = 35 # seconds
    reattempt = False # Reattemtp simulation with some changes if errored. Tries to account for floating point and other options
    SE = SymbolicExecutor(binary_path=binary_path, radar_functions=functions, debugger=debugger, simulation_timeout=timeout, reattempt=reattempt)
    SE.execute_all()
    debugger.close()


def main():
    debugger = Debugger(enabled=True, level="DEBUG", toFile=True)

    parser = argparse.ArgumentParser(description="Process a binary or directory of binaries.")
    parser.add_argument("path", help="Path to a binary file or a directory containing binaries")

    args = parser.parse_args()
    input_path = args.path
    
    # Check if the path is a directory
    if os.path.isdir(input_path):
        debugger.info(f"Directory detected: {input_path}")
        # Iterate over all files in the directory and process only binary files
        for filename in os.listdir(input_path):
            file_path = os.path.join(input_path, filename)
            if os.path.isfile(file_path):
                debugger.info(f"Processing binary: {file_path}")
                process_binary(file_path, debugger)
    elif os.path.isfile(input_path):
        # If it's a file, process that binary
        debugger.info(f"File detected: {input_path}")
        process_binary(input_path, debugger)
    else:
        debugger.error(f"{input_path} is neither a valid file nor a directory.")
        return

    # Path to the binary
    #binary_path = "test/bin/coreutils/cp"
    
if __name__ == "__main__":
    main()
