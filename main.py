#!/usr/bin/env python3

import angr
import claripy
import json
import re
import os
import argparse
import signal
from functions import Function
from radar_extractor import FunctionExtractor
from executor import SymbolicExecutor
from debugger import Debugger

class TimeoutException(Exception):
    pass

def timeout_handler(signum, frame):
    raise TimeoutException("Execution timed out")

def process_binary(binary_path, debugger):
    project = angr.Project(binary_path, auto_load_libs=False)

    program_name = os.path.basename(binary_path) 
    json_filename = f"{program_name}_functions.json"

    debugger.set_binary_log(f"{program_name}.log")
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
    try:
        # Set the timeout for the entire execute_all process
        signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(15 * 60)  # 15 minutes in seconds
        SE.execute_all()
        signal.alarm(0)  # Disable the alarm after successful execution
    except TimeoutException:
        debugger.error("Binary processing timed out. Moving to the next binary.")
    except Exception as e:
        debugger.error(f"Something went wrong while processing the binary")
        debugger.error(f"{e}")
    finally:
        debugger.close()


def main():
    debugger = Debugger(enabled=True, level="DEBUG", toFile=True)

    parser = argparse.ArgumentParser(description="Process a binary or directory of binaries.")
    parser.add_argument("path", help="Path to a binary file or a directory containing binaries")

    args = parser.parse_args()
    input_path = args.path
    
    # Check if the path is a directory
    if os.path.isdir(input_path):
        debugger.main_info(f"Directory detected: {input_path}")
        # Iterate over all files in the directory and process only binary files
        for filename in os.listdir(input_path):
            file_path = os.path.join(input_path, filename)
            if os.path.isfile(file_path):
                debugger.main_info(f"Processing binary: {file_path}")
                try:
                    process_binary(file_path, debugger)
                except Exception as e:
                    # Catch any unexpected errors during the setup process
                    debugger.main_error(f"Failed to process binary '{binary_path}' with error: {e}")
    elif os.path.isfile(input_path):
        # If it's a file, process that binary
        debugger.main_info(f"File detected: {input_path}")
        try:
            process_binary(file_path, debugger)
        except Exception as e:
            # Catch any unexpected errors during the setup process
            debugger.main_error(f"Failed to process binary '{binary_path}' with error: {e}")
    else:
        debugger.error(f"{input_path} is neither a valid file nor a directory.")
        return

    debugger.main_close()
    
if __name__ == "__main__":
    main()
