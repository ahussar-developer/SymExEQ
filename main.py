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
from solver import ConstraintSolver

class TimeoutException(Exception):
    pass

def timeout_handler(signum, frame):
    raise TimeoutException("Execution timed out")


def analyze_trackers(trackers, debugger):
    """
    Analyze trackers and compare their constraints for equivalence.
    :param trackers: Dictionary of {dir_name: {binary_name: Tracker}}.
    :param debugger: Debugger instance for logging.
    """
    dir1, dir2 = trackers.keys()
    debugger.main_info(f"Starting analysis between trackers for directories: {dir1} and {dir2}")
    
    binaries1 = trackers[dir1]
    binaries2 = trackers[dir2]
    
    common_binaries = set(binaries1.keys()) & set(binaries2.keys())
    if not common_binaries:
        debugger.main_error("No common binaries found for analysis.")
        return

    solver = ConstraintSolver(debugger)

    # Iterate over common binaries
    for binary_name in common_binaries:
        tracker1 = binaries1[binary_name]
        tracker2 = binaries2[binary_name]

        debugger.main_info(f"Analyzing binary: {binary_name}")
        common_functions = set(tracker1.list_functions()) & set(tracker2.list_functions())
        if not common_functions:
            debugger.main_error(f"No common functions found in binary: {binary_name}")
            continue

        # Compare constraints for each function
        for function_name in common_functions:
            debugger.main_info(f"Analyzing function: {function_name}")
            ret_addrs1 = tracker1.get_return_addresses(function_name)
            ret_addrs2 = tracker2.get_return_addresses(function_name)

            # Compare constraints for matching return addresses
            
            for ret_addr1 in ret_addrs1:
                #print(tracker1)
                #print(tracker1.get_return_addresses(function_name))
                constraints1 = tracker1.get_constraints(function_name, return_addr=ret_addr1)
                #debugger.main_info(f"Constraints for {function_name} at {hex(ret_addr1)} in {dir1}:")
                #for c in constraints1:
                #    debugger.main_info(str(c))

                for ret_addr2 in ret_addrs2:
                    #print(tracker2)
                    constraints2 = tracker2.get_constraints(function_name, return_addr=ret_addr2)
                    #print(tracker2.get_return_addresses(function_name))
                    #debugger.main_info(f"Constraints for {function_name} at {hex(ret_addr2)} in {dir2}:")
                    #for c in constraints2:
                    #    debugger.main_info(str(c))
                    equivalent = solver.are_equivalent(constraints1, constraints2)
                    if equivalent:
                        debugger.main_info(f"EQUIVALENT: {function_name} with return addresses {hex(ret_addr1)} and {hex(ret_addr2)} are equivalent.")
                    else:
                        debugger.main_error(f"NOT EQ: {function_name} with return addresses {hex(ret_addr1)} and {hex(ret_addr2)} are NOT equivalent.")
                        debugger.main_error(f'C1: {constraints1}')
                        debugger.main_error(f'C2: {constraints2}')

    debugger.main_info("Tracker analysis complete!")

def process_binary(binary_path, debugger, log_suffix=None):
    project = angr.Project(binary_path, auto_load_libs=False)

    program_name = os.path.basename(binary_path) 
    json_filename = f"{program_name}_functions.json"
    json_dir = "json/"
    json_path = os.path.join(json_dir, json_filename)

    debugger.set_binary_log(f"{program_name}_{log_suffix}.log")
    debugger.info(f"The function json file for the binary is {json_filename}")

    if not os.path.exists(json_path):
        debugger.info(f"JSON file '{json_path}' not found. Extracting function details...")
        # Use FunctionExtractor to generate the JSON file
        extractor = FunctionExtractor(binary_path, json_filename, debugger)
        try:
            extractor.run()
        except Exception as e:
            debugger.error(f"function extraction failed with error: {e}")
            return None
    else:
            debugger.info(f"JSON file '{json_path}' already exists. Loading functions...")

    # Load the functions from the JSON file
    try:
        with open(json_path, 'r') as f:
            functions_data = json.load(f)
            functions = [Function.from_dict(data,debugger) for data in functions_data]
    except Exception as e:
        debugger.error(f"Loading functions from JSON failed with error: {e}")
        return None


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
        return None
    finally:
        debugger.close()
    
    return SE.tracker
    

def process_two_directories(dir1, dir2, debugger, binary_name=None):
    """
    Process directories to match binaries and optionally run on a specific binary.
    :param dir1: Path to the first directory.
    :param dir2: Path to the second directory.
    :param debugger: Debugger instance for logging.
    :param binary_name: Optional specific binary name to process.
    """
    trackers = {dir1: {}, dir2: {}}
    binaries1 = {os.path.basename(file): os.path.join(dir1, file) for file in os.listdir(dir1) if os.path.isfile(os.path.join(dir1, file))}
    binaries2 = {os.path.basename(file): os.path.join(dir2, file) for file in os.listdir(dir2) if os.path.isfile(os.path.join(dir2, file))}

    # Extract the last directory names to use as suffixes
    suffix1 = os.path.basename(os.path.normpath(dir1))
    suffix2 = os.path.basename(os.path.normpath(dir2))

    if binary_name:
        # Process only the specified binary
        if binary_name in binaries1 and binary_name in binaries2:
            debugger.main_info(f"Processing specific binary: {binary_name}")
            try:
                debugger.main_info(f"Running SEE on {suffix1} version of {binary_name}")
                tracker1 = process_binary(binaries1[binary_name], debugger, log_suffix=suffix1)
                if tracker1:
                    trackers[dir1][binary_name] = tracker1
                
                debugger.main_info(f"Running SEE on {suffix2} version of {binary_name}")
                tracker2 = process_binary(binaries2[binary_name], debugger, log_suffix=suffix2)
                if tracker2:
                    trackers[dir2][binary_name] = tracker2
            except Exception as e:
                debugger.main_error(f"Failed to process {binary_name} with error: {e}")
        else:
            debugger.main_error(f"Binary '{binary_name}' not found in both directories.")
    else:
        # Match binaries by name and process them
        common_binaries = set(binaries1.keys()) & set(binaries2.keys())
        if not common_binaries:
            debugger.main_error("No matching binaries found between the two directories.")
            return

        for program_name in common_binaries:
            debugger.main_info(f"Processing matching binary: {program_name}")
            try:
                debugger.main_info(f"Running SEE on {suffix1} version of {program_name}")
                tracker1 = process_binary(binaries1[program_name], debugger, log_suffix=suffix1)
                if tracker1:
                    trackers[dir1][binary_name] = tracker1
                
                debugger.main_info(f"Running SEE on {suffix2} version of {program_name}")
                tracker2 = process_binary(binaries2[program_name], debugger, log_suffix=suffix2)
                if tracker2:
                    trackers[dir2][binary_name] = tracker2
            
            except Exception as e:
                debugger.main_error(f"Failed to process {program_name} with error: {e}")
                continue

        debugger.main_info("Comparison complete!")
    
    # analyze trackers
    analyze_trackers(trackers, debugger)


def process_directory(directory, debugger):
    """Process all binaries in a single directory."""
    for filename in os.listdir(directory):
        file_path = os.path.join(directory, filename)
        if os.path.isfile(file_path):
            debugger.main_info(f"Processing binary: {file_path}")
            try:
                process_binary(file_path, debugger)
            except Exception as e:
                debugger.main_error(f"Failed to process {file_path} with error: {e}")


def main():
    debugger = Debugger(enabled=True, level="DEBUG", toFile=True)

    parser = argparse.ArgumentParser(description="Process one or two directories or a single binary.")
    parser.add_argument("path1", help="Path to a binary, directory, or the first directory for comparison.")
    parser.add_argument("path2", nargs="?", help="Optional: Path to the second directory for comparison.")
    parser.add_argument("binary_name", nargs='?', default=None, help="Optional specific binary to process")

    args = parser.parse_args()
    path1 = args.path1
    path2 = args.path2
    binary_name = args.binary_name

    if path2:
        # Two paths provided, both should be directories
        if os.path.isdir(path1) and os.path.isdir(path2):
            if binary_name:
                debugger.main_info(f"Comparing binary {binary_name} from directories: {path1} and {path2}")
                process_two_directories(path1, path2, debugger, binary_name)
            else:
                debugger.main_info(f"Comparing directories: {path1} and {path2}")
                process_two_directories(path1, path2, debugger, None)
        else:
            debugger.main_error("Both paths must be valid directories for comparison.")
    elif os.path.isdir(path1):
        debugger.main_info(f"Directory detected: {path1}")
        process_directory(path1, debugger)
    elif os.path.isfile(path1):
        # If it's a file, process that binary
        debugger.main_info(f"File detected: {path1}")
        try:
            process_binary(path1, debugger)
        except Exception as e:
            # Catch any unexpected errors during the setup process
            debugger.main_error(f"Failed to process binary '{path1}' with error: {e}")
    else:
        debugger.error(f"{path1} is neither a valid file nor a directory and {path2} wasnt provided.")
        return

    debugger.main_close()
    
if __name__ == "__main__":
    main()
