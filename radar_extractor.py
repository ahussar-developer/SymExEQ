import r2pipe
import json
import os
import argparse
from functions import Function,Argument, Call
from debugger import Debugger

class FunctionExtractor:
    def __init__(self, binary_path, json_filename, debugger):
        """
        Initialize the FunctionExtractor.
        :param binary_path: Path to the binary to analyze.
        :param json_filename: Name of the output JSON file to save function details.
        """
        self.binary_path = binary_path
        self.dir = "json/"
        self.json_filename = os.path.join(self.dir, json_filename)
        self.debugger = debugger
        self.r2 = None
        self.functions = []
        self.create_dir()

    def create_dir(self):
        if not os.path.exists(self.dir):
            os.makedirs(self.dir)
            self.debugger.info(f"Directory {self.dir} created.")
        else:
            self.debugger.info(f"Directory {self.dir} already exists.")


    def open_binary(self):
        """Open the binary in radare2."""
        self.r2 = r2pipe.open(self.binary_path, flags=["-e", "bin.cache=true"])
        self.r2.cmd("aaa")  # Perform analysis

    def extract_functions(self):
        """Extract function details using radare2."""
        function_list = json.loads(self.r2.cmd("aflj"))
        for func in function_list:
            # Extract function details with error handling for optional fields
            drf = func.get('datarefs', [])
            crf = func.get('callrefs', [])
            
            # Create a Function object
            fn = Function(
                name=func["name"],
                offset=func["offset"],
                size=func["size"],
                type=func["type"],
                stackframe=func["stackframe"],
                calltype=func["calltype"],
                signature=func["signature"],
                n_args=func["nargs"],
                n_locals=func["nlocals"],
                datarefs=drf,
                callrefs=crf,
                debugger=self.debugger
            )
            self.functions.append(fn)
    
    def save_to_json(self):
        """Save the extracted functions to a JSON file."""
        with open(self.json_filename, 'w') as f:
            json.dump([func.to_dict() for func in self.functions], f)
        self.debugger.info(f"Function details saved to {self.json_filename}")
    
    def close_binary(self):
        """Close the radare2 pipe."""
        if self.r2:
            self.r2.quit()

    def run(self):
        """Execute the full extraction process."""
        try:
            self.open_binary()
            self.extract_functions()
            self.save_to_json()
        finally:
            self.close_binary()

class CallExtractor:
    def __init__(self, binary_path, json_filename, debugger):
        """
        Initialize the CallExtractor.
        :param binary_path: Path to the binary to analyze.
        :param json_filename: Name of the output JSON file to save call details.
        :param debugger: Debugger instance for logging.
        """
        self.binary_path = binary_path
        self.dir = "json/"
        self.json_filename = os.path.join(self.dir, json_filename)
        self.debugger = debugger
        self.r2 = None
        self.calls = []
        self.create_dir()

    def create_dir(self):
        if not os.path.exists(self.dir):
            os.makedirs(self.dir)
            self.debugger.info(f"Directory {self.dir} created.")
        else:
            self.debugger.info(f"Directory {self.dir} already exists.")

    def open_binary(self):
        """Open the binary in radare2."""
        self.r2 = r2pipe.open(self.binary_path, flags=["-e", "bin.cache=true"])
        self.r2.cmd("aaa")  # Perform analysis

    def is_relevant_call(self, func_name):
        excluded_names =  [
            "frame_dummy", "register_tm_clones", "deregister_tm_clones",
            "__libc_csu_init", "__libc_csu_fini", "__do_global_dtors_aux", "_start"
        ]
        if func_name.startswith('__'):
            return False
        if func_name.startswith('_'):
            return False
        if func_name in excluded_names:
            return False
        return True

    def extract_calls(self):
        """
        Extract call details using radare2.
        Identify all functions and iterate through each function's disassembly to locate call instructions.
        """
        self.debugger.info("Extracting calls from binary...")
        function_list = json.loads(self.r2.cmd("aflj"))
        imports = json.loads(self.r2.cmd("iij"))  # Get all imported functions
        imported_functions = {imp["name"]: True for imp in imports}  # Create a set of imported function names

        for func in function_list:
            # Remove `sym.` prefix from the caller's name
            caller_name = func["name"].replace("sym.imp.", "").replace("sym.", "")
            if not self.is_relevant_call(caller_name):
                continue
            caller_offset = func["offset"]

            # Get the disassembly of the function
            disassembly = self.r2.cmd(f"pdfj @{caller_offset}")
            disassembly = json.loads(disassembly)

            if "ops" not in disassembly:
                self.debugger.warning(f"No operations found for function {caller_name}. Skipping...")
                continue

            for op in disassembly["ops"]:
                if op.get("type") == "call":
                    # Extract the target and clean up prefixes
                    target = op.get("disasm").split("call ")[-1]
                    if ".imp." in target:
                        target_import = True
                    else:
                        target_import = False
                    target = target.replace("sym.imp.", "").replace("sym.", "")

                    call_addr = op["offset"]
                    call = Call(caller=caller_name, addr=hex(call_addr), target=target, target_import=target_import)
                    self.calls.append(call)
                    self.debugger.debug(f"Found {call}")


    def save_to_json(self):
        """Save the extracted calls to a JSON file."""
        with open(self.json_filename, 'w') as f:
            json.dump([call.to_dict() for call in self.calls], f, indent=4)
        self.debugger.info(f"Call details saved to {self.json_filename}")

    def close_binary(self):
        """Close the radare2 pipe."""
        if self.r2:
            self.r2.quit()

    def run(self):
        """Execute the full extraction process."""
        try:
            self.open_binary()
            self.extract_calls()
            self.save_to_json()
        finally:
            self.close_binary()
# Add a testable main block
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Extract function details from a binary and save them to a JSON file."
    )
    parser.add_argument(
        "binary_path", 
        type=str, 
        help="Path to the binary file to analyze."
    )
    parser.add_argument(
        "json_filename", 
        type=str, 
        nargs="?", 
        help="Name of the output JSON file. Default: <program_name>_functions.json."
    )

    args = parser.parse_args()

    # Determine default JSON filename if not provided
    if not args.json_filename:
        program_name = os.path.basename(args.binary_path)  # Extract program name
        json_filename = f"{program_name}_functions.json"
        json_calls_filename = f"{program_name}_function_calls.json"
        print(f"{program_name}:{json_filename}")
    else:
        json_filename = args.json_filename
        json_calls_filename = f"{program_name}_function_calls.json"
    debugger = Debugger(enabled=True, level="DEBUG", toFile=False)
    # Validate binary path
    if not os.path.exists(args.binary_path):
        print(f"Error: The binary file '{args.binary_path}' does not exist.")
        exit(1)

    # Run the extractor
    try:
        extractor = FunctionExtractor(args.binary_path, json_filename, debugger)
        extractor.run()
        debugger.info(f"Function extraction completed. Details saved to '{json_filename}'.")
    except Exception as e:
        debugger.error(f"Function extraction failed with error: {e}")
    
    try:
        call_ex = CallExtractor(args.binary_path, json_calls_filename, debugger)
        call_ex.run()
        debugger.info(f"Call extraction completed. Details saved to '{json_calls_filename}'.")
    except Exception as e:
        debugger.error(f"Call extraction failed with error: {e}")