import angr
import claripy
import sys
import threading
import time
#from utils import get_function_info  # Optional utility import

class NoOpProcedure(angr.SimProcedure):
    def run(self, *args, **kwargs):
        # Print the name of the procedure being called
        print(f"\nNoOpProcedure: {self.display_name}")

        # Log the arguments passed to the procedure
        if args:
            print("Arguments:")
            for i, arg in enumerate(args):
                print(f"  Arg {i}: {arg}")

        # Log the current instruction address
        print(f"Current PC: {hex(self.state.addr)}")

        # Optionally log specific register or memory values
        print(f"EAX: {self.state.regs.eax}")
        print(f"Stack Pointer (SP): {self.state.regs.sp}")
        print(f"Top of Stack: {self.state.memory.load(self.state.regs.sp, 4)}")  # Read 4 bytes from SP

        # Return a default value
        return 0

class SymbolicExecutor:
    def __init__(self, binary_path, radar_functions, debugger, simulation_timeout):
        self.project = angr.Project(binary_path, auto_load_libs=False)
        self.radar_functions = radar_functions
        self.debugger = debugger
        self.simulation_timeout = simulation_timeout #in seconds
        self.cfg = self.run_cfg()
        self.reattempt = True
        self.reattempt_options=['fp']
        self.terminate_flag = threading.Event()
        self.active_threads = []

    def setup_state(self, function, return_addr):
        """Set up the symbolic state for a given function."""
        print(f"Setting up state")
        #self.print_function_attrs(function)
        # need to find function.name in self.radar_functions to get args
        match = False
        for func in self.radar_functions:
            if function.name == "main":
                if func.name == function.name:
                    print(f"RADAR FIND: {func.name}")
                    radar_func = func
                    match = True
                    break

            if function.name in func.name:
                print(f"RADAR FIND: {func.name}")
                radar_func = func
                match = True
                break
        if not match:
            print("Not matched")
            return None
        mem_size = 4 # Bytes or 32-bits
        print(f"Starting state at {hex(function.addr)}")
        state = self.project.factory.blank_state(addr=function.addr)
        print(f"Storing ret addr {hex(return_addr)} in stack")
        state.memory.store(state.regs.sp, return_addr, size=mem_size)  # Push the return address

        # Push arguments (cdecl: reverse order)
        print(f'We need to create {len(radar_func.args)} args')
        stack_offset = 4
        for arg in reversed(radar_func.args):
            #print(f"Creating arg {arg.name}")
            symbolic_arg = claripy.BVS(arg.name, 32)
            state.memory.store(state.regs.sp + stack_offset, symbolic_arg,size=mem_size)
            print(f"Pushed Symbolic Variable on Stack: {symbolic_arg}")
            stack_offset += 4

        # Add angr options
        print("Setting state options: LAZY_SOLVES, ZERO_FILL_UNCONSTRAINED_*  BYPASS_UNSUPPORTED_SYSCALLand CALLLESS")
        state.options.add(angr.options.LAZY_SOLVES)
        state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
        state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)
        state.options.add(angr.options.BYPASS_UNSUPPORTED_SYSCALL)
        state.options.add(angr.options.CALLLESS)
        
        self.debugger.enable_instruction_logging(state)
        print("Finished state setup")
        return state

    def run_cfg(self):
        return self.project.analyses.CFGFast()
    
    def print_function_attrs(self, func):
        print(f"\tFunction Name: {func.name}")
        print(f"\tFunction Address: {hex(func.addr)}")
        print(f"\tFunction Size: {func.size}")
        print(f"\tIs Syscall: {func.is_syscall}")
        print(f"\tReturning: {func.returning}")
        #print(f"\tTransition Graph: {func.transition_graph}")
        #print(f"\tReturn Sites: {func.ret_sites}")

    def replace_floating_pt_with_concrete(self,state):
        """
        Hook to replace floating-point operations with default concrete values.
        """
        # Get the current instruction
        instruction = state.block().capstone.insns[0]
        mnemonic = instruction.mnemonic
        #print("HOOK")

        # Check if the instruction is floating-point related
        if mnemonic.startswith('f'):
            print(f"Handling floating-point instruction: {mnemonic} at {hex(state.addr)}")

            # Inject concrete values based on the instruction type
            if mnemonic in ['fld', 'fldz', 'fld1']:  # Load constants
                # Push a concrete value onto the stack
                print(f"Injecting concrete value for {mnemonic}")
                state.regs.st0 = claripy.BVV(0, state.arch.bits)  # Example: Push 0 onto ST0
            elif mnemonic in ['fst', 'fstp']:  # Store operations
                # Mock a store operation by skipping it
                print(f"Skipping store for {mnemonic}")
            elif mnemonic.startswith('fi'):  # Integer-FP conversions
                 print(f"Nopping floating-point instruction: {mnemonic} at {hex(state.addr)}")
            else:
                print(f"Unknown floating-point instruction {mnemonic}, skipping.")

            # Skip the instruction by advancing the instruction pointer
            state.regs.ip += instruction.size
    
    def enable_floating_pt_replacement(self, state):
        """Set up an instruction hook to log executed instructions."""
        state.inspect.b(
            "instruction",
            when=angr.BP_BEFORE,
            action=self.replace_floating_pt_with_concrete,
        )
    
    def execute_function(self, function):
        """Execute symbolic execution for a single function."""
        print(f"Starting symbolic execution for:")
        self.print_function_attrs(function)
        
        
        if not [ret.addr for ret in function.ret_sites]:
            #self.print_function_attrs(function)
            print("No return sites found. Skipping")
        for return_addr in [ret.addr for ret in function.ret_sites]:
            print(f"Executing for return address: {hex(return_addr)}")
            state = self.setup_state(function, return_addr)
            error = False
            continue_to_nxt = False
            if not state:
                print("Failed state init. Skipping\n")
                return None
            
            exploration_result = [None]
            def explore():
                try:
                    simgr.explore(find=return_addr)
                    exploration_result[0] = True
                except Exception as e:
                    print(f"Error during symbolic execution: {e}")
                    exploration_result[0] = False

            # Execute
            print("Initializaing simulation manager.")
            simgr = self.project.factory.simgr(state)
            print("Staring Simulation")

            # Create a thread for symbolic exploration
            exploration_thread = threading.Thread(target=explore)
            self.active_threads.append(exploration_thread)
            exploration_thread.start()
            
            # Wait for the exploration to finish or timeout
            exploration_thread.join(self.simulation_timeout)
            
            if exploration_thread.is_alive():
                print(f"Timed out after {self.simulation_timeout} seconds while exploring {function.name}. Moving to next function.")
                continue
            else:
                print("Thread completed. DEAD")
            
            # Return the exploration result if no timeout occurred
            if exploration_result[0] is None:
                print("Something went wrong with a thread.")

            error = exploration_result[0]
            if error and self.reattempt:
                print(f"Options: {self.reattempt_options}")
                state = self.setup_state(function, return_addr)
                for option in self.reattempt_options:
                    if option == "fp":
                        # Floating point remmediation
                        print("Attempt floating point remediation")
                        self.enable_floating_pt_replacement(state)
                        simgr = None
                        simgr = self.project.factory.simgr(state)
                        try:
                            simgr.explore(find=return_addr)
                            error = False
                            break
                        except Exception as e:
                            #Reattempt, then debug and move on
                            print(f"Error during symbolic execution.")
            
            if error:
                print("Reinitializing state with debugging enabled for more logs.")
                self.debugger.set_status(True)
                debug_state = self.setup_state(function, return_addr)
                debug_simgr = self.project.factory.simgr(debug_state)
                try:
                    debug_simgr.explore(find=return_addr)
                    self.debugger.set_status(False)
                    print("Finished debug")
                except Exception as e:
                    print(f"Symbolic Execution failed.\nERROR: {e}")
                    continue_to_nxt = True
                    self.debugger.set_status(False)
            
            if continue_to_nxt:
                continue

            # Results
            if simgr.found:
                print("Symbolic execution succeeded!")
                for state in simgr.found:
                    simgr.move(from_stash='found', to_stash='deadended', filter_func=lambda s: s.addr == return_addr)
                #for constraint in simgr.found[0].solver.constraints:
                #    print(constraint)
            else:
                print("No valid paths found.")
            for deadend_state in simgr.deadended:
                print(f"Deadended state at address: {hex(deadend_state.addr)}")
                for constraint in deadend_state.solver.constraints:
                    print(constraint)
            if simgr.errored:
                for error in simgr.errored:
                    print(f"Errored State: {error}")
                    print(f"Address: {hex(error.state.addr)}")

    def execute_all(self):
        main_object = self.project.loader.main_object
        text_section = main_object.sections_map.get('.text')
        
        if not text_section:
            raise ValueError("Could not find the '.text' section in the binary")

        text_start = text_section.vaddr
        text_end = text_start + text_section.memsize

        binary_start = main_object.min_addr
        binary_end = main_object.max_addr
        print(f"Min Memory Address: {hex(binary_start)}")
        print(f"Max Memory Address: {hex(binary_end)}")
        excluded_names =  [
            "frame_dummy", "register_tm_clones", "deregister_tm_clones",
            "__libc_csu_init", "__libc_csu_fini", "__do_global_dtors_aux"
        ]

        user_functions = [
            func for func in self.cfg.kb.functions.values()
            if text_start <= func.addr < text_end  # Ensure it's in the .text section (main code)
            and not func.is_plt  # Exclude PLT (Procedure Linkage Table) entries
            and func.name not in excluded_names  # Exclude known non-user functions
            and not func.name.startswith('_')  # Skip internal/hidden functions
        ]

        count = 0
        for function in user_functions:
            count += 1
            print(f"\nWorking on function {count}/{len(user_functions)}")
            start_time = time.time()
            self.execute_function(function)
            end_time = time.time()

            # Calculate and print the elapsed time
            elapsed_time = end_time - start_time
            print(f"Time taken: {elapsed_time:.2f} seconds")
            if (count == len(user_functions)):
                print("Complete!")
                for thread in active_threads:
                    thread.join()
                self.terminate_flag.set()
                sys.exit(0)
























