import angr
import claripy
import sys
import threading
import time
import concurrent.futures
#from utils import get_function_info  # Optional utility import

class NoOpProcedure(angr.SimProcedure):
    def run(self, *args, **kwargs):
        # Print the name of the procedure being called
        debugger.info(f"\nNoOpProcedure: {self.display_name}")

        # Log the arguments passed to the procedure
        if args:
            debugger.debug("Arguments:")
            for i, arg in enumerate(args):
                debugger.debug(f"  Arg {i}: {arg}")

        # Log the current instruction address
        debugger.debug(f"Current PC: {hex(self.state.addr)}")

        # Optionally log specific register or memory values
        debugger.debug(f"EAX: {self.state.regs.eax}")
        debugger.debug(f"Stack Pointer (SP): {self.state.regs.sp}")
        debugger.debug(f"Top of Stack: {self.state.memory.load(self.state.regs.sp, 4)}")  # Read 4 bytes from SP

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
        self.debugger.info(f"Setting up state")
        #self.print_function_attrs(function)
        # need to find function.name in self.radar_functions to get args
        match = False
        self.debugger.debug(f"Searching for *{function.name}* in radar")
        for func in self.radar_functions:
            
            if function.name == "main":
                #self.debugger.debug(f"angr Function: {function.name}")
                #self.debugger.debug(f"radar Function: {func.name}")
                if func.name == function.name:
                    self.debugger.info(f"RADAR FIND: {func.name}")
                    radar_func = func
                    match = True
                    break

            elif function.name in func.name:
                self.debugger.info(f"RADAR FIND: {func.name}")
                radar_func = func
                match = True
                break
        if not match:
            self.debugger.info("Not matched")
            return None
        mem_size = 4 # Bytes or 32-bits
        self.debugger.debug(f"Starting state at {hex(function.addr)}")
        state = self.project.factory.blank_state(addr=function.addr)
        self.debugger.debug(f"Storing ret addr {hex(return_addr)} in stack")
        state.memory.store(state.regs.sp, return_addr, size=mem_size)  # Push the return address

        # Push arguments (cdecl: reverse order)
        self.debugger.debug(f'We need to create {len(radar_func.args)} args')
        stack_offset = 4
        for arg in reversed(radar_func.args):
            #print(f"Creating arg {arg.name}")
            symbolic_arg = claripy.BVS(arg.name, 32)
            state.memory.store(state.regs.sp + stack_offset, symbolic_arg,size=mem_size)
            self.debugger.debug(f"Pushed Symbolic Variable on Stack: {symbolic_arg}")
            stack_offset += 4

        # Add angr options
        self.debugger.info("Setting state options: LAZY_SOLVES, ZERO_FILL_UNCONSTRAINED_*  BYPASS_UNSUPPORTED_SYSCALLand CALLLESS")
        state.options.add(angr.options.LAZY_SOLVES)
        state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
        state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)
        state.options.add(angr.options.BYPASS_UNSUPPORTED_SYSCALL)
        state.options.add(angr.options.CALLLESS)
        
        self.debugger.info("Finished state setup")
        return state

    def run_cfg(self):
        return self.project.analyses.CFGFast()
    
    def log_function_attrs(self, func):
        self.debugger.info(f"\tFunction Name: {func.name}")
        self.debugger.debug(f"\tFunction Address: {hex(func.addr)}")
        self.debugger.debug(f"\tFunction Size: {func.size}")
        self.debugger.debug(f"\tIs Syscall: {func.is_syscall}")
        self.debugger.debug(f"\tReturning: {func.returning}")
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
            self.debugger.debug(f"Handling floating-point instruction: {mnemonic} at {hex(state.addr)}")

            # Inject concrete values based on the instruction type
            if mnemonic in ['fld', 'fldz', 'fld1']:  # Load constants
                # Push a concrete value onto the stack
                self.debugger.debug(f"Injecting concrete value for {mnemonic}")
                state.regs.st0 = claripy.BVV(0, state.arch.bits)  # Example: Push 0 onto ST0
            elif mnemonic in ['fst', 'fstp']:  # Store operations
                # Mock a store operation by skipping it
                self.debugger.debug(f"Skipping store for {mnemonic}")
            elif mnemonic.startswith('fi'):  # Integer-FP conversions
                 self.debugger.debug(f"Nopping floating-point instruction: {mnemonic} at {hex(state.addr)}")
            else:
                self.debugger.debug(f"Unknown floating-point instruction {mnemonic}, skipping.")

            # Skip the instruction by advancing the instruction pointer
            state.regs.ip += instruction.size
    
    def enable_floating_pt_replacement(self, state):
        """Set up an instruction hook to log executed instructions."""
        state.inspect.b(
            "instruction",
            when=angr.BP_BEFORE,
            action=self.replace_floating_pt_with_concrete,
        )

    def start_sim(self, simgr, return_addr, function):
        start_time = time.time()
        found = False
        while simgr.active:
            # Check for timeout
            elapsed_time = time.time() - start_time
            if elapsed_time > self.simulation_timeout:
                self.debugger.info(f"Timeout reached after {self.simulation_timeout} seconds for function {function.name}. Moving to the next function.")
                break

            # Perform one symbolic execution step
            simgr.step()
            #print("Step")

            # Check for found paths
            found_states = [s for s in simgr.active if s.addr == return_addr]
            if found_states:
                found = True
                for found_state in found_states:
                    simgr.move(from_stash='active', to_stash='deadended', filter_func=lambda s: s.addr == return_addr)
                self.debugger.info(f"Found return address {hex(return_addr)} for function {function.name}.")
                break

        # Check results
        if found:
            self.debugger.info("Symbolic execution succeeded!")
        else:
            self.debugger.info(f"No valid paths found for function {function.name}.")
        return simgr

    def execute_function(self, function):
        """Execute symbolic execution for a single function."""
        self.debugger.info(f"Starting symbolic execution for:")
        self.log_function_attrs(function)
        
        
        if not [ret.addr for ret in function.ret_sites]:
            #self.print_function_attrs(function)
            self.debugger.info("No return sites found. Skipping")
        for return_addr in [ret.addr for ret in function.ret_sites]:
            self.debugger.info(f"Executing for return address: {hex(return_addr)}")
            state = self.setup_state(function, return_addr)
            error = False
            continue_to_nxt = False
            if not state:
                self.debugger.info("Failed state init. Skipping")
                return None
            
            # Execute
            self.debugger.info("Initializaing simulation manager.")
            simgr = self.project.factory.simgr(state)
            self.debugger.info("Staring Simulation")

            try:
                simgr = self.start_sim(simgr, return_addr, function)
            except Exception as e:
                self.debugger.error("Simulation Failed")
                error = True
                #continue
            

            if error and self.reattempt:
                self.debugger.info(f"Options: {self.reattempt_options}")
                state = self.setup_state(function, return_addr)
                for option in self.reattempt_options:
                    if option == "fp":
                        # Floating point remmediation
                        self.debugger.info("Attempt floating point remediation")
                        self.enable_floating_pt_replacement(state)
                        simgr = None
                        simgr = self.project.factory.simgr(state)
                        try:
                            simgr.explore(find=return_addr)
                            error = False
                            break
                        except Exception as e:
                            #Reattempt, then debug and move on
                            self.debugger.error(f"Simulation failed during reattempt option.")
            
            if error:
                self.debugger.debug("Reinitializing state for debug logs")
                debug_state = self.setup_state(function, return_addr)
                self.debugger.enable_instruction_logging(debug_state)
                debug_simgr = self.project.factory.simgr(debug_state)
                try:
                    debug_simgr.explore(find=return_addr)
                    self.debugger.set_status(False)
                    self.debugger.debug("Finished debug")
                except Exception as e:
                    self.debugger.debug(f"Symbolic Execution failed with error:\n{e}")
                    continue_to_nxt = True
            
            if continue_to_nxt:
                self.debugger.info("Skipping to next function.")
                continue
            
            for deadend_state in simgr.deadended:
                self.debugger.info(f"Deadended state at address: {hex(deadend_state.addr)}")
                for constraint in deadend_state.solver.constraints:
                    self.debugger.info(constraint)
            error_count = 0
            max_errors = 10  # Example threshold
            if simgr.errored:
                for error in simgr.errored:
                    self.debugger.error(f"Errored State: {error}")
                    #print(f"Address: {hex(error.state.addr)}")
                    error_count += 1
                    if error_count > max_errors:
                        self.debugger.error("Too many error states. Stopping state logging.")
                        break
                simgr.drop(stash='errored') 
            

    def execute_all(self):
        main_object = self.project.loader.main_object
        text_section = main_object.sections_map.get('.text')
        
        if not text_section:
            self.debugger.error("Could not find the '.text' section in the binary")

        text_start = text_section.vaddr
        text_end = text_start + text_section.memsize

        binary_start = main_object.min_addr
        binary_end = main_object.max_addr
        self.debugger.info(f"Min Memory Address: {hex(binary_start)}")
        self.debugger.info(f"Max Memory Address: {hex(binary_end)}")
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
            self.debugger.info(f"\n\nWorking on function {count}/{len(user_functions)}")
            start_time = time.time()
            self.execute_function(function)
            end_time = time.time()

            # Calculate and print the elapsed time
            elapsed_time = end_time - start_time
            self.debugger.info(f"Time taken: {elapsed_time:.2f} seconds")
            if (count == len(user_functions)):
                self.debugger.info("Complete!")
                #sys.exit(0)
























