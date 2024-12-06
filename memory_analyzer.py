import angr
import claripy

# TODO: Do we want to track all memory accesses ro path specific?
# Seems path specific would be better for amtching

#TODO: The memory output doesnt match the actual instruction.
# This is liekly were normalization needs to happen so we dont bothe with the address

#TODO: Account for call instructions

class MemoryAnalyzer:
    def __init__(self, project, debugger):
        """
        Initialize the MemoryAnalyzer.
        :param project: The angr project.
        :param debugger: Debugger instance for logging.
        """
        self.project = project
        self.debugger = debugger
        self.memory_accesses = []  # Store relevant memory accesses
        self.memory_accesses_by_ret_addr = {}
        self.stack_region = self.get_stack_region()
    
    def get_stack_region(self):
        """
        Determine the stack region for a 32-bit ELF file.
        :return: Tuple (stack_start, stack_end) representing the stack range.
        """
        stack_base = 0xC0000000  # Stack base for a 32-bit ELF
        stack_size = 0x8000      # Adjust stack size as needed
        stack_start = stack_base - stack_size
        return stack_start, stack_base
    
    def store_memory_accesses(self, return_addr):
        if not self.memory_accesses:
            self.debugger.info(f"No memory accesses to store for return address {hex(return_addr)}.")
            return
        
        self.memory_accesses_by_ret_addr[return_addr] = self.memory_accesses.copy()
        self.debugger.info(f"Stored {len(self.memory_accesses)} memory accesses for return address {hex(return_addr)}.")
        self.memory_accesses.clear()

    def is_relevant_memory_access(self, insn):
        """
        Determine if a memory access is relevant.
        :param insn: Capstone instruction.
        :param addr: Memory address being accessed.
        :return: True if relevant, False otherwise.
        """
        #stack_start, stack_base = self.stack_region
        #if stack_start <= addr <= stack_base:
        #    print(f'{hex(stack_start)} - {hex(stack_base)}: {insn}')
        #    return False  # Ignore stack-related accesses
        # Ignore stack-related instructions
        if "esp" in insn.op_str or "ebp" in insn.op_str:
            return False
        # Ignore push/pop instructions
        if insn.mnemonic in ["push", "pop"]:
            return False
        # Ignore function call setup
        if insn.mnemonic == "call":
            return False

        # Ignore jump table or function pointer resolutions
        if "jmp" in insn.mnemonic and "[" in insn.op_str:
            return False
        
        #OS/Compiler specifc usage
        if "gs:" in insn.op_str or "fs:" in insn.op_str:
            return False
        
        if insn.mnemonic.startswith("rep") and "stos" in insn.mnemonic:
            return False

        if insn.mnemonic in ["leave", "ret"]:
            return False
        return True

    def categorize_memory_address(self, state, insn):
        """
        Categorize a memory address (e.g., stack, heap, global).
        :param addr: Memory address.
        :return: Category as a string.
        """
        print(f'\n\nINSN: {type(insn)} {insn}')
        for op in insn.operands:
            print(f'type: {op.type}')
            print(f'op: {op}')

        is_read = state.inspect.mem_read_address is not None
        addr = state.inspect.mem_read_address if is_read else state.inspect.mem_write_address
        symbolic = False
        category = 'unknown'
        if addr.symbolic:
            # Skip symbolic addresses (optional)
            self.debugger.debug("Skipping symbolic address")
            symbolic = True
            print(f'Symbolic:{addr}')
        if not symbolic:
            concrete_addr = state.solver.eval(addr, cast_to=int)  # Resolve concrete address
            print(f'Concrete: {hex(concrete_addr)}')
        # Determine the relevant register

        '''
        if self.project.loader.main_object.min_addr <= addr <= self.project.loader.main_object.max_addr:
            return "global"
        elif addr in range(0x70000000, 0x80000000):  # Example heap range
            return "heap"
        elif addr in range(0x7fff0000, 0x80000000):  # Example stack range
            return "stack"
        return "unknown"
        '''
        return (symbolic, addr, category)

    def trace_relevant_memory_access(self, state):
        """
        Trace and log relevant memory accesses.
        :param state: Current angr state.
        """
        # Determine if it's a read or write access
        is_read = state.inspect.mem_read_address is not None
        access_type = "read" if is_read else "write"
        

        
        instr_addr = state.addr  # Address of the instruction performing the access
        

        # Fetch the Capstone instruction
        block = state.project.factory.block(instr_addr)
        if not block.capstone.insns:
            self.debugger.debug(f"No instruction found at address: {hex(instr_addr)}")
            return

        triggering_insn = None
        for insn in block.capstone.insns:
            if insn.address == instr_addr:
                triggering_insn = insn
                break

        if self.is_relevant_memory_access(triggering_insn):
            
            # Log the access if it's relevant
            symbolic, addr, category = self.categorize_memory_address(state, triggering_insn)
            self.debugger.debug(f'MEM_{access_type}: {triggering_insn}')
            # Fix this
            #self.memory_accesses.append((instr_addr, concrete_addr, category, access_type))
            
            #self.debugger.debug(f"MEM_{access_type}: Instruction {hex(instr_addr)}: {access_type} at {hex(concrete_addr)} ({category})")


    def attach_hooks(self, state):
        """
        Attach hooks for memory read/write events.
        :param state: Current angr state.
        """
        state.inspect.b("mem_read", when=angr.BP_BEFORE, action=self.trace_relevant_memory_access)
        state.inspect.b("mem_write", when=angr.BP_BEFORE, action=self.trace_relevant_memory_access)

    def reset_memory_accesses(self):
        """
        Reset the memory access log.
        """
        self.memory_accesses = []

    def summarize_all_memory_accesses(self):
        summary = []
        for ret_addr, accesses in self.memory_accesses_by_ret_addr.items():
            summary.append(f"Return Address {hex(ret_addr)}:")
            for instr_addr, addr, category, access_type in accesses:
                summary.append(f"  Instruction {hex(instr_addr)}: {access_type} at {hex(addr)} ({category})")
        return "\n".join(summary)

    def reset_all_stored_accesses(self):
        self.reset_memory_accesses()
        self.memory_accesses_by_ret_addr.clear()
        self.debugger.info("Cleared all stored memory accesses.")
