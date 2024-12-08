import angr
import claripy
import re
from capstone.x86 import X86_OP_REG, X86_OP_IMM, X86_OP_MEM
# TODO: Do we want to track all memory accesses ro path specific?
# Seems path specific would be better for amtching

#TODO: The memory output doesnt match the actual instruction.
# This is liekly were normalization needs to happen so we dont bothe with the address

#TODO: Account for call instructions
class MemOp:
    def __init__(self, base_reg, index, scale, offset):
        self.base_reg = base_reg
        self.index = index
        self.scale = scale
        self.offset = offset
    def __repr__(self):
        return (f"base_reg={self.base_reg!r}, "
                f"index={self.index!r}, "
                f"scale={self.scale!r}, "
                f"offset={self.offset!r}")
class CallInsn:
    def __init__(self, insn, target, args):
        self.insn = insn
        self.target = target
        self.args = args
    def __repr__(self):
        return (f"Call target={self.target!r}, "
                f"args={self.args!r}")


class MemoryAccess:
    """
    Represents a memory access event.
    """
    def __init__(self, insn, access_type, is_symbolic, symbolic_addr, is_concrete, concrete_addr, tag, source, dest, segment=None):
        self.instruction = insn
        self._access_type = access_type  # 'read' or 'write'
        self._is_symbolic = is_symbolic  # True or False
        self._symbolic_addr = symbolic_addr  # Claripy expression or None
        self._is_concrete = is_concrete  # True or False
        self._concrete_addr = concrete_addr  # Concrete address or None
        self._tag = tag  # 'register', 'stack', 'heap', 'global', etc.
        self.source = source # reg of MemOp
        self.dest = dest # reg or MemOp
        self.segment = segment
    
    def __repr__(self):
        # Extract and clean up the disassembled instruction string
        if hasattr(self.instruction, 'insn_text'):
            insn_str = self.instruction.insn_text.replace("\t", " ")  # Replace tabs with spaces
        else:
            insn_str = str(self.instruction).replace("\t", " ")

        return (
            f"MemoryAccess("
            f"access_type={self._access_type!r}, "
            f"is_symbolic={self._is_symbolic!r}, "
            f"symbolic_addr={self._symbolic_addr!r}, "
            f"is_concrete={self._is_concrete!r}, "
            f"concrete_addr={hex(self._concrete_addr) if self._concrete_addr else None}, "
            f"tag={self._tag!r}, "
            f"source={self.source!r}, "
            f"dest={self.dest!r})"
        )


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
        
        if insn.mnemonic == "endbr32":
            # Ignore control-flow enforcement instructions
            return False

        return True

    def determine_tag(self, insn, source, dest, const):
        """
        Determine the tag for a memory access event.
        
        :param insn: The instruction triggering the memory access.
        :param source: Source operand (register or memory).
        :param dest: Destination operand (register or memory).
        :param const: Indicates if the constant is in the source ('src'), destination ('dest'), or absent (None).
        :return: A string tag (e.g., 'reg=mem', 'mem=const', 'stack=reg').
        """
        # Determine if source/dest are memory operands
        source_is_mem = isinstance(source, MemOp)
        dest_is_mem = isinstance(dest, MemOp)
        
        # Stack-related determination
        source_is_stack = source_is_mem and source.base_reg in {"esp", "ebp"}
        dest_is_stack = dest_is_mem and dest.base_reg in {"esp", "ebp"}

        # Determine if source/dest are registers
        source_is_reg = not source_is_mem and isinstance(source, str) and source not in {None}
        dest_is_reg = not dest_is_mem and isinstance(dest, str) and dest not in {None}

        # Handle cases with constants
        if const == "src":
            if dest_is_mem:
                return "mem=const" if not dest_is_stack else "stack=const"
            elif dest_is_reg:
                return "reg=const"
            else:
                return "const=unknown"

        elif const == "dest":
            if source_is_mem:
                return "const=mem" if not source_is_stack else "const=stack"
            elif source_is_reg:
                return "const=reg"
            else:
                return "unknown=const"

        # Determine the tag based on source/dest when const is None
        if dest_is_reg and source_is_reg:
            return "reg=reg"
        elif dest_is_reg and source_is_mem:
            return "reg=mem" if not source_is_stack else "reg=stack"
        elif dest_is_mem and source_is_reg:
            return "mem=reg" if not dest_is_stack else "stack=reg"
        elif dest_is_mem and source_is_mem:
            return "mem=mem"
        else:
            # TODO account for fld & rep movsd
            print("unknown")
            print(insn)
            print(source)
            print(dest)
            return "unknown"

    def extract_segment_from_instruction(self, instruction_str):
        """
        Extract the segment register from an instruction string.
        :param instruction_str: The instruction string (e.g., "rep movsd dword ptr es:[edi], dword ptr [esi]")
        :return: A list of segment registers found (e.g., ['es']), or an empty list if none are found.
        """
        # Regex pattern to match segment registers before the colon
        segment_pattern = r'\b([a-z]{2}):'  # Match two-letter segment registers followed by ':'
        matches = re.findall(segment_pattern, instruction_str)
        return matches

    def categorize_memory_address(self, state, insn):
        """
        Categorize a memory address (e.g., stack, heap, global).
        :param addr: Memory address.
        :return: Category as a string.
        """
        is_read = state.inspect.mem_read_address is not None
        access_type = "read" if is_read else "write"
        offset = None
        index = None
        scale = None
        base = None
        source_reg = None
        dest_reg = None
        mem_op = None
        const = None
        #self.debugger.debug(f'MEM_{access_type}: {insn}')
        if len(insn.operands) > 2:
            print(f'OP > 2: {len(insn.operands)}')

        if insn.mnemonic == "rep movsd":
            instruction_str = f"{insn.mnemonic}\t{insn.op_str}"
            #print(instruction_str)
            segments = self.extract_segment_from_instruction(instruction_str)
            # Special handling for repeat move string doubleword
            source = MemOp(
                base_reg="esi",
                index=None,
                scale=None,
                offset=None  # Offset is dynamic in this case
            )
            dest = MemOp(
                base_reg="edi",
                index=None,
                scale=None,
                offset=None  # Offset is dynamic in this case
            )
            return MemoryAccess(
                insn=insn,
                access_type="mem=mem",
                is_symbolic=False,  # Usually concrete for this instruction
                symbolic_addr=None,
                is_concrete=True,
                concrete_addr=None,  # Cannot resolve a single concrete address due to repetition
                tag="mem=mem",
                source=source,
                dest=dest,
                segment=segments[0]
            )


        i = 1
        for op in insn.operands:
            if insn.mnemonic.startswith("fld"):
                # Handle floating-point memory access
                mem_op = MemOp(
                    base_reg=insn.reg_name(op.mem.base) if op.mem.base != 0 else None,
                    index=insn.reg_name(op.mem.index) if op.mem.index != 0 else None,
                    scale=op.mem.scale if op.mem.scale != 0 else None,
                    offset=hex(op.mem.disp) if op.mem.disp != 0 else None,
                )
                tag = "fpu=mem"
                # Log or process as required
                return MemoryAccess(
                    insn=insn,
                    access_type="read",
                    is_symbolic=False,  # Usually, FPU loads deal with concrete addresses
                    symbolic_addr=None,
                    is_concrete=True,
                    concrete_addr=None,  # Set the actual resolved address if available
                    tag=tag,
                    source=mem_op,
                    dest="st(0)",  # Represent the FPU stack destination
                )
            if op.type == X86_OP_REG:  # Operand is a register
                reg_name = insn.reg_name(op.reg)
                if i == 2:
                    source_reg = reg_name
                elif i == 1:
                    dest_reg = reg_name
            elif op.type == X86_OP_IMM:  # Operand is an immediate value
                if i == 2:
                    const = 'src'
                    source_reg = hex(op.imm)  # Immediate as source
                elif i == 1:
                    const = 'dest'
                    dest_reg = hex(op.imm)  # Immediate as destination
            elif op.type == X86_OP_MEM:  # Operand is memory
                mem_op = 'src' if i == 2 else 'dest'
                base = insn.reg_name(op.mem.base) if op.mem.base != 0 else None
                index = insn.reg_name(op.mem.index) if op.mem.index != 0 else None
                scale = op.mem.scale if op.mem.scale != 0 else None
                offset = hex(op.mem.disp) if op.mem.disp != 0 else None
                
                 # Check for segment override (e.g., es:[edi])
                #segment_reg = insn.reg_name(op.mem.segment) if op.mem.segment != 0 else None
                #print(segment)
                
            i += 1
        if mem_op:
            tmp_mem =  MemOp(base_reg=base, index=index, scale=scale, offset=offset)
            if mem_op == 'src':
                source_reg = tmp_mem
            elif mem_op == 'dest':
                dest_reg = tmp_mem
        #self.debugger.debug(f'\t\tSource: {source_reg}')
        #self.debugger.debug(f'\t\tDest: {dest_reg}')
        
        addr = state.inspect.mem_read_address if is_read else state.inspect.mem_write_address
        symbolic = False
        category = 'unknown'
        if addr.symbolic:
            # Skip symbolic addresses (optional)
            #self.debugger.debug(f"\t\tSymbolic mem op: {addr}")
            symbolic = True

        if not symbolic:
            concrete_addr = state.solver.eval(addr, cast_to=int)  # Resolve concrete address
            #self.debugger.debug(f"\t\tConcrete mem op: {hex(concrete_addr)}")
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
        #print(insn)
        tag = self.determine_tag(insn, source_reg, dest_reg, const)
        #print(tag)
        return MemoryAccess(
            insn = insn, 
            access_type = access_type, 
            is_symbolic = symbolic, 
            symbolic_addr = addr if symbolic else None, 
            is_concrete = False if symbolic else True, 
            concrete_addr = concrete_addr if not symbolic else None, 
            tag=tag, 
            source = source_reg, 
            dest = dest_reg
        )

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
            mem_access = self.categorize_memory_address(state, triggering_insn)
            self.memory_accesses.append(mem_access)
    def is_relevant_call(self, call_name):
        '''
        excluded_names =  [
            "frame_dummy", "register_tm_clones", "deregister_tm_clones",
            "__libc_csu_init", "__libc_csu_fini", "__do_global_dtors_aux", "_start"
        ]
        if call_name in excluded_names:
            return False
        
        if call_name.name.startswith('sub_'):
            return True  # autogenerated names
        if call_name.name.startswith('__'):
            return False  # compiler-generated and compiler-specific
        if call_name.name.startswith('_') :
            return False # compiler-generated and compiler-specific
        '''
        if call_name.startswith("__x86.get_pc_thunk"):
            print(f"Skipping thunk function: {call_name}")
            return
        print(f"Call: {call_name}")
        return True

    def trace_call(self, state):
        """
        Trace and log call instructions.
        :param state: Current angr state.
        """
        instr_addr = state.addr
        block = state.project.factory.block(instr_addr)
        if not block.capstone.insns:
            self.debugger.debug(f"No instruction found at address: {hex(instr_addr)}")
            return

        triggering_insn = None
        for insn in block.capstone.insns:
            if 'call' in insn.mnemonic:
                triggering_insn = insn
                break
        if triggering_insn == None:
            return
        
        # Extract the call target
        target = int(triggering_insn.op_str, 16)  # Extract address from the instruction operand

        # Attempt to resolve the function name
        func = self.project.kb.functions.get(target)
        func_name = func.name if func else "Unknown Function"
        if (self.is_relevant_call(func_name)):
            print(triggering_insn)
            print(f"CALL detected at {hex(triggering_insn.address)} to {hex(target)} ({func_name})\n")


        '''
        call_target = state.inspect.function_address  # The target address of the call
        #instr_addr = state.addr  # The address of the instruction performing the call
        stack_pointer = state.regs.sp  # Stack pointer at the time of the call

        # Retrieve arguments from the stack (cdecl calling convention example)
        args = []
        for i in range(4):  # Adjust based on the number of arguments you expect
            arg = state.memory.load(stack_pointer + (i * 4), 4, endness=state.arch.memory_endness)
            args.append(state.solver.eval(arg, cast_to=int))

        # Log the call details
        call_details = {
            "instruction_addr": instr_addr,
            "call_target": call_target,
            "arguments": args
        }
        #call = CallInsn(insn)
        self.call_instructions.append(call_details)
        self.debugger.debug(f"CALL: {hex(instr_addr)} -> {hex(call_target)} with args: {args}")
        '''
    def attach_hooks(self, state):
        """
        Attach hooks for memory read/write events.
        :param state: Current angr state.
        """
        state.inspect.b("mem_read", when=angr.BP_BEFORE, action=self.trace_relevant_memory_access)
        state.inspect.b("mem_write", when=angr.BP_BEFORE, action=self.trace_relevant_memory_access)
        state.inspect.b('call', when=angr.BP_BEFORE, action=lambda state: self.trace_call(state))
        #state.inspect.b("call", when=angr.BP_BEFORE, action=self.trace_call)

    def reset_memory_accesses(self):
        """
        Reset the memory access log.
        """
        self.memory_accesses = []

    def summarize_all_memory_accesses(self):
        """
        Summarize all memory accesses for all return addresses.
        :return: A string summarizing all memory accesses in an easy-to-read format.
        """
        summary = []
        summary.append("Memory Access Summary:\n")
        for ret_addr, accesses in self.memory_accesses_by_ret_addr.items():
            summary.append(f"Return Address: {hex(ret_addr)}")
            for access in accesses:
                summary.append(f"  {access}")
            summary.append("")  # Blank line for readability between return addresses
        
        return "\n".join(summary)


    def reset_all_stored_accesses(self):
        self.reset_memory_accesses()
        self.memory_accesses_by_ret_addr.clear()
        self.debugger.info("Cleared all stored memory accesses.")
