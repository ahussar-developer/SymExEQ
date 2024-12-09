import angr
import claripy
import datetime
import sys
import logging
import os

class Debugger:
    def __init__(self, enabled=True, level="INFO", toFile=False, curr_bin_log=None):
        """
        Initialize the Debugger.
        :param enabled: Whether debugging is enabled or disabled.
        :param level: The default log level (INFO, DEBUG, ERROR).
        """
        self.dir = f"debug_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.enabled = enabled
        self.level = level.upper()
        self.level_order = {"DEBUG": 1, "INFO": 2, "ERROR": 3, "RESULTS":4, "EQUIV":5}
        self.gen_log_filename = os.path.join(self.dir, "general.log")
        self.curr_bin_log_filename = curr_bin_log
        self.toFile = toFile
        self.curr_bin_log = None
        self.gen_log = None
        
        if self.toFile:
            self.dir_setup()
            # Open the log file for writing
            self.gen_log = open(self.gen_log_filename, "a")
        else:
            self.gen_log = None

        print(self.gen_log)
    
    def is_enabled(self):
        if self.enabled:
            return True
        return False
    
    def set_binary_log(self, bin_log):
        self.curr_bin_log_filename = os.path.join(self.dir, bin_log)
        self.curr_bin_log = open(self.curr_bin_log_filename, "a")
    
    def dir_setup(self):
        if not os.path.exists(self.dir):
            os.makedirs(self.dir)
            self.info(f"Created debug directory: {self.dir}")

    def set_level(self, level):
        """
        Set the log level dynamically.
        :param level: The new log level (INFO, DEBUG, ERROR).
        """
        self.level = level.upper()

    def log(self, level, message):
        """
        Log a message if debugging is enabled and the level is appropriate.
        :param level: The level of the log message.
        :param message: The message to log.
        """
        
        if self.enabled and self.level_order[level.upper()] >= self.level_order[self.level]:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            #print(f"[{timestamp}] [{level.upper()}] {message}")
            log_message = f"[{level.upper()}] {message}"
            if self.toFile and self.curr_bin_log:
                # Write the log message to the file
                self.curr_bin_log.write(log_message + "\n")
            else:
                # Print the log message to stdout
                print(log_message)
    
    def main_log(self, level, message):
        """
        Log a message if debugging is enabled and the level is appropriate.
        :param level: The level of the log message.
        :param message: The message to log.
        """
        if self.enabled and self.level_order[level.upper()] >= self.level_order[self.level]:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            #print(f"[{timestamp}] [{level.upper()}] {message}")
            log_message = f"[{level.upper()}] {message}"
            if self.toFile and self.gen_log:
                # Write the log message to the file
                self.gen_log.write(log_message + "\n")
            else:
                # Print the log message to stdout
                print(log_message)

    def debug(self, message):
        """Log a debug message."""
        self.log("DEBUG", message)

    def info(self, message):
        """Log an informational message."""
        self.log("INFO", message)

    def error(self, message):
        """Log an error message."""
        self.log("ERROR", message)
    
    def main_debug(self, message):
        """Log a debug message."""
        self.main_log("DEBUG", message)

    def main_info(self, message):
        """Log an informational message."""
        self.main_log("INFO", message)

    def main_error(self, message):
        """Log an error message."""
        self.main_log("ERROR", message)

    def main_res(self, message):
        """Log results message."""
        self.main_log("RESULTS", message)
    
    def main_equiv(self, message):
        """Log results message."""
        self.main_log("EQUIV", message)
    
    def close(self):
        """Close the log file if logging to a file."""
        if self.curr_bin_log:
            self.curr_bin_log.close()
            self.curr_bin_log = None
    
    def main_close(self):
        """Close the log file if logging to a file."""
        if self.gen_log:
            self.gen_log.close()
            self.gen_log = None    

    def enable_instruction_logging(self, state):
        """Set up an instruction hook to log executed instructions."""
        if self.enabled:
            state.inspect.b(
                "instruction",
                when=angr.BP_BEFORE,
                action=lambda s: self.print_instruction(s)
            )

    def print_instruction(self, state):
        """Print the disassembled instruction being executed."""
        try:
            block = state.project.factory.block(state.addr)
            if block.capstone.insns:
                insn = block.capstone.insns[0]
                if insn and 'fistp' in insn.mnemonic:
                    self.debug(f"Skipping instruction: {insn}")
                else:
                    self.debug(f"Executing instruction: {insn}")
            else:
                self.debug(f"No instruction found at address: {hex(state.addr)}")
        except Exception as e:
            self.error(f"Error disassembling instruction at {hex(state.addr)}: {e}")

    def log_call_instruction(self, state):
        """
        Log the instruction address and the target of a call instruction.
        :param state: The current angr state.
        """
        try:
            # Get the target address of the call
            target_addr = state.inspect.function_address
            if isinstance(target_addr, claripy.ast.Base):
                # If symbolic, try to concretize
                if state.solver.satisfiable(extra_constraints=[target_addr == target_addr]):
                    concrete_addr = state.solver.eval(target_addr, exact=True)
                    self.debug(f"Call to function at {hex(concrete_addr)} from {hex(state.addr)} (symbolically resolved)")
                else:
                    self.debug(f"Call to function at {target_addr} from {hex(state.addr)} (symbolic and unsatisfiable)")
            else:
                # If concrete, print directly
                self.debug(f"Call to function at {hex(target_addr)} from {hex(state.addr)}")
        except Exception as e:
            self.error(f"Failed to log call instruction: {e}")

    def attach_call_logger(self, state):
        """
        Attach a call-level logger to the angr state.
        :param state: The angr state to attach the logger to.
        :param project: The angr project to retrieve function information.
        """
        if self.enabled:
            state.inspect.b(
                'call',
                when=angr.BP_BEFORE,
                action=lambda s: self.debug(self.log_call_instruction(s))
            )
    def trace_memory_access(self,state):
        """
        Log memory access events, including reads and writes, handling both concrete and symbolic addresses.
        :param state: The current angr state.
        """
        try:
            # Determine whether it's a read or write operation
            is_read = state.inspect.mem_read_address is not None
            addr = state.inspect.mem_read_address if is_read else state.inspect.mem_write_address
            size = state.inspect.mem_read_length if is_read else state.inspect.mem_write_length

            # Address Handling
            if isinstance(addr, claripy.ast.Base):
                if state.solver.satisfiable(extra_constraints=[addr == addr]):
                    concrete_addr = state.solver.eval(addr, exact=True)
                    addr_str = hex(concrete_addr)
                else:
                    addr_str = str(addr)  # Leave symbolic if unsatisfiable
            else:
                addr_str = hex(addr)

            # Size Handling
            if isinstance(size, claripy.ast.Base):
                if state.solver.satisfiable(extra_constraints=[size == size]):
                    concrete_size = state.solver.eval(size, exact=True)
                    size_str = str(concrete_size)
                else:
                    size_str = str(size)  # Leave symbolic if unsatisfiable
            else:
                size_str = str(size)

            # Log the memory access
            access_type = "read" if is_read else "write"
            self.debug(f"Memory {access_type} at instruction {hex(state.addr)}: address={addr_str}, size={size_str}")

        except Exception as e:
            self.error(f"Failed to log memory access at instruction {hex(state.addr)}: {e}")


    def attach_memory_hooks(self,state):
        # Log memory reads
        state.inspect.b(
            "mem_read",
            when=angr.BP_BEFORE,
            action=self.trace_memory_access
        )
        # Log memory writes
        state.inspect.b(
            "mem_write",
            when=angr.BP_BEFORE,
            action=self.trace_memory_access
        )




    def set_status(self, enabled):
        """
        Enable or disable debugging.
        :param enabled: True to enable debugging, False to disable.
        """
        self.enabled = enabled
