import angr
import claripy
class Debugger:
    def __init__(self, enabled=False):
        """
        Initialize the Debugger.
        :param enabled: Whether debugging is enabled or disabled.
        """
        self.enabled = enabled
    
    def is_enabled(self):
        if self.enabled:
            return True
        return False

    def log(self, message):
        """
        Log a debug message if debugging is enabled.
        :param message: The message to log.
        """
        if self.enabled:
            print(f"[DEBUG] {message}")
    
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
                    pass
                else:
                    print(f"Executing instruction: {insn}")
            else:
                print(f"No instruction found at address: {hex(state.addr)}")
        except Exception as e:
            print(f"Error disassembling instruction at {hex(state.addr)}: {e}")

    def attach_call_logger(self, state, project):
        """
        Attach a call-level logger to the angr state.
        :param state: The angr state to attach the logger to.
        :param project: The angr project to retrieve function information.
        """
        if self.enabled:
            state.inspect.b(
                'call',
                when=angr.BP_BEFORE,
                action=lambda s: self.log(self.get_function_info(s, project))
            )

    def set_status(self, enabled):
        """
        Enable or disable debugging.
        :param enabled: True to enable debugging, False to disable.
        """
        self.enabled = enabled
