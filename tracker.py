class FunctionInstance:
    def __init__(self, function_name):
        """
        Initialize the FunctionInstance for a specific function.
        :param function_name: The name of the function.
        """
        self.function_name = function_name
        self.return_data = {}  # {return_addr: {"constraints": [], "memory_accesses": []}}

    def add_return_address(self, return_addr):
        """
        Add a return address to the function.
        :param return_addr: The return address to add.
        """
        if return_addr not in self.return_data:
            self.return_data[return_addr] = {"constraints": [], "memory_accesses": []}

    def add_constraints(self, return_addr, constraints):
        """
        Add constraints for a specific return address.
        :param return_addr: The return address of the function.
        :param constraints: The constraints to add.
        """
        self.add_return_address(return_addr)
        self.return_data[return_addr]["constraints"].extend(constraints)

    def add_memory_accesses(self, return_addr, memory_accesses):
        """
        Add memory accesses for a specific return address.
        :param return_addr: The return address of the function.
        :param memory_accesses: The memory accesses to add.
        """
        self.add_return_address(return_addr)
        self.return_data[return_addr]["memory_accesses"].extend(memory_accesses)

    def get_constraints(self, return_addr=None):
        """
        Retrieve constraints for a specific return address or all.
        :param return_addr: Optional return address to filter constraints.
        :return: A list of constraints or a dictionary of all return addresses and constraints.
        """
        if return_addr:
            return self.return_data.get(return_addr, {}).get("constraints", [])
        return {
            addr: data["constraints"]
            for addr, data in self.return_data.items()
        }

    def get_memory_accesses(self, return_addr=None):
        """
        Retrieve memory accesses for a specific return address or all.
        :param return_addr: Optional return address to filter memory accesses.
        :return: A list of memory accesses or a dictionary of all return addresses and memory accesses.
        """
        if return_addr:
            return self.return_data.get(return_addr, {}).get("memory_accesses", [])
        return {
            addr: data["memory_accesses"]
            for addr, data in self.return_data.items()
        }

    def list_return_addresses(self):
        """
        List all return addresses for this function.
        :return: A list of return addresses.
        """
        return list(self.return_data.keys())

    def __repr__(self):
        return f"FunctionInstance({self.function_name}, {len(self.return_data)} return addresses)"

class Tracker:
    def __init__(self, binary_name, debugger):
        """
        Initialize the Tracker for a specific binary.
        :param binary_name: The name of the binary being tracked.
        """
        self.binary_name = binary_name
        self.functions = {}  # {function_name: FunctionInstance}
        self.debugger = debugger

    def initialize_function(self, function_name):
        """
        Ensure a function instance exists in the tracker.
        :param function_name: The name of the function.
        """
        if function_name not in self.functions:
            self.functions[function_name] = FunctionInstance(function_name)

    def add_return_address(self, function_name, return_addr):
        """
        Add a return address to a specific function.
        :param function_name: The name of the function.
        :param return_addr: The return address to add.
        """
        self.initialize_function(function_name)
        self.functions[function_name].add_return_address(return_addr)

    def add_constraints(self, function_name, return_addr, constraints):
        """
        Add constraints to a specific function and return address.
        :param function_name: The name of the function.
        :param return_addr: The return address of the function.
        :param constraints: The constraints to add.
        """
        self.initialize_function(function_name)
        self.functions[function_name].add_constraints(return_addr, constraints)

    def integrate_memory_accesses(self, function_name, memory_accesses_by_ret_addr):
        """
        Integrate memory accesses into a specific function instance.
        :param function_name: The name of the function.
        :param memory_accesses_by_ret_addr: Dictionary {return_addr: [memory_access1, memory_access2, ...]}.
        """
        self.initialize_function(function_name)
        for return_addr, memory_accesses in memory_accesses_by_ret_addr.items():
            self.functions[function_name].add_memory_accesses(return_addr, memory_accesses)

    def get_constraints(self, function_name, return_addr=None):
        """
        Retrieve constraints for a specific function and return address.
        :param function_name: The name of the function.
        :param return_addr: Optional return address to filter constraints.
        :return: A list of constraints or a dictionary of all return addresses and constraints.
        """
        if function_name not in self.functions:
            return None
        return self.functions[function_name].get_constraints(return_addr)

    def get_memory_accesses(self, function_name, return_addr=None):
        """
        Retrieve memory accesses for a specific function and return address.
        :param function_name: The name of the function.
        :param return_addr: Optional return address to filter memory accesses.
        :return: A list of memory accesses or a dictionary of all return addresses and memory accesses.
        """
        if function_name not in self.functions:
            return None
        return self.functions[function_name].get_memory_accesses(return_addr)

    def list_functions(self):
        """
        List all functions in the tracker.
        :return: A list of function names.
        """
        return list(self.functions.keys())

    def list_return_addresses(self, function_name):
        """
        List all return addresses for a specific function.
        :param function_name: The name of the function.
        :return: A list of return addresses.
        """
        if function_name in self.functions:
            return self.functions[function_name].list_return_addresses()
        return []

    def __repr__(self):
        """
        Return a string representation of the tracked functions and return addresses.
        """
        return f"Tracker({self.binary_name}, {len(self.functions)} functions)"
