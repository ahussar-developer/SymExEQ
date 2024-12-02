class Tracker:
    def __init__(self, binary_name, debugger):
        """
        Initialize the ConstraintTracker for a specific binary.
        :param binary_name: The name of the binary being tracked.
        """
        self.binary_name = binary_name
        self.function_data = {}  # {function_name: {return_addr: [constraints]}}
        self.return_addresses = {}  # {function_name: [return_addr1, return_addr2, ...]}
        self.debugger = debugger
    
    def initialize_function(self, function_name):
        """
        Ensure function entry exists in the tracker.
        :param function_name: The name of the function to initialize.
        """
        if function_name not in self.function_data:
            self.function_data[function_name] = {}
        if function_name not in self.return_addresses:
            self.return_addresses[function_name] = []

    def add_return_address(self, function_name, return_addr):
        """
        Add a return address to a specific function.
        :param function_name: The name of the function.
        :param return_addr: The return address to add.
        """
        self.initialize_function(function_name)  # Ensure the function is initialized

        if return_addr not in self.return_addresses[function_name]:
            self.return_addresses[function_name].append(return_addr)

        # Ensure the function_data also includes this return address
        if return_addr not in self.function_data[function_name]:
            self.function_data[function_name][return_addr] = {"constraints": [], "address": return_addr}


    def add_constraints(self, function_name, return_addr, constraints):
        """
        Add constraints and save return address for a specific function.
        :param function_name: The name of the function.
        :param return_addr: The return address of the function.
        :param constraints: The constraints to add.
        """
        if function_name not in self.function_data:
            self.function_data[function_name] = {}
            self.return_addresses[function_name] = []

        # Add constraints and return address
        if return_addr not in self.function_data[function_name]:
            self.function_data[function_name][return_addr] = {"constraints": [], "address": return_addr}
            self.return_addresses[function_name].append(return_addr)

        self.function_data[function_name][return_addr]["constraints"].extend(constraints)
    

    def get_constraints(self, function_name, return_addr=None):
        """
        Retrieve constraints for a specific function and return address.
        :param function_name: The name of the function.
        :param return_addr: Optional return address to filter constraints.
        :return: A list of constraints or a dictionary of all return addresses and constraints.
        """
        if function_name not in self.function_data:
            return None
        if return_addr:
            return self.function_data[function_name].get(return_addr, {}).get("constraints", [])
        return {
            addr: data["constraints"]
            for addr, data in self.function_data[function_name].items()
        }
    
    def get_return_addresses(self, function_name):
        """
        Retrieve all return addresses for a specific function.
        :param function_name: The name of the function.
        :return: A list of return addresses.
        """
        return self.return_addresses.get(function_name, [])

    def get_all_return_addresses(self):
        """
        Retrieve all return addresses across all functions.
        :return: A dictionary of function_name: [return addresses].
        """
        return self.return_addresses

    def list_functions(self):
        """
        List all functions for which constraints are tracked.
        :return: A list of function names.
        """
        return list(self.function_data.keys())

    def list_return_addresses(self, function_name):
        """
        List all return addresses for a specific function.
        :param function_name: The name of the function.
        :return: A list of return addresses.
        """
        if function_name in self.function_data:
            return list(self.function_data[function_name].keys())
        return []

    def __repr__(self):
        """
        Return a string representation of the tracked constraints and return addresses.
        """
        return f"ConstraintTracker({self.binary_name}, {len(self.function_data)} functions, {sum(len(addrs) for addrs in self.return_addresses.values())} return addresses)"
