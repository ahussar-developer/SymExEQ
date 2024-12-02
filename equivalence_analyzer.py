import claripy
import re
import json
class EquivalenceAnalyzer:
    def __init__(self,  binary1_name, binary2_name, debugger):
        self.binary1_name = binary1_name
        self.binary2_name = binary2_name
        self.equivalence_results = {}  # {function_name: {gcc_ret_addr: {clang_ret_addr: is_equivalent}}}
        self.not_equivalence_results = {}
        self.solver = claripy.Solver()
        self.debugger = debugger
    
    def set_equivalence_res(self, function_name, ret_addr):
        self.equivalence_results
    def extract_core_name(self,var_name):
        """
        Extract the core name of a symbolic variable.
        Handles naming patterns introduced by angr and claripy.
        """
        match = re.match(r"arg_\w+_(\d+)_\d+", var_name)
        return match.group(1) if match else var_name
    
    def build_variable_mapping(self, constraints1, constraints2):
        """
        Build a mapping between variable names from two sets of constraints.
        :param constraints1: First set of constraints.
        :param constraints2: Second set of constraints.
        :return: Mapping dictionary {var1: var2}.
        """
        variables1 = set(str(var) for c in constraints1 for var in c.variables)
        variables2 = set(str(var) for c in constraints2 for var in c.variables)

        # Extract core names
        core_map1 = {var: self.extract_core_name(var) for var in variables1}
        core_map2 = {var: self.extract_core_name(var) for var in variables2}

        # Build mapping
        mapping = {}
        for var1, core1 in core_map1.items():
            for var2, core2 in core_map2.items():
                if core1 == core2:
                    mapping[var1] = var2
                    break
        return mapping

    def extract_variable_names(self, constraints):
        """
        Extract the variable names from a list of claripy constraints.
        :param constraints: List of claripy constraints.
        :return: Set of variable names as strings.
        """
        variable_names = set()
        for constraint in constraints:
            # Traverse the AST to extract free variables
            for var in constraint.variables:
                variable_names.add(var)
        return variable_names
    
    def has_matching_variable_names(self, constraints1, constraints2):
        """
        Check if two sets of constraints have matching variable names.
        :param constraints1: List of claripy constraints from the first function.
        :param constraints2: List of claripy constraints from the second function.
        :return: True if the variable names match, False otherwise.
        """
        vars1 = self.extract_variable_names(constraints1)
        vars2 = self.extract_variable_names(constraints2)
        return vars1 == vars2

    def normalize_constraints(self, constraints, var_mapping=None):
        """
        Normalize constraints to standardize variable names.
        :param constraints: List of claripy constraints.
        :param var_mapping: Dictionary mapping original variable names to normalized ones.
        :return: List of normalized constraints.
        """
        normalized = []
        if var_mapping:
            for constraint in constraints:
                for old_var, new_var in var_mapping.items():
                    constraint = constraint.replace(old_var, new_var)
                normalized.append(constraint)
        else:
            normalized = constraints  # No normalization needed
        return normalized

    def are_equivalent(self, function_name, constraints1, constraints2, return_addr1, return_addr2, var_mapping=None):
        """
        Check if two sets of constraints are equivalent.
        :param constraints1: Constraints from the first function.
        :param constraints2: Constraints from the second function.
        :param var_mapping: Optional mapping of variable names between the two sets of constraints.
        :return: True if equivalent, False otherwise.
        """
        normalized1 = None
        normalized2 = None
        if not self.has_matching_variable_names(constraints1, constraints2):
            #self.debugger.main_info("Normalizing constriants")
            var_mapping = self.build_variable_mapping(constraints1, constraints2)
            # Normalize constraints
            normalized1 = self.normalize_constraints(constraints1, var_mapping)
            normalized2 = self.normalize_constraints(constraints2, var_mapping)
            #print(f"Nomralized C1: {normalized1}")
            #print(f"Nomralized C2: {normalized1}")
        else:
            normalized1 = constraints1
            normalized2 = constraints2
        # Add first set of constraints
        self.solver.add(normalized1)

        # Check if the negation of the second set is satisfiable
        negated = claripy.Not(claripy.And(*normalized2))
        self.solver.add(negated)
        equivalent = not self.solver.satisfiable()

        #clear for next check
        self.solver = claripy.Solver()

        # Track equivalence results
        unmatched1 = f"unmatched_{self.binary1_name}"
        unmatched2 = f"unmatched_{self.binary2_name}"
        if function_name not in self.equivalence_results:
            self.equivalence_results[function_name] = {
                "all_matched": True,  # Assume true initially
                "matched_pairs": [],
                unmatched1: [],
                unmatched2: []
            }

        results = self.equivalence_results[function_name]
        if equivalent:
            results["matched_pairs"].append((return_addr1, return_addr2))
        else:
            results[unmatched1].append(return_addr1)
            results[unmatched2].append(return_addr2)

        # Update all_matched status
        results["all_matched"] = (
            len(results[unmatched1]) == 0 and len(results[unmatched2]) == 0
        )

        return equivalent
        
    def print_equivalence_results(self):
        """
        Print the equivalence results in a readable format.
        """
        self.debugger.main_res("")
        results_str = json.dumps(self.equivalence_results, indent=4, default=str)
        self.debugger.main_res(results_str)

    def compare_functions(self, func1_constraints, func2_constraints, var_mapping=None):
        """
        Compare two functions using their constraints.
        :param func1_constraints: Constraints from the first function.
        :param func2_constraints: Constraints from the second function.
        :param var_mapping: Optional variable mapping between the two functions.
        :return: Dictionary with comparison details.
        """
        equivalence = self.are_equivalent(func1_constraints, func2_constraints, var_mapping)
        result = {
            "equivalence": equivalence,
            "constraints1": func1_constraints,
            "constraints2": func2_constraints,
        }
        return result

    def simplify_constraints(self, constraints):
        """
        Simplify a set of constraints.
        :param constraints: List of claripy constraints.
        :return: Simplified constraints.
        """
        return [c.simplify() for c in constraints]

    def clear(self):
        """
        Clear the solver's state.
        """
        self.solver = claripy.Solver()