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
        
    # TODO: Fix constriant normaliztion
    def extract_core_name(self,var_name):
        """
        Extract the core name of a symbolic variable.
        Handles naming patterns introduced by angr and claripy.
        """
        # SOme have many return vars, should we count them?
        # fake_ret_value_1167_32
        # arg_ch_714_32
        # *arg_ch_537_32
        # size_775_32
        # *stream_1599_32
        # ptr_787_32
        # *ptr_1458_32
        # *s_1104_32
        # **s_515_32
        
        
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
        
        print(f'M1: {core_map1}')
        print(f'M2: {core_map2}')

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
    
    def compare_calls(self, calls1, calls2):
        """
        Compare two sets of calls for equivalence.
        :param calls1: List of Call objects for the first function.
        :param calls2: List of Call objects for the second function.
        :return: True if the calls are equivalent, False otherwise.
        """
        self.debugger.main_equiv(f"Comparing calls: {[call.target for call in calls1]} vs. {[call.target for call in calls2]}")

        if len(calls1) != len(calls2):
            self.debugger.main_equiv(f"call lengths differnt: 1={len(calls1)} 2={len(calls2)}")
            return False

        for call1, call2 in zip(calls1, calls2):
            if call1.target != call2.target:
                self.debugger.main_equiv(f"Targets different: 1={call1.target} 2={call2.target}")
                return False
            if call1.target_import != call2.target_import:
                self.debugger.main_equiv(f"Targets not imports: 1={call1.target} 2={call2.target}")
                return False
        self.debugger.main_equiv(f"Calls equivalent")
        return True
    def compare_constraints(self,c1,c2):
        self.solver.add(c1)
        negated = claripy.Not(claripy.And(*c2))
        self.solver.add(negated)
        constraints_equivalent = not self.solver.satisfiable()
        return constraints_equivalent
    
    def calculate_similarity(self, constraints1, constraints2, calls1, calls2):
        # Constraint similarity
        shared_constraints = self.compare_constraints(constraints1, constraints2)
        constraint_similarity = 1.0 if shared_constraints else 0.0

        # Call similarity
        call_targets1 = set(call.target for call in calls1)
        call_targets2 = set(call.target for call in calls2)
        shared_calls = call_targets1.intersection(call_targets2)
        call_similarity = len(shared_calls) / max(len(call_targets1), len(call_targets2), 1)

        # Return address similarity
        #shared_ret_addrs = set(ret_addrs1).intersection(set(ret_addrs2))
        #ret_addr_similarity = len(shared_ret_addrs) / max(len(ret_addrs1), len(ret_addrs2), 1)

        # Weighted average (adjust weights as needed)
        weights = {"constraints": 0.5, "calls": 0.5}
        similarity_score = (
            weights["constraints"] * constraint_similarity +
            weights["calls"] * call_similarity
        )

        return similarity_score
    
    def are_equivalent(self, function_name, constraints1, constraints2, return_addr1, return_addr2, calls1, calls2, var_mapping=None):
        """
        Check if two sets of constraints and their call patterns are equivalent.
        :param function_name: Name of the function being checked.
        :param constraints1: Constraints from the first function.
        :param constraints2: Constraints from the second function.
        :param return_addr1: Return address of the first function.
        :param return_addr2: Return address of the second function.
        :param var_mapping: Optional mapping of variable names between the two sets of constraints.
        :return: True if equivalent, False otherwise.
        """
        normalized1 = None
        normalized2 = None
        if not self.has_matching_variable_names(constraints1, constraints2):
            # Normalize constraints with variable mapping
            var_mapping = self.build_variable_mapping(constraints1, constraints2)
            normalized1 = self.normalize_constraints(constraints1, var_mapping)
            normalized2 = self.normalize_constraints(constraints2, var_mapping)
        else:
            normalized1 = constraints1
            normalized2 = constraints2
        self.debugger.main_equiv(f"C1: {normalized1}")
        self.debugger.main_equiv(f"C2: {normalized2}")
        
        threshold = 0.75
        similarity_score = self.calculate_similarity(normalized1, normalized2, calls1, calls2)

        # Log similarity score
        self.debugger.main_equiv(f"Function {function_name} - Similarity Score: {similarity_score:.2f}")

        # Determine equivalence based on threshold
        equivalent = similarity_score >= threshold
        
        # Check equivalence of memory constraints
        '''
        self.solver.add(normalized1)
        negated = claripy.Not(claripy.And(*normalized2))
        self.solver.add(negated)
        constraints_equivalent = not self.solver.satisfiable()
        self.debugger.main_equiv(f"contraints equiv:  {constraints_equivalent}")
        
        sorted_calls1 = sorted(calls1, key=lambda call: call.target)
        sorted_calls2 = sorted(calls2, key=lambda call: call.target)
        calls_equivalent = self.compare_calls(sorted_calls1, sorted_calls2)
        
        equivalent = constraints_equivalent and calls_equivalent
        '''

        # Clear solver for next check
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
