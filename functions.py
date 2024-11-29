import json
import re

class Argument:
    def __init__(self, type, name):
        self.type = type
        self.name = name
    
    def to_dict(self):
        """Convert the Argument object to a dictionary for JSON serialization."""
        return {
            'type': self.type,
            'name': self.name
        }
    
    def __repr__(self):
        return (f"Argument(type={self.type}, name={self.name})")

class Function:
    def __init__(self, name, offset, size, type, stackframe, calltype, signature, n_args, n_locals, datarefs, callrefs):
        self.name = name
        self.offset = offset
        self.size = size
        self.type = type
        self.stackframe = stackframe
        self.calltype = calltype
        self.signature = signature
        self.n_args = n_args
        self.n_locals = n_locals
        self.datarefs = datarefs
        self.callrefs = callrefs
        self.args = []
        self.extract_arguments()
    
    def to_dict(self):
        """Convert the Function object to a dictionary for JSON serialization."""
        return {
            'name': self.name,
            'offset': self.offset,
            'size': self.size,
            'type': self.type,  # Updated field name
            'stackframe': self.stackframe,
            'calltype': self.calltype,
            'signature': self.signature,
            'n_args': self.n_args,
            'n_locals': self.n_locals,
            'datarefs': self.datarefs,
            'callrefs': self.callrefs,
            'args': [arg.to_dict() for arg in self.args]
        }

    @staticmethod
    def from_dict(data):
        """Create a Function object from a dictionary."""
        return Function(
            data['name'],
            data['offset'],
            data['size'],
            data['type'],  # Updated field name
            data['stackframe'],
            data['calltype'],
            data['signature'],
            data['n_args'],
            data['n_locals'],
            data['datarefs'],
            data['callrefs']
        )
        # Convert arguments back from the dictionaries
        func.args = [Argument(arg['type'], arg['name']) for arg in data['args']]
        return func

    def extract_arguments(self):
        #print(f"Extracting from: {self.signature}")
        match = re.search(r'\((.*?)\)', self.signature)
        if match:
            args_str = match.group(1)  # Get the part inside the parentheses
            #print(f'arg_str:{args_str}')
            # Now split the arguments by commas, but also clean up extra spaces
            args = args_str.split(',')

            if not args:
                print('No args')
                return
            
            # Clean up each argument and print
            for arg in args:
                # Strip any extra spaces and check for type and name
                parts = arg.strip().split()
                if not parts:
                    continue
                #print(f'parts: {parts}')
                # Handle multi-word types (e.g., 'const char *s')
                if len(parts) >= 2:
                    # The type could be multiple words, so we join them back together except the last part (argument name)
                    type_name = ' '.join(parts[:-1])
                    arg_name = parts[-1]
                    final_arg = Argument(type=type_name, name=arg_name)
                    self.args.append(final_arg)
                    #print(f"Type: {type_name}, Argument: {arg_name}")
                else:
                    if ("..." in arg):
                        continue
                    print("Invalid argument format:", arg)



    def __repr__(self):
        return (f"Function(name={self.name}, offset={self.offset}, size={self.size}, type={self.type},"
                f"stackframe={self.stackframe}, calltype={self.calltype}, signature={self.signature}, "
                f"n_args={self.n_args}, n_locals={self.n_locals}, "
                f"datarefs={self.datarefs}, callrefs={self.callrefs}, args={self.args})")
