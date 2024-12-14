# SymExEQ: Symbolic Execution-Based Equivalence Checking

SymExEQ is a tool designed to compare binaries across different compilers using symbolic execution and constraint-solving techniques.
It analyzes constraints, memory accesses, and function calls to determine equivalence between functions.

---

## Features
- **Function Comparison**: Compares symbolic constraints and function calls to determine equivalence.
- **Support for Multiple Binaries**: Compare binaries from different directories or process a single binary.
- **JSON-Based Logging**: Saves extracted function and call information in JSON format for easy access.
- **Customizable Debugging**: Extensive debugging options for tracking equivalence results.

---

## Installation

### 1. Clone the Repository
```
git clone https://github.com/your-repo/symexeq.git  
cd symexeq
````
### 2. Set Up a Virtual Environment
```
python3 -m venv env  
source env/bin/activate  # For Linux/Mac  
````

### 3. Install Dependencies
Install dependencies:  
`pip install -r requirements.txt `

### 3. Make `main` Executable
`chmod +x main.py`

---
## Usage

### Command-Line Interface
Run the main script to process one or two directories of binaries or a single binary file.

### Arguments
- **`path1`**: Path to the first directory.
- **`path2`**: Path to the second directory.
- **`binary_name`** (optional): Specific binary to process when comparing directories.

#### Examples:
**Compare Two Directories**  
`./main.py /path/to/directory1 /path/to/directory2`

**Compare a Specific Binary Between Directories**  
`./main.py /path/to/directory1 /path/to/directory2 binary_name`  

The tool also supports processing a single binary or directroy for debug purposes.
**Process a Single Binary**  
`./main.py /path/to/binary`

**Process a Directory of Binaries**  
`./main.py /path/to/directory`  

#### Run Provided Test Binaries
We have provided the coreutils programs `true` and `false`, compiled by both `clang` and `gcc`. These binaries are located in the following directories:
- `gcc`-compiled binary: `test/example/gcc/`
- `clang`-compiled binary: `test/example/clang/`

1. Navigate to the project root directory
Use the `cd` command to navigate to the SymExEQ project directory.
`cd /path/to/symexeq`

2. Run SymExEQ on the directories
Execute the main script to compare all binaries in the GCC and Clang directories.
```
./main.py test/example/gcc/ test/example/clang/
````

4. Run SymExEQ on a specific binary
If you want to compare a specific binary (e.g., `true`), provide its name as an additional argument.
```
./main.py test/example/gcc/ test/example/clang/ true
```

---

## How It Works

1. **Binary Analysis**:
   - Extracts function information using `radare2` via `FunctionExtractor` and `CallExtractor`.
   - Saves data to JSON for subsequent symbolic execution.

2. **Symbolic Execution**:
   - Processes each binary using `angr` to perform symbolic execution.
   - Tracks memory accesses, constraints, and function calls.

3. **Equivalence Checking**:
   - Uses `claripy` to compare constraints for equivalence.
   - Matches function calls and memory patterns to compute equivalence scores.

4. **Results**:
   - Generates a summary of equivalence results across binaries.
   - Logs are stored in a structured format for debugging.

---

## File Structure

- **`main.py`**: Entry point of the application.
- **`functions.py`**: Defines `Function` and `Call` objects.
- **`radar_extractor.py`**: Handles function and call extraction using `radare2`.
- **`executor.py`**: Executes symbolic paths using `angr`.
- **`equivalence_analyzer.py`**: Handles constraint and function equivalence logic.
- **`debugger.py`**: Handles debugging and logging.
- **`json/`**: Stores extracted function and call data.

---

## Debugging and Logs
Enable debugging logs to file by setting the `toFile` parameter in the `Debugger` class to `True`.
Note: This will significantly slow down the tool

---

## Requirements

Ensure the following dependencies are installed (included in `requirements.txt`):
- `angr`
- `claripy`
- `r2pipe`
- `pyjson`

---

## Known Issues
- Some binaries may not process correctly if JSON extraction fails.
- Ensure `radare2` is installed and accessible in the system's PATH.

---
