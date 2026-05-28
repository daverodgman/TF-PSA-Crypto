#!/usr/bin/env python3

import sys
import subprocess
import re
from rich.console import Console
from rich.syntax import Syntax
from rich.text import Text

console = Console()

def usage():
    console.print("Usage: dis <object_file.o> <function_name>", style="bold yellow")
    sys.exit(1)

def extract_function_asm(obj_file, func_name):
    import platform
    tool = "objdump"
    
    if platform.system() == "Darwin":
        tool = "/opt/homebrew/opt/llvm/bin/llvm-objdump"  # Adjust path as needed

    try:
        result = subprocess.run(
            [tool, "-d", obj_file],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
    except subprocess.CalledProcessError as e:
        console.print(f"[red]Error running objdump:[/red] {e.stderr.strip()}")
        sys.exit(1)

    # macOS llvm-objdump labels look like:
    # 0000000000000030 <function_name>:
    label_re = re.compile(rf"^([0-9a-f]+)\s+<{re.escape(func_name)}>:")
    next_label_re = re.compile(r"^[0-9a-f]+\s+<.+>:")

    asm_lines = result.stdout.splitlines()
    in_function = False
    output = []

    for line in asm_lines:
        print(line)
        if label_re.match(line):
            in_function = True
            output.append(line)
            continue
        elif in_function and next_label_re.match(line):
            break
        elif in_function:
            output.append(line)

    if not output:
        console.print(f"[red]Function '{func_name}' not found in output from {tool}[/red]")
        sys.exit(1)

    return "\n".join(output)

def highlight_asm(asm_text):
    # Use rich.syntax for better formatting
    syntax = Syntax(asm_text, "gas", theme="ansi_dark", line_numbers=False)
    console.print(syntax)

def main():
    if len(sys.argv) != 3:
        usage()

    obj_file = sys.argv[1]
    func_name = sys.argv[2]

    asm_text = extract_function_asm(obj_file, func_name)
    highlight_asm(asm_text)

if __name__ == "__main__":
    main()
