#!/usr/bin/env python3
import subprocess
import sys

def run_nullhandshake_command(command):
    """Run a command in NullHandshake and capture the output."""
    process = subprocess.Popen(
        ['python', 'nullhandshake.py'],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    # Send command
    stdout, stderr = process.communicate(input=command + '\nexit\n')
    
    # Print output
    print(stdout)
    print(stderr, file=sys.stderr)
    
    return process.returncode

if __name__ == '__main__':
    # Check if a command was provided
    if len(sys.argv) > 1:
        command = sys.argv[1]
    else:
        command = 'help'
    
    sys.exit(run_nullhandshake_command(command))