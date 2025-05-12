#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
NullHandshake - CLI Runner

This script provides a simple way to run NullHandshake commands from the command line.
Usage: python run.py <command>
Example: python run.py "load wifirecon"
"""

import sys
from run_command import run_nullhandshake_command

def main():
    """Main entry point for the script."""
    if len(sys.argv) > 1:
        command = sys.argv[1]
    else:
        print("Usage: python run.py <command>")
        print("Example: python run.py \"load wifirecon\"")
        sys.exit(1)
    
    return run_nullhandshake_command(command)

if __name__ == '__main__':
    sys.exit(main())