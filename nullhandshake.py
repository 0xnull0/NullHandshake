#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
NullHandshake - Main CLI Interface

This module provides the main command-line interface for the NullHandshake framework.
"""

import os
import sys
import cmd
import readline
import argparse
import logging
import traceback
from typing import List, Dict, Any, Optional

from rich.console import Console
from rich.prompt import Prompt
from rich.syntax import Syntax
from rich.panel import Panel

from core.framework import NullHandshake
from core.config import Config

class NullHandshakeCLI(cmd.Cmd):
    """Command-line interface for the NullHandshake framework."""
    
    intro = ""  # Set in init
    prompt = "[nullhandshake] > "
    
    def __init__(self, framework: NullHandshake):
        """
        Initialize the CLI.
        
        Args:
            framework (NullHandshake): The framework instance
        """
        super().__init__()
        self.framework = framework
        self.console = framework.console
        
        # Customize intro message
        self.intro = "\n[cyan]Welcome to NullHandshake - Wireless Network Post-Exploitation Framework[/cyan]\n" \
                   + "Type 'help' for a list of commands.\n"
    
    def emptyline(self) -> bool:
        """Handle empty lines."""
        return False
    
    def default(self, line: str) -> bool:
        """Handle unknown commands."""
        self.console.print(f"[red]Unknown command: {line}[/red]")
        self.console.print("Type 'help' for a list of available commands.")
        return False
    
    def do_exit(self, arg: str) -> bool:
        """Exit the program."""
        self.framework.cleanup()
        return True
    
    def do_quit(self, arg: str) -> bool:
        """Exit the program (alias for exit)."""
        return self.do_exit(arg)
    
    def do_banner(self, arg: str) -> None:
        """Display the banner."""
        self.framework.banner()
    
    def do_plugins(self, arg: str) -> None:
        """List available plugins."""
        self.framework.list_plugins()
    
    def do_load(self, arg: str) -> None:
        """
        Load and activate a plugin.
        
        Usage: load <plugin_name>
        """
        arg = arg.strip()
        if not arg:
            self.console.print("[red]Error: Plugin name required[/red]")
            self.console.print("Usage: load <plugin_name>")
            return
        
        self.framework.load_plugin(arg)
    
    def do_unload(self, arg: str) -> None:
        """Unload the active plugin."""
        self.framework.unload_plugin()
    
    def do_reload(self, arg: str) -> None:
        """Reload all plugins."""
        self.framework.reload_plugins()
    
    def do_help(self, arg: str) -> None:
        """
        Show help information.
        
        Usage: help [command/topic]
        """
        if not arg:
            # General help
            framework_commands = [
                ("banner", "Display the NullHandshake banner"),
                ("plugins", "List available plugins"),
                ("load <plugin>", "Load and activate a plugin"),
                ("unload", "Unload the active plugin"),
                ("reload", "Reload all plugins"),
                ("help", "Show this help message"),
                ("config", "View or set configuration options"),
                ("plugin_help", "Show help for the active plugin"),
                ("exit/quit", "Exit NullHandshake")
            ]
            
            # Create help table
            from rich.table import Table
            table = Table(title="NullHandshake Commands")
            table.add_column("Command", style="cyan")
            table.add_column("Description", style="green")
            
            for cmd, desc in framework_commands:
                table.add_row(cmd, desc)
            
            self.console.print(table)
            
            # Show active plugin and its commands
            if self.framework.active_plugin:
                plugin_commands = self.framework.get_plugin_commands()
                if plugin_commands:
                    self.console.print(f"\n[yellow]Active Plugin: {self.framework.active_plugin}[/yellow]")
                    self.console.print("[yellow]Plugin commands (use 'plugin_help' for more details):[/yellow]")
                    
                    for cmd in plugin_commands:
                        self.console.print(f"  [cyan]{cmd}[/cyan]")
                
        else:
            # Help for a specific command
            cmd.Cmd.do_help(self, arg)
    
    def do_config(self, arg: str) -> None:
        """
        View or set configuration options.
        
        Usage: 
          config                    # View all configuration
          config <section>          # View section configuration
          config <section> <key>    # View specific configuration value
          config <section> <key> <value>  # Set configuration value
        """
        args = arg.strip().split()
        config = self.framework.config
        
        if not args:
            # Show all configuration
            self.console.print("[green]Current Configuration:[/green]")
            for section, values in config.items():
                self.console.print(f"[cyan]{section}:[/cyan]")
                for key, value in values.items():
                    self.console.print(f"  {key} = {value}")
                    
        elif len(args) == 1:
            # Show section configuration
            section = args[0]
            if section in config:
                self.console.print(f"[green]Configuration for section '{section}':[/green]")
                for key, value in config[section].items():
                    self.console.print(f"  {key} = {value}")
            else:
                self.console.print(f"[red]Section '{section}' not found[/red]")
                
        elif len(args) == 2:
            # Show specific value
            section, key = args
            if section in config and key in config[section]:
                value = config[section][key]
                self.console.print(f"[green]{section}.{key} = {value}[/green]")
            else:
                self.console.print(f"[red]Configuration value '{section}.{key}' not found[/red]")
                
        elif len(args) >= 3:
            # Set configuration value
            section, key, value = args[0], args[1], ' '.join(args[2:])
            
            # Try to convert string value to appropriate type
            try:
                # Check if the value is a number
                if value.isdigit():
                    value = int(value)
                elif value.replace('.', '', 1).isdigit():
                    value = float(value)
                # Check for boolean
                elif value.lower() in ('true', 'yes', 'on'):
                    value = True
                elif value.lower() in ('false', 'no', 'off'):
                    value = False
            except:
                # Keep as string if conversion fails
                pass
            
            self.framework.config.set(section, key, value)
            self.console.print(f"[green]Set {section}.{key} = {value}[/green]")
    
    def do_plugin_help(self, arg: str) -> None:
        """Show help information for the active plugin."""
        self.framework.show_plugin_help()
    
    def default(self, line: str) -> None:
        """
        Handle commands that aren't recognized as built-in.
        Attempt to pass them to the active plugin.
        """
        if not line.strip():
            return
        
        # Check if we have an active plugin
        if not self.framework.active_plugin:
            self.console.print("[red]No active plugin. Use 'load <plugin_name>' first.[/red]")
            return
        
        # Parse the command and arguments
        parts = line.split()
        command = parts[0]
        args = parts[1:]
        
        # Check if the command exists in the active plugin
        plugin_commands = self.framework.get_plugin_commands()
        if command not in plugin_commands:
            self.console.print(f"[red]Unknown command: {command}[/red]")
            self.console.print("Type 'help' for available commands or 'plugin_help' for plugin commands.")
            return
        
        # Execute the command in the plugin
        try:
            self.framework.execute_plugin_command(command, *args)
        except Exception as e:
            self.console.print(f"[red]Error executing command: {str(e)}[/red]")
            
            # Print traceback in debug mode
            if self.framework.config.get('general', 'debug'):
                self.console.print(Panel(traceback.format_exc(), title="Traceback", border_style="red"))
    
    def completenames(self, text, *ignored) -> List[str]:
        """
        Tab-completion for command names.
        Include built-in commands and plugin commands if a plugin is active.
        """
        commands = super().completenames(text, *ignored)
        
        # Add plugin commands if a plugin is active
        if self.framework.active_plugin:
            plugin_commands = self.framework.get_plugin_commands()
            commands.extend([cmd for cmd in plugin_commands if cmd.startswith(text)])
        
        return commands
    
    def completedefault(self, text, line, begidx, endidx) -> List[str]:
        """Tab-completion for plugin command arguments."""
        # Not implemented yet - would need plugin-specific completion logic
        return []

def parse_arguments() -> argparse.Namespace:
    """
    Parse command-line arguments.
    
    Returns:
        argparse.Namespace: Parsed arguments
    """
    parser = argparse.ArgumentParser(description="NullHandshake - Wireless Network Post-Exploitation Framework")
    parser.add_argument("-c", "--config", help="Path to configuration file")
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("-p", "--plugin", help="Plugin to load on startup")
    
    return parser.parse_args()

def main() -> None:
    """Main entry point for the NullHandshake CLI."""
    # Parse command-line arguments
    args = parse_arguments()
    
    # Initialize the framework
    framework = NullHandshake(debug=args.debug)
    
    # Display the banner
    framework.banner()
    
    # Load specified plugin if provided
    if args.plugin:
        framework.load_plugin(args.plugin)
    
    # Start the CLI
    cli = NullHandshakeCLI(framework)
    
    try:
        cli.cmdloop()
    except KeyboardInterrupt:
        # Handle Ctrl+C gracefully
        print("\n")
        framework.cleanup()
    except Exception as e:
        # Handle other exceptions
        framework.console.print(f"[red]Error: {str(e)}[/red]")
        if args.debug:
            traceback.print_exc()
        framework.cleanup()

if __name__ == "__main__":
    main()
