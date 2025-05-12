#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
NullHandshake - Core Framework

This module provides the core functionality for the NullHandshake framework,
including plugin management and command execution.
"""

import os
import sys
import logging
from typing import Dict, Any, List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.plugin_manager import PluginManager
from core.logger import setup_logger

class NullHandshake:
    """Main framework class that orchestrates all operations."""
    
    def __init__(self, debug: bool = False):
        """
        Initialize the NullHandshake framework.
        
        Args:
            debug (bool): Enable debug mode if True
        """
        # Set up logging
        self.logger = setup_logger(debug)
        self.logger.info("Initializing NullHandshake framework")
        
        # Rich console for pretty output
        self.console = Console()
        
        # Initialize plugin manager
        self.plugin_manager = PluginManager(self)
        
        # Keep track of the active plugin
        self.active_plugin = None
        
        # Framework configuration
        self.config = {
            'debug': debug,
            'data_dir': os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data'),
        }
        
        # Create data directory if it doesn't exist
        if not os.path.exists(self.config['data_dir']):
            os.makedirs(self.config['data_dir'])

    def banner(self) -> None:
        """Display the NullHandshake banner."""
        banner_text = """
        ███╗   ██╗██╗   ██╗██╗     ██╗     ██╗  ██╗ █████╗ ███╗   ██╗██████╗ ███████╗██╗  ██╗ █████╗ ██╗  ██╗███████╗
        ████╗  ██║██║   ██║██║     ██║     ██║  ██║██╔══██╗████╗  ██║██╔══██╗██╔════╝██║  ██║██╔══██╗██║ ██╔╝██╔════╝
        ██╔██╗ ██║██║   ██║██║     ██║     ███████║███████║██╔██╗ ██║██║  ██║███████╗███████║███████║█████╔╝ █████╗  
        ██║╚██╗██║██║   ██║██║     ██║     ██╔══██║██╔══██║██║╚██╗██║██║  ██║╚════██║██╔══██║██╔══██║██╔═██╗ ██╔══╝  
        ██║ ╚████║╚██████╔╝███████╗███████╗██║  ██║██║  ██║██║ ╚████║██████╔╝███████║██║  ██║██║  ██║██║  ██╗███████╗
        ╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝
                                                                                                       v0.1.0
        [Wireless Network Post-Exploitation Framework]
        """
        self.console.print(Panel(banner_text, border_style="cyan"))
        self.console.print("\n[bold red]⚠ DISCLAIMER: Use only for authorized security assessments![/bold red]\n")

    def list_plugins(self) -> None:
        """Display a list of available plugins."""
        # Get plugin modules (available plugins) rather than loaded plugin instances
        plugin_modules = self.plugin_manager.plugin_modules
        
        if not plugin_modules:
            self.console.print("[yellow]No plugins discovered![/yellow]")
            return
            
        # Get currently loaded plugins
        loaded_plugins = self.plugin_manager.get_all_plugins()
            
        table = Table(title="Available Plugins", show_lines=True)
        table.add_column("Name", style="cyan")
        table.add_column("Description", style="green")
        table.add_column("Status", style="yellow")
        
        for name, plugin_info in plugin_modules.items():
            # Get plugin class to extract description
            plugin_class = plugin_info.get('class')
            # Get description from class docstring or default
            description = getattr(plugin_class, '__doc__', "No description available").strip()
            # Determine status
            if self.active_plugin == name:
                status = "[bright_green]Active[/bright_green]"
            elif name in loaded_plugins:
                status = "[green]Loaded[/green]"
            else:
                status = "[yellow]Available[/yellow]"
                
            table.add_row(name, description, status)
            
        self.console.print(table)

    def load_plugin(self, plugin_name: str) -> bool:
        """
        Load and activate a plugin.
        
        Args:
            plugin_name (str): Name of the plugin to load
            
        Returns:
            bool: True if plugin was loaded successfully, False otherwise
        """
        success = self.plugin_manager.load_plugin(plugin_name)
        if success:
            self.active_plugin = plugin_name
            self.logger.info(f"Activated plugin: {plugin_name}")
            self.console.print(f"[green]Plugin '{plugin_name}' activated successfully[/green]")
            return True
        else:
            self.console.print(f"[red]Failed to load plugin '{plugin_name}'[/red]")
            return False

    def unload_plugin(self) -> None:
        """Unload the currently active plugin."""
        if self.active_plugin:
            plugin_name = self.active_plugin
            self.plugin_manager.unload_plugin(plugin_name)
            self.active_plugin = None
            self.logger.info(f"Unloaded plugin: {plugin_name}")
            self.console.print(f"[yellow]Plugin '{plugin_name}' unloaded[/yellow]")
        else:
            self.console.print("[yellow]No active plugin to unload[/yellow]")

    def reload_plugins(self) -> None:
        """Reload all plugins."""
        self.plugin_manager.discover_plugins()
        self.logger.info("Reloaded all plugins")
        self.console.print("[green]All plugins reloaded[/green]")

    def execute_plugin_command(self, command: str, *args: Any, **kwargs: Any) -> Any:
        """
        Execute a command on the currently active plugin.
        
        Args:
            command (str): Command to execute
            *args: Positional arguments to pass to the command
            **kwargs: Keyword arguments to pass to the command
            
        Returns:
            Any: Result of the command execution
        """
        if not self.active_plugin:
            self.console.print("[red]No active plugin. Use 'load <plugin_name>' first.[/red]")
            return False
            
        plugin = self.plugin_manager.get_plugin(self.active_plugin)
        if not plugin:
            self.console.print("[red]Active plugin not found. Try reloading plugins.[/red]")
            return False
            
        if not hasattr(plugin, command):
            self.console.print(f"[red]Command '{command}' not found in plugin '{self.active_plugin}'[/red]")
            return False
            
        try:
            self.logger.debug(f"Executing command '{command}' with args: {args}, kwargs: {kwargs}")
            result = getattr(plugin, command)(*args, **kwargs)
            return result
        except Exception as e:
            self.logger.error(f"Error executing command '{command}': {str(e)}")
            self.console.print(f"[red]Error executing command: {str(e)}[/red]")
            return False

    def get_plugin_commands(self) -> List[str]:
        """
        Get the list of commands available in the active plugin.
        
        Returns:
            List[str]: List of command names
        """
        if not self.active_plugin:
            return []
            
        plugin = self.plugin_manager.get_plugin(self.active_plugin)
        if not plugin:
            return []
            
        # Filter out built-in methods and private methods
        commands = [
            attr for attr in dir(plugin) 
            if callable(getattr(plugin, attr)) and not attr.startswith('_')
        ]
        
        return commands

    def show_plugin_help(self) -> None:
        """Display help information for the active plugin."""
        if not self.active_plugin:
            self.console.print("[yellow]No active plugin. Use 'load <plugin_name>' first.[/yellow]")
            return
            
        plugin = self.plugin_manager.get_plugin(self.active_plugin)
        if not plugin:
            self.console.print("[red]Active plugin not found. Try reloading plugins.[/red]")
            return
            
        # Get plugin description and commands
        description = getattr(plugin, 'description', 'No description available')
        commands = self.get_plugin_commands()
        
        # Create help table
        table = Table(title=f"Help for plugin: {self.active_plugin}", show_lines=True)
        table.add_column("Command", style="cyan")
        table.add_column("Description", style="green")
        
        for cmd in commands:
            # Get the docstring of the command
            func = getattr(plugin, cmd)
            doc = func.__doc__ or "No description available"
            # Clean up the docstring
            doc = ' '.join([line.strip() for line in doc.split('\n')])
            table.add_row(cmd, doc)
            
        self.console.print(Panel(description, title="Description", border_style="green"))
        self.console.print(table)

    def cleanup(self) -> None:
        """Perform cleanup before exiting."""
        if self.active_plugin:
            self.unload_plugin()
        self.logger.info("NullHandshake framework shutting down")
        self.console.print("[yellow]Cleaning up and exiting...[/yellow]")
