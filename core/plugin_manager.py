#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
NullHandshake - Plugin Manager

This module handles the discovery, loading, and management of plugins for the framework.
"""

import os
import sys
import importlib
import inspect
import logging
from typing import Dict, Any, List, Optional, Type

class PluginInterface:
    """Base interface that all plugins must implement."""
    
    def __init__(self, framework):
        """
        Initialize the plugin with a reference to the framework.
        
        Args:
            framework: The NullHandshake framework instance
        """
        self.framework = framework
        self.logger = framework.logger
        self.console = framework.console
        self.description = "Base plugin interface. Should be overridden."
        
    def cleanup(self) -> None:
        """
        Cleanup resources before unloading the plugin.
        This method should be overridden by plugins.
        """
        pass

class PluginManager:
    """Manages discovery, loading, and unloading of plugins."""
    
    def __init__(self, framework):
        """
        Initialize the plugin manager.
        
        Args:
            framework: The NullHandshake framework instance
        """
        self.framework = framework
        self.logger = framework.logger
        self.plugins = {}  # Store loaded plugin instances
        self.plugin_modules = {}  # Store references to loaded modules
        
        # Path to the plugins directory
        self.plugins_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
            'plugins'
        )
        
        # Discover available plugins
        self.discover_plugins()
        
    def discover_plugins(self) -> None:
        """Discover available plugins in the plugins directory."""
        self.logger.info("Discovering plugins...")
        
        # Clear existing plugins
        self.plugins = {}
        self.plugin_modules = {}
        
        # Ensure plugins directory exists in Python path
        if self.plugins_dir not in sys.path:
            sys.path.insert(0, os.path.dirname(self.plugins_dir))
        
        # Get list of potential plugin files - specifically looking for *_plugin.py files
        plugin_files = [
            f for f in os.listdir(self.plugins_dir) 
            if f.endswith('_plugin.py') and not f.startswith('_')
        ]
        
        # Directories that might contain plugins (excluding __pycache__ and similar)
        plugin_dirs = [
            d for d in os.listdir(self.plugins_dir)
            if os.path.isdir(os.path.join(self.plugins_dir, d)) and not d.startswith('_')
        ]
        
        # First load the __init__.py file from the plugins package
        try:
            import plugins
            importlib.reload(plugins)
            self.logger.debug("Loaded plugins package")
        except Exception as e:
            self.logger.error(f"Error loading plugins package: {str(e)}")
        
        # Load all plugin modules
        for filename in plugin_files:
            try:
                module_name = filename[:-3]  # Remove .py extension
                self._load_plugin_module('plugins.' + module_name)
            except Exception as e:
                self.logger.error(f"Error discovering plugin {filename}: {str(e)}")
        
        # Load plugin directories
        for dirname in plugin_dirs:
            # Check if there's an __init__.py file
            init_path = os.path.join(self.plugins_dir, dirname, '__init__.py')
            if os.path.exists(init_path):
                try:
                    self._load_plugin_module(f'plugins.{dirname}')
                except Exception as e:
                    self.logger.error(f"Error discovering plugin package {dirname}: {str(e)}")
        
        self.logger.info(f"Discovered {len(self.plugin_modules)} plugins")
    
    def _load_plugin_module(self, module_path: str) -> None:
        """
        Load a plugin module and register any plugins it contains.
        
        Args:
            module_path (str): Import path of the module
        """
        try:
            # Import the module
            module = importlib.import_module(module_path)
            
            # Reload the module to ensure we have the latest version
            module = importlib.reload(module)
            
            # Find plugin classes in the module
            for name, obj in inspect.getmembers(module):
                # Look for classes that inherit from PluginInterface
                if (inspect.isclass(obj) and 
                    issubclass(obj, PluginInterface) and 
                    obj is not PluginInterface):
                    
                    # Extract the plugin name (use class name as default)
                    plugin_name = getattr(obj, 'name', name.lower())
                    
                    # Store the plugin class
                    self.plugin_modules[plugin_name] = {
                        'module': module,
                        'class': obj
                    }
                    self.logger.debug(f"Registered plugin: {plugin_name}")
        
        except ImportError as e:
            self.logger.error(f"Failed to import plugin module {module_path}: {str(e)}")
        except Exception as e:
            self.logger.error(f"Error loading plugin module {module_path}: {str(e)}")
    
    def load_plugin(self, plugin_name: str) -> bool:
        """
        Load and initialize a plugin.
        
        Args:
            plugin_name (str): Name of the plugin to load
            
        Returns:
            bool: True if plugin loaded successfully, False otherwise
        """
        if plugin_name in self.plugins:
            self.logger.debug(f"Plugin {plugin_name} is already loaded")
            return True
            
        if plugin_name not in self.plugin_modules:
            self.logger.error(f"Plugin {plugin_name} not found")
            return False
            
        try:
            # Get the plugin class
            plugin_class = self.plugin_modules[plugin_name]['class']
            
            # Initialize the plugin
            plugin_instance = plugin_class(self.framework)
            
            # Store the plugin instance
            self.plugins[plugin_name] = plugin_instance
            
            self.logger.info(f"Loaded plugin: {plugin_name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error loading plugin {plugin_name}: {str(e)}")
            return False
    
    def unload_plugin(self, plugin_name: str) -> bool:
        """
        Unload a plugin.
        
        Args:
            plugin_name (str): Name of the plugin to unload
            
        Returns:
            bool: True if plugin unloaded successfully, False otherwise
        """
        if plugin_name not in self.plugins:
            self.logger.debug(f"Plugin {plugin_name} is not loaded")
            return False
            
        try:
            # Get the plugin instance
            plugin = self.plugins[plugin_name]
            
            # Call cleanup method
            plugin.cleanup()
            
            # Remove the plugin
            del self.plugins[plugin_name]
            
            self.logger.info(f"Unloaded plugin: {plugin_name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error unloading plugin {plugin_name}: {str(e)}")
            return False
    
    def get_plugin(self, plugin_name: str) -> Optional[Any]:
        """
        Get a loaded plugin instance.
        
        Args:
            plugin_name (str): Name of the plugin
            
        Returns:
            Optional[Any]: Plugin instance if loaded, None otherwise
        """
        return self.plugins.get(plugin_name)
    
    def get_all_plugins(self) -> Dict[str, Any]:
        """
        Get all loaded plugin instances.
        
        Returns:
            Dict[str, Any]: Dictionary of plugin names to instances
        """
        return self.plugins
