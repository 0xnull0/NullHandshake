#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
NullHandshake - Configuration Manager

This module handles the configuration settings for the framework.
"""

import os
import json
import logging
from typing import Dict, Any, Optional

class Config:
    """Manages configuration settings for the framework."""
    
    def __init__(self, config_file: str = None):
        """
        Initialize the configuration manager.
        
        Args:
            config_file (str, optional): Path to the configuration file
        """
        # Default configuration file
        if config_file is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            config_file = os.path.join(base_dir, 'config.json')
            
        self.config_file = config_file
        self.config = self._load_default_config()
        
        # Load configuration from file if it exists
        if os.path.exists(config_file):
            self._load_config()
        else:
            # Save default configuration
            self._save_config()
    
    def _load_default_config(self) -> Dict[str, Any]:
        """
        Load default configuration settings.
        
        Returns:
            Dict[str, Any]: Default configuration
        """
        return {
            'general': {
                'debug': False,
                'log_level': 'INFO',
                'data_dir': os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data'),
            },
            'wifi': {
                'default_interface': '',
                'channel_hop_interval': 1.0,
            },
            'evil_twin': {
                'phishing_port': 5000,
                'dns_port': 53,
                'gateway_ip': '10.0.0.1',
                'subnet_mask': '255.255.255.0',
                'dhcp_range': '10.0.0.10,10.0.0.50,12h',
            },
            'wpa_handshake': {
                'pcap_dir': 'captures',
                'hashcat_path': '',
                'wordlist_path': '',
            },
            'plugins': {
                'enabled': [],
                'autoload': [],
            }
        }
    
    def _load_config(self) -> None:
        """Load configuration from file."""
        try:
            with open(self.config_file, 'r') as f:
                loaded_config = json.load(f)
                
            # Update the default config with loaded values
            self._update_dict(self.config, loaded_config)
            
        except Exception as e:
            logging.error(f"Error loading configuration: {str(e)}")
    
    def _save_config(self) -> None:
        """Save configuration to file."""
        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(self.config_file), exist_ok=True)
            
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=4)
                
        except Exception as e:
            logging.error(f"Error saving configuration: {str(e)}")
    
    def _update_dict(self, target: Dict[str, Any], source: Dict[str, Any]) -> None:
        """
        Update a nested dictionary with values from another dictionary.
        
        Args:
            target (Dict[str, Any]): Target dictionary to update
            source (Dict[str, Any]): Source dictionary with values to use
        """
        for key, value in source.items():
            if key in target and isinstance(target[key], dict) and isinstance(value, dict):
                self._update_dict(target[key], value)
            else:
                target[key] = value
    
    def get(self, section: str, key: str, default: Any = None) -> Any:
        """
        Get a configuration value.
        
        Args:
            section (str): Configuration section
            key (str): Configuration key
            default (Any, optional): Default value if not found
            
        Returns:
            Any: Configuration value
        """
        try:
            return self.config[section][key]
        except KeyError:
            return default
    
    def set(self, section: str, key: str, value: Any) -> None:
        """
        Set a configuration value.
        
        Args:
            section (str): Configuration section
            key (str): Configuration key
            value (Any): Configuration value
        """
        # Create section if it doesn't exist
        if section not in self.config:
            self.config[section] = {}
            
        self.config[section][key] = value
        self._save_config()
    
    def get_section(self, section: str) -> Dict[str, Any]:
        """
        Get an entire configuration section.
        
        Args:
            section (str): Configuration section
            
        Returns:
            Dict[str, Any]: Section configuration
        """
        return self.config.get(section, {})
    
    def set_section(self, section: str, values: Dict[str, Any]) -> None:
        """
        Set an entire configuration section.
        
        Args:
            section (str): Configuration section
            values (Dict[str, Any]): Section configuration
        """
        self.config[section] = values
        self._save_config()
