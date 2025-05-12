#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
NullHandshake - Credential Harvester Plugin

This plugin provides functionality to extract stored WiFi credentials
from various operating systems.
"""

import os
import platform
import subprocess
import re
import base64
import binascii
import xml.etree.ElementTree as ET
from typing import Dict, List, Any, Tuple, Optional
from rich.table import Table

from core.plugin_manager import PluginInterface
from core.utils import run_command, is_root, sanitize_filename

class CredentialHarvester(PluginInterface):
    """Credential harvester plugin for extracting stored WiFi credentials."""
    
    def __init__(self, framework):
        """
        Initialize the credential harvester plugin.
        
        Args:
            framework: The NullHandshake framework instance
        """
        super().__init__(framework)
        self.name = "credential_harvester"
        self.description = "Extract stored WiFi credentials from various operating systems"
        
        # Mapping of OS to credential extraction method
        self.extractors = {
            'Windows': self._extract_windows_credentials,
            'Darwin': self._extract_macos_credentials,
            'Linux': self._extract_linux_credentials
        }
        
        # Storage for extracted credentials
        self.credentials = []
        
        self.logger.info("Credential harvester plugin initialized")
    
    def extract_credentials(self) -> bool:
        """
        Extract WiFi credentials from the current operating system.
        
        Returns:
            bool: True if credentials were extracted, False otherwise
        """
        system = platform.system()
        
        if system not in self.extractors:
            self.console.print(f"[red]Unsupported operating system: {system}[/red]")
            return False
        
        if not is_root() and system != 'Windows':  # Windows can work without admin for some operations
            self.console.print("[red]Root/Administrator privileges required to extract credentials[/red]")
            return False
        
        self.console.print(f"[green]Extracting credentials from {system}...[/green]")
        
        # Clear previous credentials
        self.credentials = []
        
        # Call the appropriate extractor
        success = self.extractors[system]()
        
        if success:
            self.console.print(f"[green]Successfully extracted {len(self.credentials)} WiFi credentials[/green]")
            return True
        else:
            self.console.print("[red]Failed to extract WiFi credentials[/red]")
            return False
    
    def show_credentials(self) -> None:
        """
        Display extracted credentials.
        """
        if not self.credentials:
            self.console.print("[yellow]No credentials extracted yet[/yellow]")
            return
        
        # Create a formatted table
        table = Table(title="Extracted WiFi Credentials")
        table.add_column("#", style="dim", width=4)
        table.add_column("SSID", style="cyan")
        table.add_column("Password", style="green")
        table.add_column("Security", style="yellow")
        table.add_column("Source", style="blue")
        
        for idx, cred in enumerate(self.credentials, 1):
            table.add_row(
                str(idx),
                cred.get('ssid', 'N/A'),
                cred.get('password', 'N/A'),
                cred.get('security_type', 'N/A'),
                cred.get('source', 'N/A')
            )
        
        # Print the table
        self.console.print(table)
    
    def save_credentials(self, filename: str = None) -> bool:
        """
        Save extracted credentials to a file.
        
        Args:
            filename (str, optional): Output filename
            
        Returns:
            bool: True if credentials were saved successfully, False otherwise
        """
        if not self.credentials:
            self.console.print("[yellow]No credentials to save[/yellow]")
            return False
        
        if not filename:
            system = platform.system().lower()
            filename = f"wifi_credentials_{system}.txt"
        
        # Create data directory if it doesn't exist
        data_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data')
        os.makedirs(data_dir, exist_ok=True)
        
        # Full path to output file
        output_file = os.path.join(data_dir, sanitize_filename(filename))
        
        try:
            with open(output_file, 'w') as f:
                f.write("===== WiFi Credentials =====\n\n")
                
                for cred in self.credentials:
                    f.write(f"SSID: {cred.get('ssid', 'N/A')}\n")
                    f.write(f"Password: {cred.get('password', 'N/A')}\n")
                    f.write(f"Security Type: {cred.get('security_type', 'N/A')}\n")
                    f.write(f"Source: {cred.get('source', 'N/A')}\n")
                    f.write("\n")
            
            self.console.print(f"[green]Credentials saved to: {output_file}[/green]")
            return True
            
        except Exception as e:
            self.logger.error(f"Error saving credentials: {str(e)}")
            self.console.print(f"[red]Error saving credentials: {str(e)}[/red]")
            return False
    
    def _extract_windows_credentials(self) -> bool:
        """
        Extract WiFi credentials from Windows.
        
        Returns:
            bool: True if extraction was successful, False otherwise
        """
        try:
            # Get list of profiles
            rc, stdout, stderr = run_command(["netsh", "wlan", "show", "profiles"])
            
            if rc != 0:
                self.logger.error(f"Failed to list profiles: {stderr}")
                return False
            
            # Extract profile names
            profile_names = []
            for line in stdout.split('\n'):
                if "All User Profile" in line:
                    profile = line.split(":")[-1].strip()
                    profile_names.append(profile)
            
            if not profile_names:
                self.logger.info("No WiFi profiles found")
                return True
            
            # Process each profile
            for profile in profile_names:
                try:
                    # Get profile details including the password
                    rc, stdout, stderr = run_command(
                        ["netsh", "wlan", "show", "profile", profile, "key=clear"]
                    )
                    
                    if rc != 0:
                        self.logger.error(f"Failed to get profile {profile}: {stderr}")
                        continue
                    
                    # Extract password and security type
                    password = None
                    security_type = None
                    
                    for line in stdout.split('\n'):
                        if "Key Content" in line:
                            password = line.split(":")[-1].strip()
                        elif "Authentication" in line:
                            security_type = line.split(":")[-1].strip()
                    
                    # Add to credentials list
                    self.credentials.append({
                        'ssid': profile,
                        'password': password if password else "<not-found>",
                        'security_type': security_type if security_type else "Unknown",
                        'source': "Windows WiFi Profile"
                    })
                    
                except Exception as e:
                    self.logger.error(f"Error processing profile {profile}: {str(e)}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error extracting Windows credentials: {str(e)}")
            return False
    
    def _extract_macos_credentials(self) -> bool:
        """
        Extract WiFi credentials from macOS.
        
        Returns:
            bool: True if extraction was successful, False otherwise
        """
        try:
            # Check if security command is available
            rc, _, _ = run_command(["which", "security"])
            if rc != 0:
                self.logger.error("security command not found")
                return False
            
            # Get the list of WiFi SSIDs
            rc, stdout, stderr = run_command(
                ["networksetup", "-listallhardwareports"]
            )
            
            if rc != 0:
                self.logger.error(f"Failed to list hardware ports: {stderr}")
                return False
            
            # Find WiFi interface
            wifi_device = None
            for line in stdout.split('\n'):
                if "Wi-Fi" in line or "AirPort" in line:
                    # Get the device name from the next line
                    device_index = stdout.split('\n').index(line) + 1
                    if device_index < len(stdout.split('\n')):
                        device_line = stdout.split('\n')[device_index]
                        if "Device" in device_line:
                            wifi_device = device_line.split(":")[-1].strip()
                            break
            
            if not wifi_device:
                self.logger.error("WiFi interface not found")
                return False
            
            # Get preferred wireless networks
            rc, stdout, stderr = run_command(
                ["networksetup", "-listpreferredwirelessnetworks", wifi_device]
            )
            
            if rc != 0:
                self.logger.error(f"Failed to list preferred networks: {stderr}")
                return False
            
            # Extract SSIDs
            ssids = []
            for line in stdout.split('\n'):
                if line.strip() and "Preferred networks" not in line:
                    ssid = line.strip()
                    ssids.append(ssid)
            
            if not ssids:
                self.logger.info("No WiFi networks found")
                return True
            
            # Try to extract passwords from keychain
            for ssid in ssids:
                try:
                    # Attempt to extract password from keychain
                    rc, stdout, stderr = run_command([
                        "security", "find-generic-password", 
                        "-D", "AirPort network password", 
                        "-a", ssid, "-w"
                    ])
                    
                    password = stdout.strip() if rc == 0 else "<not-found>"
                    
                    # Try to get security type
                    rc, stdout, stderr = run_command([
                        "networksetup", "-getairportnetwork", wifi_device
                    ])
                    
                    security_type = "Unknown"
                    if rc == 0 and ssid in stdout:
                        # Unfortunately, networksetup doesn't show security type
                        # Could use airport command, but it requires elevated privileges
                        security_type = "WPA/WPA2 (assumed)"
                    
                    # Add to credentials list
                    self.credentials.append({
                        'ssid': ssid,
                        'password': password,
                        'security_type': security_type,
                        'source': "macOS Keychain"
                    })
                    
                except Exception as e:
                    self.logger.error(f"Error extracting password for {ssid}: {str(e)}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error extracting macOS credentials: {str(e)}")
            return False
    
    def _extract_linux_credentials(self) -> bool:
        """
        Extract WiFi credentials from Linux.
        
        Returns:
            bool: True if extraction was successful, False otherwise
        """
        try:
            # Check for common network manager locations
            if self._extract_networkmanager_credentials():
                return True
            
            if self._extract_wpa_supplicant_credentials():
                return True
            
            # If we get here, no credentials were found
            self.logger.warning("No WiFi credentials found in common locations")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error extracting Linux credentials: {str(e)}")
            return False
    
    def _extract_networkmanager_credentials(self) -> bool:
        """
        Extract credentials from NetworkManager.
        
        Returns:
            bool: True if credentials were found, False otherwise
        """
        # Common NetworkManager config directories
        nm_paths = [
            "/etc/NetworkManager/system-connections/",
            "/var/lib/NetworkManager/"
        ]
        
        found_any = False
        
        for path in nm_paths:
            if not os.path.exists(path):
                continue
            
            # Look for connection files
            try:
                files = os.listdir(path)
                
                for filename in files:
                    if filename.endswith(".nmconnection") or "." not in filename:
                        # This is likely a connection file
                        file_path = os.path.join(path, filename)
                        
                        try:
                            # Read the file if we have permission
                            with open(file_path, 'r') as f:
                                content = f.read()
                                
                                # Extract SSID, password and security type
                                ssid = None
                                password = None
                                security_type = None
                                
                                for line in content.split('\n'):
                                    line = line.strip()
                                    if line.startswith("ssid="):
                                        ssid = line.split("=", 1)[1].strip()
                                    elif line.startswith("psk="):
                                        password = line.split("=", 1)[1].strip()
                                    elif line.startswith("key-mgmt="):
                                        security_type = line.split("=", 1)[1].strip()
                                
                                if ssid and password:
                                    # Add to credentials list
                                    self.credentials.append({
                                        'ssid': ssid,
                                        'password': password,
                                        'security_type': security_type if security_type else "Unknown",
                                        'source': f"NetworkManager ({file_path})"
                                    })
                                    found_any = True
                                    
                        except Exception as e:
                            self.logger.error(f"Error reading file {file_path}: {str(e)}")
            
            except Exception as e:
                self.logger.error(f"Error listing files in {path}: {str(e)}")
        
        return found_any
    
    def _extract_wpa_supplicant_credentials(self) -> bool:
        """
        Extract credentials from wpa_supplicant configuration.
        
        Returns:
            bool: True if credentials were found, False otherwise
        """
        # Common wpa_supplicant config locations
        wpa_paths = [
            "/etc/wpa_supplicant/wpa_supplicant.conf",
            "/etc/wpa_supplicant.conf"
        ]
        
        found_any = False
        
        for path in wpa_paths:
            if not os.path.exists(path):
                continue
            
            try:
                # Read the file if we have permission
                with open(path, 'r') as f:
                    content = f.read()
                    
                    # Extract network blocks
                    network_blocks = re.findall(r'network\s*=\s*{(.*?)}', content, re.DOTALL)
                    
                    for block in network_blocks:
                        # Extract SSID, password and security type
                        ssid = None
                        password = None
                        security_type = "WPA/WPA2"  # Assume WPA by default
                        
                        ssid_match = re.search(r'ssid\s*=\s*"([^"]*)"', block)
                        if ssid_match:
                            ssid = ssid_match.group(1)
                        
                        # Check for PSK (pre-shared key)
                        psk_match = re.search(r'psk\s*=\s*"([^"]*)"', block)
                        if psk_match:
                            password = psk_match.group(1)
                        
                        # Check for WEP key
                        wep_match = re.search(r'wep_key\d\s*=\s*"?([^"]*)"?', block)
                        if wep_match:
                            password = wep_match.group(1)
                            security_type = "WEP"
                        
                        # Check for key_mgmt
                        key_mgmt_match = re.search(r'key_mgmt\s*=\s*([^\s]*)', block)
                        if key_mgmt_match:
                            key_mgmt = key_mgmt_match.group(1)
                            if key_mgmt == "NONE":
                                security_type = "None"
                            elif key_mgmt == "WPA-EAP":
                                security_type = "WPA-Enterprise"
                                # Enterprise authentication, look for creds
                                identity_match = re.search(r'identity\s*=\s*"([^"]*)"', block)
                                password_match = re.search(r'password\s*=\s*"([^"]*)"', block)
                                
                                if identity_match and password_match:
                                    password = f"Identity: {identity_match.group(1)}, Password: {password_match.group(1)}"
                        
                        if ssid:
                            # Add to credentials list
                            self.credentials.append({
                                'ssid': ssid,
                                'password': password if password else "<not-found>",
                                'security_type': security_type,
                                'source': f"wpa_supplicant ({path})"
                            })
                            found_any = True
                        
            except Exception as e:
                self.logger.error(f"Error reading file {path}: {str(e)}")
        
        return found_any
    
    def cleanup(self) -> None:
        """
        Clean up resources before unloading the plugin.
        """
        # Clear credentials
        self.credentials = []
        
        self.logger.info("Credential harvester plugin cleaned up")
