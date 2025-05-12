#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
NullHandshake - Utility Functions

This module contains utility functions used across the framework.
"""

import os
import subprocess
import platform
import re
import random
import string
import time
import ipaddress
import socket
import logging
from typing import List, Dict, Tuple, Optional, Union, Any

def run_command(command: List[str], timeout: int = 60, shell: bool = False) -> Tuple[int, str, str]:
    """
    Run a system command and return its exit code, stdout, and stderr.
    
    Args:
        command (List[str]): Command as a list of strings
        timeout (int): Timeout in seconds
        shell (bool): Whether to use shell execution
        
    Returns:
        Tuple[int, str, str]: Exit code, stdout, stderr
    """
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=shell,
            universal_newlines=True
        )
        
        stdout, stderr = process.communicate(timeout=timeout)
        return process.returncode, stdout, stderr
        
    except subprocess.TimeoutExpired:
        process.kill()
        return -1, "", "Command timed out"
    except Exception as e:
        return -1, "", f"Error executing command: {str(e)}"

def is_root() -> bool:
    """
    Check if the script is running with root/admin privileges.
    
    Returns:
        bool: True if running as root/admin, False otherwise
    """
    if platform.system() == 'Windows':
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False
    else:
        return os.geteuid() == 0

def check_dependency(binary: str) -> bool:
    """
    Check if a binary dependency is available in the system.
    
    Args:
        binary (str): Name of the binary
        
    Returns:
        bool: True if dependency is available, False otherwise
    """
    try:
        subprocess.check_call(
            ["which", binary] if platform.system() != "Windows" else ["where", binary],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        return True
    except subprocess.CalledProcessError:
        return False

def random_mac() -> str:
    """
    Generate a random MAC address.
    
    Returns:
        str: Random MAC address
    """
    # Generate random hexadecimal values for each byte
    mac = [random.randint(0, 255) for _ in range(6)]
    
    # Ensure the first byte follows MAC address standards
    # Set the locally administered bit and clear the multicast bit
    mac[0] = (mac[0] & 0xFC) | 0x02
    
    # Format as a MAC address string
    return ':'.join([f"{b:02x}" for b in mac])

def is_valid_mac(mac: str) -> bool:
    """
    Check if a string is a valid MAC address.
    
    Args:
        mac (str): MAC address to validate
        
    Returns:
        bool: True if valid, False otherwise
    """
    pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
    return bool(re.match(pattern, mac))

def get_interface_mac(interface: str) -> Optional[str]:
    """
    Get the MAC address of a network interface.
    
    Args:
        interface (str): Network interface name
        
    Returns:
        Optional[str]: MAC address if found, None otherwise
    """
    try:
        if platform.system() == "Linux":
            path = f"/sys/class/net/{interface}/address"
            if os.path.exists(path):
                with open(path, 'r') as f:
                    return f.read().strip()
        
        # For other platforms or if the above method fails
        output = subprocess.check_output(
            ["ifconfig" if platform.system() != "Windows" else "ipconfig", interface],
            stderr=subprocess.STDOUT,
            universal_newlines=True
        )
        
        # Extract MAC address from output
        if platform.system() == "Windows":
            match = re.search(r'Physical Address[\. ]+: ([0-9A-Fa-f-]+)', output)
        else:
            match = re.search(r'ether ([0-9a-f:]+)', output)
            
        if match:
            return match.group(1)
        return None
        
    except (subprocess.CalledProcessError, FileNotFoundError, PermissionError):
        return None

def is_valid_ip(ip: str) -> bool:
    """
    Check if a string is a valid IP address.
    
    Args:
        ip (str): IP address to validate
        
    Returns:
        bool: True if valid, False otherwise
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def get_local_ip() -> str:
    """
    Get the local IP address of the machine.
    
    Returns:
        str: Local IP address
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Doesn't need to be reachable
        s.connect(('10.255.255.255', 1))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip

def get_interfaces() -> List[str]:
    """
    Get a list of available network interfaces.
    
    Returns:
        List[str]: List of interface names
    """
    if platform.system() == "Linux":
        return [
            d for d in os.listdir('/sys/class/net/') 
            if os.path.isdir(os.path.join('/sys/class/net/', d))
        ]
    elif platform.system() == "Darwin":  # macOS
        output = subprocess.check_output(["ifconfig"], universal_newlines=True)
        return re.findall(r'^([a-zA-Z0-9]+):', output, re.MULTILINE)
    elif platform.system() == "Windows":
        output = subprocess.check_output(["ipconfig"], universal_newlines=True)
        # Windows interface names are more complex, this is a simplified approach
        return re.findall(r'Ethernet adapter ([^:]+):', output) + \
               re.findall(r'Wireless LAN adapter ([^:]+):', output)
    else:
        return []

def is_wireless_interface(interface: str) -> bool:
    """
    Check if a network interface is wireless.
    
    Args:
        interface (str): Network interface name
        
    Returns:
        bool: True if wireless, False otherwise
    """
    if platform.system() == "Linux":
        return os.path.exists(f"/sys/class/net/{interface}/wireless") or \
               os.path.exists(f"/sys/class/net/{interface}/phy80211")
    elif platform.system() == "Darwin":  # macOS
        try:
            output = subprocess.check_output(
                ["networksetup", "-listallhardwareports"],
                universal_newlines=True
            )
            wifi_devices = re.findall(r'Hardware Port: (Wi-Fi|AirPort)[\s\S]+?Device: (\w+)', output)
            return any(interface == device for _, device in wifi_devices)
        except subprocess.CalledProcessError:
            return False
    elif platform.system() == "Windows":
        try:
            output = subprocess.check_output(
                ["netsh", "wlan", "show", "interfaces"],
                universal_newlines=True
            )
            return interface in output
        except subprocess.CalledProcessError:
            return False
    else:
        return False

def generate_random_password(length: int = 12) -> str:
    """
    Generate a random password.
    
    Args:
        length (int): Length of the password
        
    Returns:
        str: Random password
    """
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(chars) for _ in range(length))

def human_readable_size(size_bytes: int) -> str:
    """
    Convert a size in bytes to a human-readable string.
    
    Args:
        size_bytes (int): Size in bytes
        
    Returns:
        str: Human-readable size
    """
    if size_bytes == 0:
        return "0B"
    
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    i = 0
    while size_bytes >= 1024 and i < len(units)-1:
        size_bytes /= 1024.0
        i += 1
        
    return f"{size_bytes:.2f}{units[i]}"

def sanitize_filename(filename: str) -> str:
    """
    Sanitize a filename to ensure it's safe for the filesystem.
    
    Args:
        filename (str): Filename to sanitize
        
    Returns:
        str: Sanitized filename
    """
    # Replace invalid characters with underscores
    invalid_chars = r'[<>:"/\\|?*]'
    return re.sub(invalid_chars, '_', filename)

def parse_mac_vendor(mac: str) -> Optional[str]:
    """
    Get the vendor of a device based on its MAC address.
    This is a simple implementation that doesn't rely on external APIs.
    
    Args:
        mac (str): MAC address
        
    Returns:
        Optional[str]: Vendor name if found, None otherwise
    """
    # This would normally use a MAC vendor database
    # For simplicity, we'll return None
    return None
