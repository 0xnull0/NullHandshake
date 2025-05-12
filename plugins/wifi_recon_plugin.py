#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
NullHandshake - WiFi Reconnaissance Plugin

This plugin provides functionality for scanning and analyzing WiFi networks.
"""

import os
import time
import threading
import subprocess
import platform
import signal
from typing import Dict, List, Any, Set, Optional, Tuple
from datetime import datetime

from scapy.all import (
    Dot11, Dot11Beacon, Dot11ProbeResp, Dot11ProbeReq, 
    Dot11Elt, RadioTap, sniff, conf
)

from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.console import Console

from core.plugin_manager import PluginInterface
from core.utils import is_wireless_interface, is_root, run_command, parse_mac_vendor

class WiFiRecon(PluginInterface):
    """WiFi reconnaissance plugin for scanning and analyzing wireless networks."""
    
    def __init__(self, framework):
        """
        Initialize the WiFi reconnaissance plugin.
        
        Args:
            framework: The NullHandshake framework instance
        """
        super().__init__(framework)
        self.name = "wifi_recon"
        self.description = "WiFi reconnaissance plugin for scanning and analyzing wireless networks"
        
        # Networks and clients storage
        self.networks = {}  # BSSID -> network info
        self.clients = {}   # Client MAC -> client info
        self.probes = {}    # MAC -> list of SSIDs
        
        # Scanning state
        self.scanning = False
        self.channel_hopping = False
        self.current_channel = 1
        self.interface = None
        self.scanner_thread = None
        self.channel_hopper_thread = None
        self.scan_start_time = None
        
        # Monitor mode state
        self.original_interface_state = None
        
        self.logger.info("WiFi reconnaissance plugin initialized")
    
    def list_interfaces(self) -> List[str]:
        """
        List available wireless interfaces.
        
        Returns:
            List[str]: List of wireless interface names
        """
        from core.utils import get_interfaces
        
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
        Set the wireless interface to use for scanning.
        
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
    
    def enable_monitor_mode(self) -> bool:
        """
        Enable monitor mode on the wireless interface.
        
        Returns:
            bool: True if monitor mode was enabled successfully, False otherwise
        """
        if not self.interface:
            self.console.print("[red]Error: No interface selected. Use set_interface first.[/red]")
            return False
        
        if not is_root():
            self.console.print("[red]Error: Root privileges required to enable monitor mode[/red]")
            return False
        
        system = platform.system()
        
        # Save original interface state for restoration later
        self.original_interface_state = self._get_interface_state()
        
        try:
            if system == "Linux":
                # Linux method using airmon-ng or iw
                if self._check_airmon_ng():
                    # Try to kill processes that might interfere
                    run_command(["airmon-ng", "check", "kill"])
                    
                    # Enable monitor mode with airmon-ng
                    rc, stdout, stderr = run_command(["airmon-ng", "start", self.interface])
                    
                    if rc != 0:
                        self.logger.error(f"airmon-ng failed: {stderr}")
                        # Try alternate method with iw
                        return self._enable_monitor_with_iw()
                    
                    # airmon-ng might have created a new interface name
                    # Try to extract it from the output
                    if "monitor mode enabled" in stdout or "monitor mode vif enabled" in stdout:
                        # Check if a new interface was created (e.g., wlan0mon)
                        mon_iface = self.interface + "mon"
                        alt_mon_iface = "mon" + self.interface
                        
                        from core.utils import get_interfaces
                        interfaces = get_interfaces()
                        
                        if mon_iface in interfaces:
                            self.interface = mon_iface
                        elif alt_mon_iface in interfaces:
                            self.interface = alt_mon_iface
                            
                        self.console.print(f"[green]Monitor mode enabled on {self.interface}[/green]")
                        return True
                else:
                    # Use iw method if airmon-ng is not available
                    return self._enable_monitor_with_iw()
                    
            elif system == "Darwin":  # macOS
                # macOS uses airport utility
                airport_path = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
                
                # Disassociate from any network
                run_command([airport_path, self.interface, "-z"])
                
                # Enable monitor mode with channel 1
                rc, stdout, stderr = run_command([airport_path, self.interface, "--sniff", "1"])
                
                if rc != 0:
                    self.logger.error(f"Failed to enable monitor mode: {stderr}")
                    return False
                    
                self.console.print(f"[green]Monitor mode enabled on {self.interface}[/green]")
                return True
                
            else:  # Windows
                self.console.print("[red]Monitor mode on Windows requires specialized drivers and tools.[/red]")
                return False
                
        except Exception as e:
            self.logger.error(f"Error enabling monitor mode: {str(e)}")
            return False
    
    def _enable_monitor_with_iw(self) -> bool:
        """
        Enable monitor mode using iw command.
        
        Returns:
            bool: True if monitor mode was enabled successfully, False otherwise
        """
        try:
            # Bring down the interface
            run_command(["ip", "link", "set", self.interface, "down"])
            
            # Set monitor mode
            rc, stdout, stderr = run_command(["iw", self.interface, "set", "monitor", "none"])
            
            if rc != 0:
                self.logger.error(f"Failed to set monitor mode: {stderr}")
                return False
                
            # Bring up the interface
            rc, stdout, stderr = run_command(["ip", "link", "set", self.interface, "up"])
            
            if rc != 0:
                self.logger.error(f"Failed to bring up interface: {stderr}")
                return False
                
            self.console.print(f"[green]Monitor mode enabled on {self.interface}[/green]")
            return True
            
        except Exception as e:
            self.logger.error(f"Error setting monitor mode with iw: {str(e)}")
            return False
    
    def _check_airmon_ng(self) -> bool:
        """
        Check if airmon-ng is available.
        
        Returns:
            bool: True if airmon-ng is available, False otherwise
        """
        rc, _, _ = run_command(["which", "airmon-ng"])
        return rc == 0
    
    def _get_interface_state(self) -> Dict[str, Any]:
        """
        Get the current state of the interface for later restoration.
        
        Returns:
            Dict[str, Any]: Interface state information
        """
        state = {
            "interface": self.interface,
            "original_mode": "managed"  # Assume managed by default
        }
        
        system = platform.system()
        
        try:
            if system == "Linux":
                # Try to get the current mode with iw
                rc, stdout, stderr = run_command(["iw", self.interface, "info"])
                if rc == 0 and "type" in stdout:
                    mode_line = [line for line in stdout.split('\n') if "type" in line]
                    if mode_line:
                        state["original_mode"] = mode_line[0].split()[-1]
            
            # Add more platform-specific state saving as needed
            
        except Exception as e:
            self.logger.error(f"Error getting interface state: {str(e)}")
        
        return state
    
    def disable_monitor_mode(self) -> bool:
        """
        Disable monitor mode and restore original interface state.
        
        Returns:
            bool: True if monitor mode was disabled successfully, False otherwise
        """
        if not self.interface:
            self.console.print("[yellow]No interface to restore[/yellow]")
            return False
        
        if not is_root():
            self.console.print("[red]Error: Root privileges required to disable monitor mode[/red]")
            return False
        
        if not self.original_interface_state:
            self.console.print("[yellow]No original state to restore[/yellow]")
            return False
        
        system = platform.system()
        
        try:
            if system == "Linux":
                if self._check_airmon_ng():
                    # Try with airmon-ng first
                    rc, stdout, stderr = run_command(["airmon-ng", "stop", self.interface])
                    
                    if rc != 0:
                        self.logger.error(f"airmon-ng failed: {stderr}")
                        # Fall back to iw method
                        return self._disable_monitor_with_iw()
                    
                    # airmon-ng might have restored the original interface name
                    orig_iface = self.original_interface_state.get("interface")
                    
                    if orig_iface:
                        self.interface = orig_iface
                        
                    self.console.print(f"[green]Monitor mode disabled, interface restored to {self.interface}[/green]")
                    return True
                else:
                    # Use iw method if airmon-ng is not available
                    return self._disable_monitor_with_iw()
                    
            elif system == "Darwin":  # macOS
                # For macOS, simply terminate any sniffing
                processes = subprocess.check_output(["ps", "-ef"]).decode()
                for line in processes.split('\n'):
                    if f"airport {self.interface} --sniff" in line:
                        pid = int(line.split()[1])
                        os.kill(pid, signal.SIGTERM)
                
                # Reset the interface
                airport_path = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
                run_command([airport_path, self.interface, "-z"])
                
                self.console.print(f"[green]Monitor mode disabled on {self.interface}[/green]")
                return True
                
            else:  # Windows
                self.console.print("[yellow]Monitor mode restoration on Windows is not fully supported[/yellow]")
                return False
                
        except Exception as e:
            self.logger.error(f"Error disabling monitor mode: {str(e)}")
            return False
            
        finally:
            self.original_interface_state = None
    
    def _disable_monitor_with_iw(self) -> bool:
        """
        Disable monitor mode using iw command.
        
        Returns:
            bool: True if monitor mode was disabled successfully, False otherwise
        """
        try:
            # Bring down the interface
            run_command(["ip", "link", "set", self.interface, "down"])
            
            # Set managed mode
            original_mode = self.original_interface_state.get("original_mode", "managed")
            rc, stdout, stderr = run_command(["iw", self.interface, "set", "type", original_mode])
            
            if rc != 0:
                self.logger.error(f"Failed to set {original_mode} mode: {stderr}")
                return False
                
            # Bring up the interface
            rc, stdout, stderr = run_command(["ip", "link", "set", self.interface, "up"])
            
            if rc != 0:
                self.logger.error(f"Failed to bring up interface: {stderr}")
                return False
                
            # Restore original interface name if needed
            orig_iface = self.original_interface_state.get("interface")
            if orig_iface and orig_iface != self.interface:
                self.interface = orig_iface
                
            self.console.print(f"[green]Monitor mode disabled, interface restored to {self.interface}[/green]")
            return True
            
        except Exception as e:
            self.logger.error(f"Error disabling monitor mode with iw: {str(e)}")
            return False
    
    def set_channel(self, channel: int) -> bool:
        """
        Set the wireless interface to a specific channel.
        
        Args:
            channel (int): Channel number
            
        Returns:
            bool: True if channel was set successfully, False otherwise
        """
        if not self.interface:
            self.console.print("[red]Error: No interface selected. Use set_interface first.[/red]")
            return False
        
        if not is_root():
            self.console.print("[red]Error: Root privileges required to set channel[/red]")
            return False
        
        if not 1 <= channel <= 14:
            self.console.print(f"[red]Error: Invalid channel number: {channel}[/red]")
            return False
        
        system = platform.system()
        
        try:
            if system == "Linux":
                rc, stdout, stderr = run_command(["iw", "dev", self.interface, "set", "channel", str(channel)])
                
                if rc != 0:
                    self.logger.error(f"Failed to set channel: {stderr}")
                    return False
                    
                self.current_channel = channel
                self.console.print(f"[green]Channel set to: {channel}[/green]")
                return True
                
            elif system == "Darwin":  # macOS
                # For macOS, we need to restart the sniffing with the new channel
                airport_path = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
                
                # Stop any current sniffing
                processes = subprocess.check_output(["ps", "-ef"]).decode()
                for line in processes.split('\n'):
                    if f"airport {self.interface} --sniff" in line:
                        pid = int(line.split()[1])
                        os.kill(pid, signal.SIGTERM)
                
                # Start sniffing on the new channel
                rc, stdout, stderr = run_command([airport_path, self.interface, "--sniff", str(channel)])
                
                if rc != 0:
                    self.logger.error(f"Failed to set channel: {stderr}")
                    return False
                    
                self.current_channel = channel
                self.console.print(f"[green]Channel set to: {channel}[/green]")
                return True
                
            else:  # Windows
                self.console.print("[red]Channel setting on Windows is not fully supported[/red]")
                return False
                
        except Exception as e:
            self.logger.error(f"Error setting channel: {str(e)}")
            return False
    
    def start_channel_hopping(self, interval: float = 1.0) -> bool:
        """
        Start channel hopping on the wireless interface.
        
        Args:
            interval (float): Time in seconds between channel hops
            
        Returns:
            bool: True if channel hopping was started successfully, False otherwise
        """
        if not self.interface:
            self.console.print("[red]Error: No interface selected. Use set_interface first.[/red]")
            return False
        
        if self.channel_hopping:
            self.console.print("[yellow]Channel hopping is already active[/yellow]")
            return True
        
        if not is_root():
            self.console.print("[red]Error: Root privileges required for channel hopping[/red]")
            return False
        
        self.channel_hopping = True
        self.channel_hopper_thread = threading.Thread(
            target=self._channel_hopper, 
            args=(interval,),
            daemon=True
        )
        self.channel_hopper_thread.start()
        
        self.console.print(f"[green]Channel hopping started with interval: {interval} seconds[/green]")
        return True
    
    def stop_channel_hopping(self) -> bool:
        """
        Stop channel hopping.
        
        Returns:
            bool: True if channel hopping was stopped successfully, False otherwise
        """
        if not self.channel_hopping:
            self.console.print("[yellow]Channel hopping is not active[/yellow]")
            return False
        
        self.channel_hopping = False
        
        if self.channel_hopper_thread:
            self.channel_hopper_thread.join(timeout=2.0)
            self.channel_hopper_thread = None
        
        self.console.print("[green]Channel hopping stopped[/green]")
        return True
    
    def _channel_hopper(self, interval: float) -> None:
        """
        Channel hopping thread function.
        
        Args:
            interval (float): Time in seconds between channel hops
        """
        channels = list(range(1, 14))  # Channels 1-13
        
        while self.channel_hopping:
            for channel in channels:
                if not self.channel_hopping:
                    break
                
                self.set_channel(channel)
                time.sleep(interval)
    
    def start_scan(self) -> bool:
        """
        Start scanning for wireless networks.
        
        Returns:
            bool: True if scanning was started successfully, False otherwise
        """
        if not self.interface:
            self.console.print("[red]Error: No interface selected. Use set_interface first.[/red]")
            return False
        
        if self.scanning:
            self.console.print("[yellow]Scanning is already active[/yellow]")
            return True
        
        if not is_root():
            self.console.print("[red]Error: Root privileges required for scanning[/red]")
            return False
        
        # Clear previous results
        self.networks = {}
        self.clients = {}
        self.probes = {}
        
        # Start channel hopping if not already active
        if not self.channel_hopping:
            self.start_channel_hopping()
        
        # Start the scanner thread
        self.scanning = True
        self.scan_start_time = datetime.now()
        self.scanner_thread = threading.Thread(
            target=self._scanner,
            daemon=True
        )
        self.scanner_thread.start()
        
        self.console.print("[green]WiFi scanning started[/green]")
        return True
    
    def stop_scan(self) -> bool:
        """
        Stop scanning for wireless networks.
        
        Returns:
            bool: True if scanning was stopped successfully, False otherwise
        """
        if not self.scanning:
            self.console.print("[yellow]Scanning is not active[/yellow]")
            return False
        
        self.scanning = False
        
        if self.scanner_thread:
            self.scanner_thread.join(timeout=2.0)
            self.scanner_thread = None
        
        self.console.print("[green]WiFi scanning stopped[/green]")
        return True
    
    def _scanner(self) -> None:
        """
        Scanner thread function. Captures and processes wireless packets.
        """
        # Set up Scapy to use the selected interface
        conf.iface = self.interface
        
        # Start sniffing packets
        self.logger.info(f"Starting packet capture on {self.interface}")
        
        try:
            sniff(prn=self._process_packet, store=0, stop_filter=lambda p: not self.scanning)
        except Exception as e:
            self.logger.error(f"Error in scanner: {str(e)}")
            self.scanning = False
    
    def _process_packet(self, packet) -> None:
        """
        Process a captured packet and extract relevant information.
        
        Args:
            packet: The captured packet
        """
        # Check if packet has wireless layer (Dot11)
        if not packet.haslayer(Dot11):
            return
        
        # Get the timestamp
        timestamp = datetime.now()
        
        # Extract MAC addresses
        addr1 = packet[Dot11].addr1  # Destination address
        addr2 = packet[Dot11].addr2  # Source address
        addr3 = packet[Dot11].addr3  # BSSID in most cases
        
        # Skip invalid MACs
        if not all([addr1, addr2, addr3]) or \
           any([addr == "00:00:00:00:00:00" or addr == "ff:ff:ff:ff:ff:ff" for addr in [addr1, addr2, addr3]]):
            return
        
        # Process beacon frames (APs advertising themselves)
        if packet.haslayer(Dot11Beacon):
            self._process_beacon(packet, timestamp)
        
        # Process probe response frames (AP responding to a client)
        elif packet.haslayer(Dot11ProbeResp):
            self._process_probe_response(packet, timestamp)
        
        # Process probe request frames (client looking for networks)
        elif packet.haslayer(Dot11ProbeReq):
            self._process_probe_request(packet, timestamp)
        
        # Process data frames (actual data between clients and APs)
        elif packet.type == 2:  # Data frame
            self._process_data_frame(packet, timestamp)
    
    def _process_beacon(self, packet, timestamp) -> None:
        """
        Process a beacon frame to extract AP information.
        
        Args:
            packet: The captured packet
            timestamp: Timestamp when the packet was captured
        """
        # Extract basic information
        bssid = packet[Dot11].addr3
        
        # Extract SSID
        ssid = None
        
        # Try to extract SSID from the packet
        if packet.haslayer(Dot11Elt) and packet[Dot11Elt].ID == 0:
            ssid = packet[Dot11Elt].info.decode('utf-8', errors='replace')
            
            # Skip hidden networks for now (empty SSID)
            if not ssid:
                ssid = "<hidden>"
        
        if not ssid:
            return
        
        # Get the radio tap information
        signal_strength = None
        channel = None
        
        if packet.haslayer(RadioTap):
            signal_strength = -(256 - packet[RadioTap].dBm_AntSignal) if hasattr(packet[RadioTap], 'dBm_AntSignal') else None
            channel = packet[RadioTap].ChannelFrequency if hasattr(packet[RadioTap], 'ChannelFrequency') else None
        
        # Get encryption information
        encryption = self._get_encryption_type(packet)
        
        # Update networks dictionary
        if bssid not in self.networks:
            self.networks[bssid] = {
                'ssid': ssid,
                'bssid': bssid,
                'channel': channel,
                'signal_strength': signal_strength,
                'encryption': encryption,
                'first_seen': timestamp,
                'last_seen': timestamp,
                'beacons': 1,
                'clients': set()
            }
        else:
            self.networks[bssid]['last_seen'] = timestamp
            self.networks[bssid]['beacons'] += 1
            
            # Update SSID if we previously had a hidden one
            if self.networks[bssid]['ssid'] == "<hidden>" and ssid != "<hidden>":
                self.networks[bssid]['ssid'] = ssid
                
            # Update signal strength if available
            if signal_strength is not None:
                self.networks[bssid]['signal_strength'] = signal_strength
                
            # Update channel if available
            if channel is not None:
                self.networks[bssid]['channel'] = channel
                
            # Update encryption info if available
            if encryption:
                self.networks[bssid]['encryption'] = encryption
    
    def _process_probe_response(self, packet, timestamp) -> None:
        """
        Process a probe response frame.
        
        Args:
            packet: The captured packet
            timestamp: Timestamp when the packet was captured
        """
        # Extract information
        bssid = packet[Dot11].addr2
        client = packet[Dot11].addr1
        
        # Extract SSID
        ssid = None
        
        if packet.haslayer(Dot11Elt) and packet[Dot11Elt].ID == 0:
            ssid = packet[Dot11Elt].info.decode('utf-8', errors='replace')
            
            # Skip hidden networks
            if not ssid:
                ssid = "<hidden>"
        
        if not ssid:
            return
        
        # Get the radio tap information
        signal_strength = None
        channel = None
        
        if packet.haslayer(RadioTap):
            signal_strength = -(256 - packet[RadioTap].dBm_AntSignal) if hasattr(packet[RadioTap], 'dBm_AntSignal') else None
            channel = packet[RadioTap].ChannelFrequency if hasattr(packet[RadioTap], 'ChannelFrequency') else None
        
        # Get encryption information
        encryption = self._get_encryption_type(packet)
        
        # Update networks dictionary
        if bssid not in self.networks:
            self.networks[bssid] = {
                'ssid': ssid,
                'bssid': bssid,
                'channel': channel,
                'signal_strength': signal_strength,
                'encryption': encryption,
                'first_seen': timestamp,
                'last_seen': timestamp,
                'beacons': 0,
                'clients': set([client])
            }
        else:
            self.networks[bssid]['last_seen'] = timestamp
            self.networks[bssid]['clients'].add(client)
            
            # Update SSID if we previously had a hidden one
            if self.networks[bssid]['ssid'] == "<hidden>" and ssid != "<hidden>":
                self.networks[bssid]['ssid'] = ssid
                
            # Update signal strength if available
            if signal_strength is not None:
                self.networks[bssid]['signal_strength'] = signal_strength
                
            # Update channel if available
            if channel is not None:
                self.networks[bssid]['channel'] = channel
                
            # Update encryption info if available
            if encryption:
                self.networks[bssid]['encryption'] = encryption
        
        # Update clients dictionary
        if client not in self.clients:
            self.clients[client] = {
                'mac': client,
                'networks': set([bssid]),
                'first_seen': timestamp,
                'last_seen': timestamp,
                'packets': 1,
                'vendor': parse_mac_vendor(client)
            }
        else:
            self.clients[client]['last_seen'] = timestamp
            self.clients[client]['packets'] += 1
            self.clients[client]['networks'].add(bssid)
    
    def _process_probe_request(self, packet, timestamp) -> None:
        """
        Process a probe request frame.
        
        Args:
            packet: The captured packet
            timestamp: Timestamp when the packet was captured
        """
        # Extract information
        client = packet[Dot11].addr2
        
        # Extract SSID being requested
        ssid = None
        
        if packet.haslayer(Dot11Elt) and packet[Dot11Elt].ID == 0:
            ssid = packet[Dot11Elt].info.decode('utf-8', errors='replace')
            
            # Skip broadcast probes (empty SSID)
            if not ssid:
                return
        
        if not ssid:
            return
        
        # Update probes dictionary
        if client not in self.probes:
            self.probes[client] = {
                'ssids': set([ssid]),
                'first_seen': timestamp,
                'last_seen': timestamp,
                'count': 1
            }
        else:
            self.probes[client]['last_seen'] = timestamp
            self.probes[client]['ssids'].add(ssid)
            self.probes[client]['count'] += 1
        
        # Update clients dictionary
        if client not in self.clients:
            self.clients[client] = {
                'mac': client,
                'networks': set(),
                'first_seen': timestamp,
                'last_seen': timestamp,
                'packets': 1,
                'vendor': parse_mac_vendor(client)
            }
        else:
            self.clients[client]['last_seen'] = timestamp
            self.clients[client]['packets'] += 1
    
    def _process_data_frame(self, packet, timestamp) -> None:
        """
        Process a data frame.
        
        Args:
            packet: The captured packet
            timestamp: Timestamp when the packet was captured
        """
        # Extract MAC addresses
        addr1 = packet[Dot11].addr1
        addr2 = packet[Dot11].addr2
        addr3 = packet[Dot11].addr3
        
        # Determine AP and client MAC
        if addr1 == "ff:ff:ff:ff:ff:ff" or addr2 == "ff:ff:ff:ff:ff:ff":
            return
        
        bssid = None
        client = None
        
        # DS Status bits determine the role of each address
        ds_status = packet.FCfield & 0x3
        
        if ds_status == 0:  # Not DS (Ad-hoc)
            return
        elif ds_status == 1:  # To DS
            client = addr2  # Source is client
            bssid = addr1   # Destination is AP
        elif ds_status == 2:  # From DS
            client = addr1  # Destination is client
            bssid = addr2   # Source is AP
        elif ds_status == 3:  # DS to DS (WDS)
            return
        
        if not (client and bssid):
            return
        
        # Update networks dictionary
        if bssid in self.networks:
            self.networks[bssid]['last_seen'] = timestamp
            self.networks[bssid]['clients'].add(client)
        
        # Update clients dictionary
        if client not in self.clients:
            self.clients[client] = {
                'mac': client,
                'networks': set([bssid]),
                'first_seen': timestamp,
                'last_seen': timestamp,
                'packets': 1,
                'vendor': parse_mac_vendor(client)
            }
        else:
            self.clients[client]['last_seen'] = timestamp
            self.clients[client]['packets'] += 1
            if bssid:
                self.clients[client]['networks'].add(bssid)
    
    def _get_encryption_type(self, packet) -> str:
        """
        Determine the encryption type from a packet.
        
        Args:
            packet: The captured packet
            
        Returns:
            str: Encryption type (None, WEP, WPA, WPA2, WPA3)
        """
        # Default to None
        encryption = "None"
        
        # Check if Privacy bit is set in Capability field
        if packet.haslayer(Dot11Beacon):
            cap = packet[Dot11Beacon].cap
            privacy_bit = bool(cap & 0x10)
            
            if privacy_bit:
                encryption = "WEP"  # Default to WEP if privacy bit is set
                
                # Search for RSN (WPA2) information
                crypto = set()
                rsn = False
                
                # Process all Information Elements
                current_element = packet[Dot11Elt]
                while current_element:
                    # RSN element indicates WPA2/WPA3
                    if current_element.ID == 48:
                        rsn = True
                        # Parse RSN IE to determine exact encryption
                        if len(current_element.info) >= 4:
                            version = int.from_bytes(current_element.info[0:2], byteorder='little')
                            if version == 1:
                                encryption = "WPA2"
                            if len(current_element.info) >= 8:
                                # Check for CCMP (AES) cipher suite
                                if current_element.info[4:8] == b'\x00\x0f\xac\x04':
                                    crypto.add("CCMP")
                                # Check for TKIP cipher suite
                                elif current_element.info[4:8] == b'\x00\x0f\xac\x02':
                                    crypto.add("TKIP")
                                
                    # Vendor specific element might indicate WPA1
                    elif current_element.ID == 221 and current_element.info.startswith(b'\x00\x50\xf2\x01'):
                        if not rsn:  # Only mark as WPA1 if not already WPA2
                            encryption = "WPA"
                        # Check for CCMP (AES) cipher suite
                        if b'\x00\x50\xf2\x04' in current_element.info:
                            crypto.add("CCMP")
                        # Check for TKIP cipher suite
                        if b'\x00\x50\xf2\x02' in current_element.info:
                            crypto.add("TKIP")
                    
                    # Move to next element
                    if not hasattr(current_element, 'payload'):
                        break
                    current_element = current_element.payload
                    if not hasattr(current_element, 'ID'):
                        break
                
                # Add crypto information to encryption string
                if crypto:
                    encryption += " (" + "+".join(crypto) + ")"
        
        return encryption
    
    def show_networks(self) -> None:
        """
        Display discovered wireless networks.
        """
        if not self.networks:
            self.console.print("[yellow]No networks discovered yet[/yellow]")
            return
        
        # Create a formatted table
        table = Table(title="Discovered Wireless Networks")
        table.add_column("#", style="dim", width=4)
        table.add_column("SSID", style="cyan")
        table.add_column("BSSID", style="blue")
        table.add_column("Channel", style="magenta", width=8)
        table.add_column("Signal", style="green", width=8)
        table.add_column("Encryption", style="yellow")
        table.add_column("Clients", style="red", width=8)
        
        # Sort networks by signal strength
        sorted_networks = sorted(
            self.networks.values(), 
            key=lambda x: x.get('signal_strength', -100),
            reverse=True
        )
        
        for idx, network in enumerate(sorted_networks, 1):
            signal = f"{network.get('signal_strength', 'N/A')} dBm" if network.get('signal_strength') else "N/A"
            
            table.add_row(
                str(idx),
                network.get('ssid', 'N/A'),
                network.get('bssid', 'N/A'),
                str(network.get('channel', 'N/A')),
                signal,
                network.get('encryption', 'N/A'),
                str(len(network.get('clients', set())))
            )
        
        # Print the table
        self.console.print(table)
        
        # Print scan duration
        if self.scan_start_time:
            duration = datetime.now() - self.scan_start_time
            self.console.print(f"[dim]Scan duration: {duration}[/dim]")
    
    def show_clients(self) -> None:
        """
        Display discovered clients.
        """
        if not self.clients:
            self.console.print("[yellow]No clients discovered yet[/yellow]")
            return
        
        # Create a formatted table
        table = Table(title="Discovered Clients")
        table.add_column("#", style="dim", width=4)
        table.add_column("MAC", style="cyan")
        table.add_column("Vendor", style="blue")
        table.add_column("Connected To", style="green")
        table.add_column("Probed Networks", style="yellow")
        table.add_column("Packets", style="magenta", width=8)
        
        # Sort clients by packets
        sorted_clients = sorted(
            self.clients.values(), 
            key=lambda x: x.get('packets', 0),
            reverse=True
        )
        
        for idx, client in enumerate(sorted_clients, 1):
            # Get connected networks (SSIDs)
            connected_ssids = []
            for bssid in client.get('networks', set()):
                if bssid in self.networks:
                    connected_ssids.append(self.networks[bssid].get('ssid', 'N/A'))
            
            connected_to = ", ".join(connected_ssids) if connected_ssids else "N/A"
            
            # Get probed SSIDs
            probed_ssids = []
            if client['mac'] in self.probes:
                probed_ssids = list(self.probes[client['mac']]['ssids'])
            
            probed = ", ".join(probed_ssids) if probed_ssids else "N/A"
            
            table.add_row(
                str(idx),
                client.get('mac', 'N/A'),
                client.get('vendor', 'Unknown'),
                connected_to,
                probed,
                str(client.get('packets', 0))
            )
        
        # Print the table
        self.console.print(table)
        
        # Print scan duration
        if self.scan_start_time:
            duration = datetime.now() - self.scan_start_time
            self.console.print(f"[dim]Scan duration: {duration}[/dim]")
    
    def show_probes(self) -> None:
        """
        Display probe requests.
        """
        if not self.probes:
            self.console.print("[yellow]No probe requests discovered yet[/yellow]")
            return
        
        # Create a formatted table
        table = Table(title="Probe Requests")
        table.add_column("#", style="dim", width=4)
        table.add_column("Client MAC", style="cyan")
        table.add_column("Vendor", style="blue")
        table.add_column("Probed SSIDs", style="yellow")
        table.add_column("Count", style="magenta", width=8)
        
        # Sort probes by count
        sorted_probes = sorted(
            [(mac, data) for mac, data in self.probes.items()],
            key=lambda x: x[1].get('count', 0),
            reverse=True
        )
        
        for idx, (mac, data) in enumerate(sorted_probes, 1):
            vendor = self.clients[mac]['vendor'] if mac in self.clients else "Unknown"
            
            table.add_row(
                str(idx),
                mac,
                vendor,
                ", ".join(data['ssids']),
                str(data['count'])
            )
        
        # Print the table
        self.console.print(table)
        
        # Print scan duration
        if self.scan_start_time:
            duration = datetime.now() - self.scan_start_time
            self.console.print(f"[dim]Scan duration: {duration}[/dim]")
    
    def save_results(self, filename: str = None) -> bool:
        """
        Save scan results to a file.
        
        Args:
            filename (str, optional): Output filename
            
        Returns:
            bool: True if results were saved successfully, False otherwise
        """
        if not self.networks and not self.clients:
            self.console.print("[yellow]No results to save[/yellow]")
            return False
        
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"wifi_scan_{timestamp}.json"
        
        # Create data directory if it doesn't exist
        data_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data')
        os.makedirs(data_dir, exist_ok=True)
        
        # Full path to output file
        output_file = os.path.join(data_dir, filename)
        
        try:
            # Prepare data for serialization (convert sets to lists)
            networks_data = {}
            for bssid, network in self.networks.items():
                networks_data[bssid] = {**network}
                networks_data[bssid]['clients'] = list(network['clients'])
                networks_data[bssid]['first_seen'] = network['first_seen'].isoformat()
                networks_data[bssid]['last_seen'] = network['last_seen'].isoformat()
            
            clients_data = {}
            for mac, client in self.clients.items():
                clients_data[mac] = {**client}
                clients_data[mac]['networks'] = list(client['networks'])
                clients_data[mac]['first_seen'] = client['first_seen'].isoformat()
                clients_data[mac]['last_seen'] = client['last_seen'].isoformat()
            
            probes_data = {}
            for mac, probe in self.probes.items():
                probes_data[mac] = {**probe}
                probes_data[mac]['ssids'] = list(probe['ssids'])
                probes_data[mac]['first_seen'] = probe['first_seen'].isoformat()
                probes_data[mac]['last_seen'] = probe['last_seen'].isoformat()
            
            # Create the final data structure
            data = {
                'networks': networks_data,
                'clients': clients_data,
                'probes': probes_data,
                'scan_start': self.scan_start_time.isoformat() if self.scan_start_time else None,
                'scan_end': datetime.now().isoformat(),
                'interface': self.interface
            }
            
            # Write to file
            with open(output_file, 'w') as f:
                import json
                json.dump(data, f, indent=4)
            
            self.console.print(f"[green]Results saved to: {output_file}[/green]")
            return True
            
        except Exception as e:
            self.logger.error(f"Error saving results: {str(e)}")
            self.console.print(f"[red]Error saving results: {str(e)}[/red]")
            return False
    
    def cleanup(self) -> None:
        """
        Clean up resources before unloading the plugin.
        """
        # Stop scanning if active
        if self.scanning:
            self.stop_scan()
        
        # Stop channel hopping if active
        if self.channel_hopping:
            self.stop_channel_hopping()
        
        # Disable monitor mode if it was enabled
        if self.original_interface_state:
            self.disable_monitor_mode()
        
        self.logger.info("WiFi reconnaissance plugin cleaned up")
