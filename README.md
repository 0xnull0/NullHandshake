# NullHandshake

A modular, plugin-driven offensive security framework for wireless network post-exploitation and credential harvesting.

## Overview

NullHandshake is a powerful tool designed for security researchers and penetration testers to assess the security of wireless networks. It provides a unified interface for various WiFi-based attack techniques through its plugin architecture.

> ⚠️ **DISCLAIMER**: This tool is intended strictly for use in controlled environments, security assessments, and training simulations with explicit authorization. Unauthorized access to computer networks is illegal and punishable under law.

## Features

- **Plugin-Based Architecture**: Seamlessly integrate attack modules such as WiFi recon, WPA key extraction, and captive portal phishing.
- **Credential Harvesting**: Extract saved WiFi passwords from Windows, Linux, and macOS devices.
- **Evil Twin Automation**: Deploy rogue APs that mimic legitimate networks and capture user credentials via phishing portals.
- **WPA Handshake Capture**: Automate deauthentication attacks and prepare handshakes for offline password cracking.
- **Extensible & Scriptable**: Designed for red team operators who want to expand with custom attack modules.

## Included Plugins

- **WiFi Recon**: Scan for wireless networks, monitor traffic, and analyze WiFi data.
- **Credential Harvester**: Extract stored WiFi credentials from various operating systems.
- **Evil Twin**: Create rogue access points that mimic legitimate networks.
- **WPA Handshake**: Capture and process WPA handshakes for offline cracking.

## Usage

### CLI Interface

You can use NullHandshake through its interactive CLI interface:

```bash
python nullhandshake.py
```

This will open the interactive console where you can type commands:

```
[nullhandshake] > help
```

### Single Command Execution

To execute a single command and exit:

```bash
python run.py "command"
```

For example:

```bash
python run.py "plugins"
python run.py "load wifirecon"
python run.py "help"
```

### Common Commands

- `help` - Display the help menu showing all available commands
- `plugins` - List all available plugins in the framework
- `load <plugin_name>` - Load and activate a specific plugin
- `unload` - Unload the currently active plugin
- `plugin_help` - Show detailed help for the active plugin
- `config` - View or set configuration options
- `exit` or `quit` - Exit the program

## Plugin-Specific Commands

Each plugin provides its own set of commands. After loading a plugin, use `plugin_help` to see available commands.

Example for WiFi Recon plugin:

```
[nullhandshake] > load wifirecon
Plugin 'wifirecon' activated successfully
[nullhandshake] > plugin_help
```

## Requirements

- Python 3.10+
- Required Python packages:
  - scapy
  - rich
  - netifaces
  - flask
  - typer

Some plugins may require root/admin privileges to function properly, especially those interacting with network interfaces.

## License

This project is intended for educational and ethical security research purposes only.

## Authors

Security research and penetration testing team.