<div align="center">

# ✨ NullHandshake ✨

<img src="generated-icon.png" alt="NullHandshake Logo" width="180px">



### 🔒 Modern Wireless Network Security Assessment Framework 🔒

[![Python](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Flask](https://img.shields.io/badge/flask-2.0+-green.svg)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)

</div>

---

## 📡 About

**NullHandshake** is a cutting-edge offensive security framework for wireless network assessment, featuring a sleek, animated web interface. Security researchers can quickly identify vulnerable networks, extract credentials, and execute sophisticated wireless attacks - all through an intuitive, modern GUI.

<div align="center">
<table>
<tr>
<td align="center">🔍 <b>Network Discovery</b></td>
<td align="center">🔑 <b>Credential Extraction</b></td>
<td align="center">📶 <b>Evil Twin Attacks</b></td>
<td align="center">🔐 <b>WPA Handshake Capture</b></td>
</tr>
</table>
  <img src="https://github.com/0xnull0/NullHandshake/blob/main/templates/w.avif">
</div>

## ✨ Key Features

- **🎨 Futuristic Web Interface** - Beautiful, animated UI with no CLI dependency
- **🧩 Plugin Architecture** - Modular design with self-contained attack vectors
- **💻 Cross-Platform Support** - Extract credentials from Windows, Linux, and macOS 
- **🔄 Real-Time Monitoring** - Live scanning and interactive network analysis
- **🖥️ Interactive Console** - Built-in terminal with command history and autocomplete
- **📊 Visual Analytics** - Data visualization for discovered networks and devices
- **⚡ Smooth Animations** - Polished transitions and feedback throughout the application

## 🧰 Modules

<details>
<summary><b>🔍 WiFi Recon</b></summary>
<br>
Discover and analyze wireless networks with comprehensive signal mapping, client enumeration, and vulnerability assessment.

**Key capabilities:**
- Network discovery and classification
- Signal strength mapping
- Client device enumeration
- Security protocol analysis
</details>

<details>
<summary><b>🔑 Credential Harvester</b></summary>
<br>
Extract and manage network credentials across operating systems with seamless integration to post-exploitation workflows.

**Key capabilities:**
- Multi-OS credential extraction
- Saved password recovery
- Credential organization and filtering
- Export in multiple formats
</details>

<details>
<summary><b>📶 Evil Twin</b></summary>
<br>
Create and manage rogue access points with custom captive portals for man-in-the-middle assessment scenarios.

**Key capabilities:**
- One-click AP deployment
- Custom captive portal templates
- Client connection management
- Traffic capture and analysis
</details>

<details>
<summary><b>🔐 WPA Handshake</b></summary>
<br>
Automated discovery and capture of WPA/WPA2 handshakes for security analysis and offline testing.

**Key capabilities:**
- Target AP prioritization
- Automated client deauthentication
- PMKID attack support
- Handshake validation and export
</details>

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/yourusername/nullhandshake.git
cd nullhandshake

# Install dependencies
pip install -r requirements.txt

# Launch the web interface
python main.py
```

## 🖥️ Usage

### Web Interface

Access the intuitive web dashboard at http://localhost:5000

### Command Line

For traditional CLI usage:
```bash
python nullhandshake.py
```

## 🛠️ Requirements

- Python 3.9+
- Flask 2.0+
- Flask-SQLAlchemy
- Scapy
- netifaces

## 🔄 Workflows

NullHandshake supports seamless workflows between modules:
1. **Discover** networks with WiFi Recon
2. **Deploy** Evil Twin based on discovered networks
3. **Capture** credentials or handshakes
4. **Export** results for further analysis

## ⚠️ Legal Disclaimer

**NullHandshake** is designed for authorized security testing only. Users must comply with all applicable laws and regulations. The developers assume no liability for misuse or damage caused by this software.

## 👥 Contributing

Contributions are welcome! Please check out our [contribution guidelines](CONTRIBUTING.md) to get started.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

<div align="center">
<p>Built with ❤️ for the security research community</p>
</div>
