# Defnet-IDS-IPS

Welcome to **Defnet-IDS-IPS**, a modern, lightweight, and efficient Intrusion Detection and Prevention System (IDS/IPS) designed to monitor, alert, and block suspicious network activities. This tool is tailored for enthusiasts and professionals looking for a customizable solution that integrates seamlessly with OpenWRT and similar environments.

---

## Table of Contents
1. [Features](#features)
2. [Getting Started](#getting-started)
3. [Directory Structure](#directory-structure)
4. [Configuration](#configuration)
5. [Usage](#usage)
6. [Contributing](#contributing)
7. [License](#license)

---

## Features
- **Real-Time Packet Monitoring**: Efficiently sniff and analyze network packets.
- **Customizable Rules**: Define, parse, and manage rules to detect and mitigate network threats.
- **Blocking Mechanism**: Use a blacklist to block malicious IP addresses dynamically.
- **Protocol Support**: Built-in support for multiple protocols with extensible configurations.
- **Radix Tree for Rules**: Optimized rule matching with a radix tree data structure.
- **OpenWRT Integration**: Seamlessly integrates with OpenWRT environments via a shell script.
- **Start/Stop Service Management**: Intuitive service controls with `main.py` and `service_manager.py`.

---

## Getting Started

### Prerequisites
- Python 3.8 or higher
- `scapy` for packet sniffing and analysis
- Administrator/root access for managing network configurations
- OpenWRT environment (optional)

### Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/Defnet-IDS-IPS.git
   cd Defnet-IDS-IPS
   ```
2. Install required Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. (Optional) Set up OpenWRT integration:
   ```bash
   ./openwrt-ids-ips.sh
   ```

---

## Directory Structure

The repository is organized into the following structure:

```sh
Defnet-IDS-IPS/
├── main.py                  # Core application: Start/Stop the service
├── openwrt-ids-ips.sh       # Shell script for managing the service on OpenWRT
├── configuration/           # Configuration files
│   ├── config_protocols.json   # Supported protocols
│   └── config_settings.json    # Network settings (HOME_NET, EXTERNAL_NET)
├── core/                    # Core utilities
│   └── utils.py
├── protocols/               # Protocol management
│   └── protocols.py
├── radixTree/               # Radix tree implementation for rule optimization
│   └── radix_tree.py
├── services/                # Service components
│   ├── service_manager.py      # Start/stop service logic
│   ├── packet_analyzer.py      # Analyze network packets
│   ├── packet_sniffer.py       # Sniff network packets
│   └── config_service.py       # Manage configuration loading
├── rules/                   # Rule definitions and managers
│   ├── config_rules.json       # Predefined network rules
│   ├── rule.py                # Rule data structure
│   ├── rule_manager.py        # Manage categorized rules
│   └── rule_parser.py         # Parse rule configurations
└── README.md                # Documentation
```

---

## Configuration

### 1. Protocol Configuration
Define the supported protocols in `configuration/config_protocols.json`. For example:
```json
{
  "TCP": 6,
  "UDP": 17,
  "ICMP": 1
}
```

### 2. Network Settings
Customize network settings in `configuration/config_settings.json`:
```json
{
  "HOME_NET": "192.168.1.0/24",
  "EXTERNAL_NET": "any"
}
```

### 3. Rules
Define your detection and prevention rules in `rules/config_rules.json`. Example:
```json
{
  "rule_id": "1",
  "protocol": "ICMP",
  "src_ip": "any",
  "dst_ip": "any",
  "action": "alert",
  "description": "ICMP packet detection",
  "threshold": {
    "count": 1,
    "time": 10
  },
  "flags":"S"
}
```

---

## Usage

### Starting the Service
Use the main script to start or stop the IDS/IPS service:
```bash
python main.py start
```

### Stopping the Service
```bash
python main.py stop
```

### OpenWRT Integration - Start/Stop Service 
Use the shell script to manage the service in an OpenWRT environment:
```bash
./openwrt-ids-ips.sh start
./openwrt-ids-ips.sh stop
```

---

## Contributing
We welcome contributions! Please follow these steps:
1. Fork the repository.
2. Create a new branch for your feature or bug fix.
3. Commit your changes and push to your fork.
4. Submit a pull request with a clear description of your changes.

---

## License
Defnet-IDS-IPS is licensed under the MIT License. See `LICENSE` for details.

---

Happy detecting and preventing! 🚀

