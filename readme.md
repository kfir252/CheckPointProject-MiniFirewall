
# Mini Firewall

## Overview
The Mini Firewall API is a simple command-line utility that allows users to manage a firewall's configuration by modifying port lists and DNS blacklists. The tool provides options to view, add, and remove entries from these lists, helping to control network access and traffic filtering.

## Features
- **Sniffing Configuration Tools**: 
  - View, add, or remove port entries from a port list (`portlist.txt`).
  - These ports are monitored by the firewall for network activity.
  
- **Blocker Configuration Tools**: 
  - View, add, or remove DNS entries from a blacklist (`blacklist.txt`).
  - These DNS entries represent domains that are blocked by the firewall.

## File Structure
- `./api_menu.c`: Main source file containing the CLI program logic.
- `/etc/portlist.txt`: A text file that stores the list of ports being monitored by the firewall.
- `/etc/blacklist.txt`: A text file that stores the list of blacklisted DNS entries.
- `./blocker/DnsBlocker.c`: Source file responsible for handling DNS blocking functionality.
- `./sniffer/PortSniffer.c`: Source file responsible for port sniffing and network monitoring.


## Requirements
- GCC (for compiling the program).
- Root permissions (for modifying `/etc/portlist.txt` and `/etc/blacklist.txt`).

## How to Compile and Run
### Compile the Program:
```bash
gcc -o firewall_api api_menu.c
```

### Run the Program:
```bash
sudo ./firewall_api
```
> **Note**: You may need `sudo` privileges because the program interacts with files in `/etc/`.


## Usage
Once you run the program, you’ll be presented with a main menu that allows you to select one of two options:
1. **Sniffing Configuration Tools**: Manage monitored ports.
2. **Blocker Configuration Tools**: Manage blacklisted DNS entries.

### Sniffing Configuration Tools
In the Sniffing Configuration Tools menu, you can:
- View the current list of monitored ports.
- Add a new port to the list.
- Remove an existing port from the list.

### Blocker Configuration Tools
In the Blocker Configuration Tools menu, you can:
- View the current list of blacklisted DNS entries.
- Add a new DNS entry to the blacklist.
- Remove an existing DNS entry from the blacklist.

## File Paths
- **Port List**: The file `/etc/portlist.txt` stores the list of ports.
- **Blacklist**: The file `/etc/blacklist.txt` stores the DNS entries.

Ensure that these files exist and are readable and writable by the user running the program.

## Issues
If you encounter any issues while using the tool, please submit a bug report with details about the problem and steps to reproduce it.

## License
This project is licensed under the GPL-3.0 License.
