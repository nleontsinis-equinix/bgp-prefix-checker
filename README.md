# bgp-prefix-checker
A Python tool to analyze and monitor the global propagation of IP prefixes using RIPEstat APIs. This tool fetches advertised prefixes for a list of IP addresses, checks their visibility in the global BGP table, and provides detailed results on their announcement status. Ideal for network engineers and researchers monitoring BGP visibility


## Features
- Fetch advertised prefixes for a given IP address.
- Check if prefixes are globally visible in the BGP table.
- Process a list of IPs from a file and display results.

## Requirements
- Python 3.x
- `requests` library (Install using `pip install requests`)

## Installation
1. Clone this repository:
   ```bash
   git clone git@github.com:nleontsinis-equinix/bgp-prefix-checker.git
   cd prefix-visibility-checker

Install dependencies:
pip install requests


Usage

Prepare a file named ip_addresses.txt with one IP address per line:
192.0.2.1
203.0.113.5


Run the script:
python check_prefixes.py
