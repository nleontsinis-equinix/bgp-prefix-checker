# bgp-prefix-checker
A Python tool to analyze and monitor the global propagation of IP prefixes using RIPEstat APIs. This tool fetches advertised prefixes for a list of IP addresses, checks their visibility in the global BGP table, and provides detailed results on their announcement status. Ideal for network engineers and researchers monitoring BGP visibility


Key Functionalities of the Script:

    Fetch Advertised Prefix:
        Uses the RIPEstat prefix-overview API to get the advertised prefix for a given IP address.

    Check Prefix Visibility:
        Uses the RIPEstat bgp-state API to determine if the fetched prefix is visible in the global BGP table.

    Process a List of IPs:
        Reads a file containing a list of IP addresses.
        For each IP, fetches the prefix and checks its visibility status.

    Output Results:
        Prints whether each IP's prefix is globally propagated or not.

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
