check-prefixes.py – Multi-Provider BGP Visibility Checker
check-prefixes.py is a Python tool for network engineers to verify global BGP visibility of IP prefixes and addresses across multiple data sources. It also reports origin ASNs and organisation names, and generates a separate report for non-propagated prefixes.
Features

Query multiple providers:

RIPEstat – Prefix visibility and more-specifics.
BGPView – Visibility, ASN, and organisation details.
Cloudflare Radar (requires API token).
bgproutes.io (requires API endpoint).
Team Cymru WHOIS – ASN and name mapping.
RADb IRR – Registration evidence.


Deduplicated origin ASN reporting with provider sources.
Optional JSON output for automation.
Separate file report for non-propagated prefixes.
Configurable HTTP timeout, retries, and backoff.
Built-in --help, --providers-list, and --version.

Usage

# Basic check with all providers
python3 check-prefixes.py -r prefixes.txt

# JSON output
python3 check-prefixes.py -r prefixes.txt --json

# Limit providers
python3 check-prefixes.py -r prefixes.txt --providers ripe,bgpview,teamcymru

# Custom report file
python3 check-prefixes.py -r prefixes.txt --report-file /tmp/not_propagated.txt

# Disable report
python3 check-prefixes.py -r prefixes.txt --report-file -

# List supported providers
python3 check-prefixes.py --providers-list

Output Example

195.234.187.0/24: Propagated as 195.234.187.0/24 via RIPEstat,BGPView | origin(s): AS47886 (EQUINIX-NL-ASN)

