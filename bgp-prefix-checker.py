
import requests

def fetch_advertised_prefix(ip):
    """Fetch the advertised prefix for an IP using RIPEstat's prefix-overview API."""
    url = f"https://stat.ripe.net/data/prefix-overview/data.json"
    params = {"resource": ip}
    response = requests.get(url, params=params)
    if response.status_code != 200:
        raise Exception(f"Failed to fetch prefix data: {response.text}")
    data = response.json()
    
    # Check if there are announced prefixes
    if data.get("data", {}).get("announced"):
        prefixes = data["data"]["announced_space"]
        return prefixes[0] if prefixes else None

    # Fallback to block information if no prefix is announced
    block_info = data["data"].get("block", {})
    return block_info.get("resource")

def fetch_prefix_status(prefix):
    """Check if a prefix is announced in the global BGP table using RIPEstat API."""
    url = f"https://stat.ripe.net/data/bgp-state/data.json"
    params = {"resource": prefix}
    response = requests.get(url, params=params)
    if response.status_code != 200:
        raise Exception(f"Failed to fetch prefix data: {response.text}")
    data = response.json()
    visibility = data.get("data", {}).get("visibility", 0)
    return visibility > 0

def check_prefixes(ip_list):
    """Check if each IP's prefix is propagated globally."""
    results = {}
    for ip in ip_list:
        try:
            prefix = fetch_advertised_prefix(ip)
            if prefix:
                is_visible = fetch_prefix_status(prefix)
                results[ip] = (
                    f"Propagated as {prefix}" if is_visible else f"Not Propagated ({prefix})"
                )
            else:
                results[ip] = "No advertised prefix found"
        except Exception as e:
            results[ip] = f"Error: {e}"
    return results

def read_ip_list(file_path):
    """Read IP addresses from a file."""
    try:
        with open(file_path, "r") as file:
            ip_list = [line.strip() for line in file if line.strip()]
        return ip_list
    except Exception as e:
        print(f"Error reading file: {e}")
        return []

if __name__ == "__main__":
    # Specify the file containing IP addresses
    file_path = "ip_addresses.txt"  # Replace with your file path

    print("Reading IP addresses from file...")
    ip_list = read_ip_list(file_path)

    if not ip_list:
        print("No IP addresses found in the file. Exiting.")
    else:
        print("Checking IP prefixes...")
        results = check_prefixes(ip_list)

        print("\nResults:")
        for ip, status in results.items():
            print(f"{ip}: {status}")
