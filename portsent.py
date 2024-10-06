import socket
import argparse
import requests
import csv
import json
import concurrent.futures

# List of common vulnerable ports often targeted in exploits
COMMON_VULNERABLE_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389, 3306, 5900, 8080,
    8443, 1723, 5432, 3307, 8888, 6379, 27017, 11211, 1521, 69, 465, 993, 995, 
    587, 1883, 6660, 6667, 6697, 8081, 9090, 10000
]

# Function to get user input for target IP, port range, and output file/format
def get_arguments():
    parser = argparse.ArgumentParser(description="A port scanner with security recommendations, geolocation, common ports scanning, and output formats (JSON/CSV)")
    parser.add_argument("target", help="Target IP address to scan")
    parser.add_argument("-p", "--ports", help="Port range to scan (e.g., 1-1000)", default=None)
    parser.add_argument("-o", "--output", help="Output file to save scan results", default=None)
    parser.add_argument("-f", "--format", help="Output format (json or csv)", choices=["json", "csv"], default="json")
    parser.add_argument("--common", help="Scan the most commonly vulnerable ports", action="store_true")
    args = parser.parse_args()
    return args.target, args.ports, args.output, args.format, args.common

# Function to define recommendations for specific ports
def port_recommendations(port):
    recommendations = {
        22: "SSH: Disable password-based authentication. Use SSH keys instead. Consider moving SSH to a non-standard port.",
        80: "HTTP: Redirect traffic to HTTPS. Use an SSL certificate to secure web traffic.",
        443: "HTTPS: Ensure SSL/TLS certificates are up to date and use strong ciphers.",
        445: "SMB: Disable SMB if not in use. Apply the latest Windows patches to prevent exploits like EternalBlue.",
        21: "FTP: Use SFTP or FTPS instead of plain FTP. Ensure strong authentication mechanisms are in place.",
        3389: "RDP: Use a VPN to restrict access to RDP services. Ensure multi-factor authentication is enabled.",
        3306: "MySQL: Limit access to trusted IP addresses. Ensure the MySQL instance is secured with strong passwords.",
        25: "SMTP: Use STARTTLS or SSL/TLS for email communication. Restrict open relays to prevent abuse.",
        110: "POP3: Transition to more secure email retrieval methods such as IMAP over SSL/TLS.",
        143: "IMAP: Ensure IMAP is secured with SSL/TLS and consider moving to encrypted mail protocols.",
        53: "DNS: Consider using DNSSEC to secure DNS requests. Restrict access to DNS servers from external networks.",
        587: "SMTP (TLS): Ensure that STARTTLS is enforced. Consider restricting to authenticated users only.",
        993: "IMAPS: Use SSL/TLS to secure IMAP communication. Ensure that weak ciphers are disabled.",
        995: "POP3S: Use SSL/TLS to secure POP3 communication. Avoid using weak encryption ciphers.",
        8080: "HTTP-Alt: Redirect traffic to port 443 and use SSL certificates for all web communication.",
        5432: "PostgreSQL: Restrict access to the database server. Ensure strong passwords and encryption.",
        6379: "Redis: Avoid exposing Redis without authentication. Use firewall rules to limit access to trusted IPs.",
        27017: "MongoDB: Secure MongoDB with authentication and ensure it's only accessible over a VPN or trusted network.",
        11211: "Memcached: Do not expose Memcached to public networks. Enable firewalls to restrict access to trusted IPs."
    }
    
    return recommendations.get(port, "No specific recommendation available for this port.")

# Function to scan a single port with service detection
def scan_port(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        sock.close()
        
        if result == 0:
            # Detect service
            try:
                service = socket.getservbyport(port)
            except OSError:
                service = "Unknown service"
            
            return {
                "port": port,
                "status": "open",
                "service": service,
                "recommendation": port_recommendations(port)
            }
    except socket.error:
        return None
    return None

# Function to scan ports with multithreading
def scan_ports(ip, port_range=None, common_ports=False):
    open_ports = []
    
    if common_ports:
        ports_to_scan = COMMON_VULNERABLE_PORTS
    else:
        start_port, end_port = map(int, port_range.split('-'))
        ports_to_scan = range(start_port, end_port + 1)
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        futures = [executor.submit(scan_port, ip, port) for port in ports_to_scan]
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)
    
    return open_ports

# Function to get geolocation information
def get_geolocation(ip):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json")
        data = response.json()
        location = data.get('city', 'Unknown City') + ", " + data.get('region', 'Unknown Region') + ", " + data.get('country', 'Unknown Country')
        return location
    except requests.exceptions.RequestException:
        return "Geolocation not available."

# Function to save results in JSON format
def save_json(output_file, scan_data):
    with open(output_file, 'w') as file:
        json.dump(scan_data, file, indent=4)
    print(f"Results saved in JSON format to {output_file}")

# Function to save results in CSV format
def save_csv(output_file, scan_data):
    with open(output_file, 'w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=["port", "status", "service", "recommendation"])
        writer.writeheader()
        writer.writerows(scan_data)
    print(f"Results saved in CSV format to {output_file}")

# Main function
if __name__ == "__main__":
    target, port_range, output, output_format, common_ports = get_arguments()

    # Get geolocation data for the target
    location = get_geolocation(target)
    print(f"Geolocation of {target}: {location}\n")

    # Start scanning ports based on either the range or common vulnerable ports
    if common_ports:
        print(f"Scanning most commonly vulnerable ports on {target}...\n")
    scan_data = scan_ports(target, port_range, common_ports)

    # Prepare final data with geolocation included
    final_data = {
        "target": target,
        "geolocation": location,
        "open_ports": scan_data
    }

    # Output results to file or print to console
    if output:
        if output_format == "json":
            save_json(output, final_data)
        elif output_format == "csv":
            save_csv(output, scan_data)
    else:
        print(json.dumps(final_data, indent=4))
