import socket
import argparse
import requests
import csv
import json

# List of common vulnerable ports often targeted in exploits
COMMON_VULNERABLE_PORTS = [
    21,   # FTP
    22,   # SSH
    23,   # Telnet
    25,   # SMTP
    53,   # DNS
    80,   # HTTP
    110,  # POP3
    139,  # NetBIOS
    143,  # IMAP
    443,  # HTTPS
    445,  # SMB
    3389, # RDP
    3306, # MySQL
    5900, # VNC
    8080, # HTTP Alternate
    8443, # HTTPS Alternate
    1723, # PPTP
    5432, # PostgreSQL
    3307, # MySQL Alternate
    8888, # HTTP Alternate
    6379, # Redis
    27017, # MongoDB
    11211, # Memcached
    1521, # Oracle DB
    69,   # TFTP
    465,  # SMTPS
    993,  # IMAPS
    995,  # POP3S
    587,  # SMTP (TLS)
    1883, # MQTT
    6660, # IRC
    6667, # IRC (standard)
    6697, # IRC (SSL)
    8081, # HTTP Alternate
    9090, # Web Admin
    10000 # Webmin
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

# Function to scan a single port
def scan_port(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # Timeout for the connection attempt
        result = sock.connect_ex((ip, port))  # Try to connect to the port
        if result == 0:
            return {"port": port, "status": "open", "recommendation": port_recommendations(port)}
        sock.close()
    except socket.error:
        return None
    return None

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
        161: "SNMP: Disable or limit SNMP access. Ensure strong community strings or move to SNMPv3 for encryption.",
        162: "SNMP Trap: Secure SNMP traps by enabling authentication. Restrict traps to trusted systems.",
        587: "SMTP (TLS): Ensure that STARTTLS is enforced. Consider restricting to authenticated users only.",
        993: "IMAPS: Use SSL/TLS to secure IMAP communication. Ensure that weak ciphers are disabled.",
        995: "POP3S: Use SSL/TLS to secure POP3 communication. Avoid using weak encryption ciphers.",
        8080: "HTTP-Alt: Redirect traffic to port 443 and use SSL certificates for all web communication.",
        69: "TFTP: Disable TFTP if not in use. Use SFTP or FTPS for secure file transfers.",
        8888: "Alternate HTTP: Ensure HTTPS is enforced and certificates are up to date.",
        5432: "PostgreSQL: Restrict access to the database server. Ensure strong passwords and encryption.",
        3307: "MySQL-Alt: Apply the same security practices as for MySQL (port 3306), such as limiting trusted IPs.",
        5900: "VNC: Avoid exposing VNC over public networks. Use a VPN or secure tunneling like SSH.",
        6379: "Redis: Avoid exposing Redis without authentication. Use firewall rules to limit access to trusted IPs.",
        27017: "MongoDB: Secure MongoDB with authentication and ensure it's only accessible over a VPN or trusted network.",
        11211: "Memcached: Do not expose Memcached to public networks. Enable firewalls to restrict access to trusted IPs.",
        1521: "Oracle DB: Ensure that Oracle listeners require authentication and are secured with encryption.",
        1723: "PPTP: Avoid using PPTP due to known security vulnerabilities. Use modern VPN protocols like OpenVPN or WireGuard.",
        25565: "Minecraft: Secure Minecraft servers with a firewall and ensure server software is up to date to avoid vulnerabilities.",
        6697: "IRC (SSL): Ensure SSL is used for secure communication over IRC and weak ciphers are disabled.",
        10000: "Webmin: Avoid exposing Webmin to the public internet. Use strong passwords and secure with SSL certificates.",
        5000: "Flask (Dev): Ensure Flask is only used for development locally and not exposed publicly.",
        22: "SSH: Enforce key-based authentication and disable password authentication. Consider changing the default SSH port.",
    }
    
    # Default message if no specific recommendation exists
    return recommendations.get(port, "No specific recommendation available for this port.")

# Function to scan a range of ports or common vulnerable ports
def scan_ports(ip, port_range=None, common_ports=False):
    open_ports = []
    if common_ports:
        ports_to_scan = COMMON_VULNERABLE_PORTS
    else:
        start_port, end_port = map(int, port_range.split('-'))  # Split the range into start and end
        ports_to_scan = range(start_port, end_port + 1)

    for port in ports_to_scan:
        result = scan_port(ip, port)
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
        writer = csv.DictWriter(file, fieldnames=["port", "status", "recommendation"])
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
