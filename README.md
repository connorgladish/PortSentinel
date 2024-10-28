## Changelog

```
10/26/24
[v0.4] Added Multithreading
```
  
   
# PortSentinel (PortSent)

![PortSent](images/1portsenticon.png)

**PortSentinel**, also known as **PortSent**, is a lightweight port scanner designed to help you identify open ports on a target IP address. It provides actionable security recommendations for each open port, and also fetches geolocation information for the target. With options for scanning custom port ranges, commonly vulnerable ports, and outputting results in formats like JSON or CSV, PortSent is a versatile tool for network security enthusiasts and professionals.

## Features

- **Port Scanning**: Scan a specific range of ports or use the `--common` flag to scan the most commonly vulnerable ports (like FTP, SSH, HTTP, etc.).
- **Geolocation Information**: Automatically fetches the city, region, and country of the target IP using geolocation services.
- **Security Recommendations**: Provides security recommendations for each open port based on industry best practices.
- **Customizable Output Formats**: Export scan results in **JSON** or **CSV** formats for easy integration with other tools or reporting.
- **Common Vulnerable Ports Scan**: Quickly scan ports that are commonly exploited in real-world attacks, such as FTP (21), SSH (22), HTTP (80), HTTPS (443), SMB (445), and more.

## Installation

1. **Clone the Repository**:

   ```bash
   git clone https://github.com/connorgladish/portsentinel.git
   cd portsentinel
   ```

2. **Install Dependencies**:

   ```bash
   pip install -r requirements.txt
   ```

   Make sure you have Python 3.x installed.

3. **Make the Script Executable** (Optional):

   ```bash
   chmod +x portsent.py
   ```

4. **Move to Global Path** (Optional):

   To make it available globally, you can move the script to `/usr/local/bin/`:

   ```bash
   sudo mv portsent.py /usr/local/bin/portsent
   ```

## Usage

### Basic Port Scan

To perform a basic port scan on a target IP (default scans ports 1-65535):

```bash
python3 portsent.py <TARGET_IP>
```

### Scan a Specific Port Range

```bash
python3 portsent.py <TARGET_IP> -p 1-100
```

### Scan Common Vulnerable Ports

To scan the most commonly vulnerable ports:

```bash
python3 portsent.py <TARGET_IP> --common
```

### Output to JSON or CSV

You can specify output formats using `-f` and save the results to a file using `-o`:

- **JSON** format:
  ```bash
  python3 portsent.py <TARGET_IP> --common -o scan_results.json -f json
  ```

- **CSV** format:
  ```bash
  python3 portsent.py <TARGET_IP> -p 1-100 -o scan_results.csv -f csv
  ```

### Example Output

```
{
    "target": "192.168.1.1",
    "geolocation": "Nashville, Tennessee, US",
    "open_ports": [
        {
            "port": 22,
            "status": "open",
            "recommendation": "SSH: Disable password-based authentication. Use SSH keys instead. Consider moving SSH to a non-standard port."
        },
        {
            "port": 80,
            "status": "open",
            "recommendation": "HTTP: Redirect traffic to HTTPS. Use an SSL certificate to secure web traffic."
        }
    ]
}
```

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

## Contributing

Contributions are welcome! Feel free to submit a pull request or open an issue to report any bugs or suggest new features.

## Support

If you encounter any issues, feel free to reach out via GitHub issues.

## Disclaimer

This tool is intended for educational purposes and ethical use only. Always ensure you have permission before scanning a network or device. Misuse of this tool may violate laws or regulations.
