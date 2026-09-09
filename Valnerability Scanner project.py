import socket
import ssl
import urllib.request
from datetime import datetime

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt"
}

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options"
]

# This is intentionally small and illustrative.
# A production scanner should use a maintained vulnerability database.
KNOWN_RISKY_BANNERS = {
    "Apache/2.2": "Potentially outdated Apache version",
    "nginx/1.10": "Potentially outdated nginx version",
    "OpenSSH_6.": "Potentially outdated OpenSSH version"
}


def scan_port(host, port, timeout=0.5):
    """Return True if a TCP connection can be established."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        result = sock.connect_ex((host, port))
        return result == 0
    except socket.error:
        return False
    finally:
        sock.close()


def get_banner(host, port, timeout=2):
    """Attempt to retrieve a basic service banner."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        sock.connect((host, port))

        # Some services send a banner immediately.
        try:
            data = sock.recv(1024)
            if data:
                return data.decode(errors="ignore").strip()
        except socket.timeout:
            pass

        # HTTP services can be queried with a simple request.
        if port in (80, 8080):
            request = f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n"
            sock.sendall(request.encode())
            data = sock.recv(2048)
            return data.decode(errors="ignore").strip()

    except (socket.error, OSError):
        return None
    finally:
        sock.close()

    return None


def check_http_headers(host, port):
    """Check common HTTP security headers."""
    scheme = "https" if port == 443 else "http"
    url = f"{scheme}://{host}"

    try:
        if scheme == "https":
            context = ssl.create_default_context()
            request = urllib.request.Request(
                url,
                method="HEAD",
                headers={"User-Agent": "MiniVulnerabilityScanner/1.0"}
            )

            with urllib.request.urlopen(
                request, timeout=4, context=context
            ) as response:
                headers = response.headers

        else:
            request = urllib.request.Request(
                url,
                method="HEAD",
                headers={"User-Agent": "MiniVulnerabilityScanner/1.0"}
            )

            with urllib.request.urlopen(request, timeout=4) as response:
                headers = response.headers

        missing = [
            header for header in SECURITY_HEADERS
            if header not in headers
        ]

        return missing

    except Exception:
        return None


def generate_report(host, open_ports, findings):
    filename = "vulnerability_report.txt"

    with open(filename, "w", encoding="utf-8") as report:
        report.write("VULNERABILITY SCANNER REPORT\n")
        report.write("=" * 40 + "\n")
        report.write(f"Target: {host}\n")
        report.write(
            f"Scan time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        )

        report.write("OPEN PORTS\n")
        report.write("-" * 40 + "\n")

        if open_ports:
            for port, service in open_ports:
                report.write(f"{port}/TCP - {service}\n")
        else:
            report.write("No scanned ports were found open.\n")

        report.write("\nFINDINGS\n")
        report.write("-" * 40 + "\n")

        if findings:
            for finding in findings:
                report.write(f"- {finding}\n")
        else:
            report.write("No issues detected by the basic checks.\n")

    print(f"\nReport saved to: {filename}")


def main():
    print("=== Mini Vulnerability Scanner ===")

    host = input("Enter target hostname/IP: ").strip()

    try:
        socket.gethostbyname(host)
    except socket.gaierror:
        print("Invalid or unreachable hostname.")
        return

    open_ports = []
    findings = []

    print(f"\nScanning {host}...\n")

    for port, service in COMMON_PORTS.items():
        if scan_port(host, port):
            print(f"[OPEN] {port}/TCP - {service}")
            open_ports.append((port, service))

    # Banner analysis
    for port, service in open_ports:
        banner = get_banner(host, port)

        if banner:
            print(f"[INFO] {port}: {banner[:100]}")

            for pattern, warning in KNOWN_RISKY_BANNERS.items():
                if pattern.lower() in banner.lower():
                    findings.append(
                        f"{warning} detected on port {port}: {banner[:100]}"
                    )

    # HTTP header analysis
    for port, service in open_ports:
        if port in (80, 443, 8080):
            missing = check_http_headers(host, port)

            if missing is not None:
                for header in missing:
                    finding = (
                        f"Missing HTTP security header '{header}' "
                        f"on port {port}"
                    )
                    findings.append(finding)
                    print(f"[WARNING] {finding}")

    generate_report(host, open_ports, findings)


if __name__ == "__main__":
    main()