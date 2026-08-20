import ipaddress
import socket
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

def validate_target(target):
    try:
        ipaddress.ip_address(target)
        return True

    except ValueError:
        try:
            socket.gethostbyname(target)
            return True

        except socket.gaierror:
            return False

def scan_ports(target, ports, timeout=0.5):
    open_ports = []

    try:
        ip = socket.gethostbyname(target)

    except socket.gaierror:
        return open_ports

    for port in ports:
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                open_ports.append(port)

        except (socket.timeout, socket.error, OSError):
            pass

    return open_ports

def grab_banner(target, port, timeout=2):
    try:
        ip = socket.gethostbyname(target)

        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)

            try:
                banner = sock.recv(1024).decode(
                    "utf-8",
                    errors="ignore"
                ).strip()

                return banner

            except socket.timeout:
                return ""

    except (socket.timeout, socket.error, OSError):
        return ""

def detect_services(target, open_ports):
    services = []

    common_services = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        139: "NetBIOS/SMB",
        443: "HTTPS",
        445: "SMB"
    }

    for port in open_ports:
        service_name = common_services.get(port, "Unknown")
        banner = grab_banner(target, port)

        services.append({
            "port": port,
            "service": service_name,
            "banner": banner
        })

    return services

def detect_http(target, open_ports):
    web_services = []

    if 80 in open_ports:
        web_services.append({
            "scheme": "http",
            "url": f"http://{target}"
        })

    if 443 in open_ports:
        web_services.append({
            "scheme": "https",
            "url": f"https://{target}"
        })

    return web_services

def http_recon(url, timeout=5):
    result = {
        "url": url,
        "status_code": None,
        "headers": {},
        "server": None,
        "powered_by": None,
        "content_type": None,
        "error": None
    }

    try:
        response = requests.get(
            url,
            timeout=timeout,
            allow_redirects=True
        )

        result["url"] = response.url
        result["status_code"] = response.status_code
        result["headers"] = dict(response.headers)

        result["server"] = response.headers.get("Server")
        result["powered_by"] = response.headers.get("X-Powered-By")
        result["content_type"] = response.headers.get("Content-Type")

    except requests.RequestException as e:
        result["error"] = str(e)

    return result

def crawl_endpoints(url, timeout=5):
    endpoints = set()

    try:
        response = requests.get(
            url,
            timeout=timeout,
            allow_redirects=True
        )

        base_url = response.url
        parsed_base = urlparse(base_url)

        endpoints.add(base_url)

        soup = BeautifulSoup(response.text, "html.parser")

        for link in soup.find_all("a", href=True):
            href = link["href"]

            full_url = urljoin(base_url, href)
            parsed_url = urlparse(full_url)

            if parsed_url.netloc == parsed_base.netloc:
                endpoints.add(full_url)

    except requests.RequestException:
        pass

    return sorted(endpoints)

def detect_os_clues(services, http_results):
    clues = []

    for service in services:
        banner = service["banner"].lower()

        if "ubuntu" in banner:
            clues.append({
                "os_family": "Linux",
                "os_clue": "Ubuntu",
                "confidence": "Medium",
                "source": f"{service['service']} banner"
            })

        elif "debian" in banner:
            clues.append({
                "os_family": "Linux",
                "os_clue": "Debian",
                "confidence": "Medium",
                "source": f"{service['service']} banner"
            })

    for http_info in http_results:
        server = (http_info["server"] or "").lower()

        if "ubuntu" in server:
            clues.append({
                "os_family": "Linux",
                "os_clue": "Ubuntu",
                "confidence": "Medium",
                "source": "HTTP Server header"
            })

    return clues

def run_recon_scan(target):
    result = {
        "module": "recon",
        "target": target,
        "status": "success",
        "host": {
            "reachable": False,
            "os_clues": []
        },
        "ports": [],
        "services": [],
        "web_services": [],
        "http_results": [],
        "endpoints": [],
        "findings": [],
        "errors": []
    }

    # -------------------------
    # Target validation
    # -------------------------

    if not validate_target(target):
        result["status"] = "error"
        result["errors"].append("Invalid target")
        return result

    # -------------------------
    # Port scanning
    # -------------------------

    ports = [
        21, 22, 23, 25, 53,
        80, 110, 139, 443, 445
    ]

    open_ports = scan_ports(target, ports)

    result["ports"] = open_ports

    if not open_ports:
        result["host"]["reachable"] = False
        result["status"] = "error"
        result["errors"].append("No open ports found")
        return result

    result["host"]["reachable"] = True

    # -------------------------
    # Service detection
    # -------------------------

    services = detect_services(target, open_ports)
    result["services"] = services

    # -------------------------
    # Web service detection
    # -------------------------

    web_services = detect_http(target, open_ports)
    result["web_services"] = web_services

    # -------------------------
    # HTTP Recon + Crawling
    # -------------------------

    http_results = []

    for web in web_services:

        http_info = http_recon(web["url"])

        http_results.append(http_info)

        endpoints = crawl_endpoints(web["url"])

        result["endpoints"].extend(endpoints)

    result["http_results"] = http_results

    # Remove duplicate endpoints
    result["endpoints"] = sorted(set(result["endpoints"]))

    # -------------------------
    # OS Clues
    # -------------------------

    os_clues = detect_os_clues(
        services,
        http_results
    )

    result["host"]["os_clues"] = os_clues

    return result

if __name__ == "__main__":

    target = "192.168.220.128"

    print("[+] Target is valid")

    recon_data = run_recon_scan(target)

    if recon_data["status"] == "error":

        print(f"[-] Recon failed")

        for error in recon_data["errors"]:
            print(f"    Error: {error}")

    else:

        print("\n[+] Host is reachable")

        print("\n[+] Open ports:")

        for port in recon_data["ports"]:
            print(f"    - {port}")

        # -------------------------
        # Services
        # -------------------------

        print("\n[+] Service Detection")

        for service in recon_data["services"]:

            print(f"\n    Port: {service['port']}")
            print(f"    Service: {service['service']}")

            if service["banner"]:
                print(f"    Banner: {service['banner']}")
            else:
                print("    Banner: Not available")

        # -------------------------
        # Web Services
        # -------------------------

        print("\n[+] Web Services")

        if recon_data["web_services"]:

            for web in recon_data["web_services"]:
                print(
                    f"    {web['scheme'].upper()} → "
                    f"{web['url']}"
                )

        else:
            print("    No web services found")

        # -------------------------
        # HTTP Recon
        # -------------------------

        print("\n[+] HTTP Recon")

        for http_info in recon_data["http_results"]:

            print(f"\n    URL: {http_info['url']}")
            print(
                f"    Status Code: "
                f"{http_info['status_code']}"
            )
            print(
                f"    Server: "
                f"{http_info['server']}"
            )
            print(
                f"    X-Powered-By: "
                f"{http_info['powered_by']}"
            )
            print(
                f"    Content-Type: "
                f"{http_info['content_type']}"
            )

            if http_info["error"]:
                print(
                    f"    Error: "
                    f"{http_info['error']}"
                )

        # -------------------------
        # Endpoint Crawling
        # -------------------------

        print("\n[+] Endpoint Crawling")

        if recon_data["endpoints"]:

            for endpoint in recon_data["endpoints"]:
                print(f"    - {endpoint}")

        else:
            print("    No endpoints found")

        # -------------------------
        # OS Clues
        # -------------------------

        print("\n[+] OS Clues")

        if recon_data["host"]["os_clues"]:

            for clue in recon_data["host"]["os_clues"]:

                print(
                    f"    OS Family: "
                    f"{clue['os_family']}"
                )

                print(
                    f"    OS Clue: "
                    f"{clue['os_clue']}"
                )

                print(
                    f"    Confidence: "
                    f"{clue['confidence']}"
                )

                print(
                    f"    Source: "
                    f"{clue['source']}"
                )

        else:
            print("    No OS clues found")