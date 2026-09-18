import ssl
import socket

from ..findings import add_finding


def check_tls_version(target):
    hostname = target.replace("https://", "").split("/")[0]

    try:
        context = ssl.create_default_context()

        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls_socket:
                version = tls_socket.version()

                print(f"[INFO] TLS version: {version}")

                if version in ["TLSv1.2", "TLSv1.3"]:
                    print("[PASS] Secure TLS version detected")
                else:
                    print("[WARN] Older TLS version detected")

                    add_finding(
                        "Weak TLS Version",
                        "High",
                        version,
                        "Use TLS 1.2 or TLS 1.3 and disable older TLS versions"
                    )

    except Exception as error:
        print(f"[ERROR] TLS check failed: {error}")