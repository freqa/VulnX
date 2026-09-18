from ..findings import add_finding


def check_security_header(headers, header_name, severity, recommendation):
    if headers.get(header_name):
        print(f"[PASS] {header_name} is present")
    else:
        print(f"[WARN] {header_name} is missing")

        add_finding(
            f"{header_name} header is missing",
            severity,
            f"{header_name} header is missing",
            recommendation
        )


def check_frame_options(headers):
    if headers.get("X-Frame-Options") in ["DENY", "SAMEORIGIN"]:
        print("X-Frame-Options header is present and correctly configured")
        return 1
    else:
        print("X-Frame-Options header is not present or not correctly configured")

        add_finding(
            "X-Frame-Options header is missing or misconfigured",
            "Medium",
            "X-Frame-Options header is missing or misconfigured",
            "Configure the X-Frame-Options header to prevent clickjacking attacks"
        )

        return 0


def check_csp(headers):
    csp = headers.get("Content-Security-Policy")

    if csp:
        if "unsafe-inline" in csp:
            print("[WARN] CSP contains unsafe-inline")

            add_finding(
                "CSP allows unsafe-inline",
                "Medium",
                "unsafe-inline is present in the Content-Security-Policy header",
                "Remove unsafe-inline from the CSP if it is not required by the application"
            )

        if "unsafe-eval" in csp:
            print("[WARN] CSP contains unsafe-eval")

            add_finding(
                "CSP allows unsafe-eval",
                "Medium",
                "unsafe-eval is present in the Content-Security-Policy header",
                "Remove unsafe-eval from the CSP if it is not required by the application"
            )


def check_content_type_options(headers):
    if headers.get("X-Content-Type-Options") == "nosniff":
        print("X-Content-Type-Options is correctly configured")
        return 1
    else:
        print("X-Content-Type-Options is not correctly configured")

        add_finding(
            "X-Content-Type-Options header is missing or misconfigured",
            "Medium",
            "X-Content-Type-Options header is missing or misconfigured",
            "Configure the X-Content-Type-Options header to prevent MIME type sniffing attacks"
        )

        return 0
    
def check_information_disclosure(headers):
    disclosure_headers = [
        "Server",
        "X-Powered-By",
        "Via"
    ]

    for header in disclosure_headers:
        value = headers.get(header)

        if value:
            print(f"[WARN] {header} is exposed: {value}")

            add_finding(
                f"{header} Information Disclosure",
                "Low",
                value,
                f"Consider removing or minimizing the {header} response header"
            )
        else:
            print(f"[PASS] {header} is not exposed")
def check_sensitive_headers(headers):
    sensitive_headers = [
        "X-AspNet-Version",
        "X-AspNetMvc-Version",
        "X-Generator"
    ]

    for header in sensitive_headers:
        value = headers.get(header)

        if value:
            print(f"[WARN] {header} is exposed: {value}")

            add_finding(
                f"{header} Information Disclosure",
                "Low",
                value,
                f"Consider removing the {header} response header"
            )
        else:
            print(f"[PASS] {header} is not exposed")