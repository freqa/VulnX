import requests

def check_http_methods(target):
    try:
        response = requests.options(target, timeout=5)

        allow_header = response.headers.get("Allow")

        if allow_header:
            print(f"[INFO] Allowed HTTP methods: {allow_header}")
        else:
            print("[INFO] Allow header is not present")

    except requests.exceptions.RequestException as error:
        print(f"[ERROR] HTTP method check failed: {error}")