from ..findings import findings
def check_redirect(response, target):
        if response.history:
              print("[INFO] Target redirected")
              for redirect in response.history:
                  print(f"[INFO] Redirected to: {redirect.url} with status code: {redirect.status_code}")
        else:
             print("[INFO] No redirect detected")

        print(f"Final URL: {response.url}")

        if target.startswith("https://") and response.url.startswith("http://"):
             print("[WARN] HTTPS target redirected to HTTP")
             findings.add_finding(
                "HTTPS to HTTP Redirect",
                "High",
                response.url,
                "Ensure HTTPS requests remain on HTTPS and are not redirected to HTTP"
           )