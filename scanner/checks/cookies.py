from ..findings import add_finding
def check_cookie_security(cookies):
    cookie_pass_count = 0
    for cookie in cookies:
        print(cookie.name)

        # SameSite check
        if cookie._rest.get("SameSite"):
            print(f"[PASS] {cookie.name}: SameSite attribute is present")
            cookie_pass_count += 1
        else:
            print(f"[WARN] {cookie.name}: SameSite attribute is not present")
            add_finding(
                "Cookie Missing SameSite Attribute",
                "Low",
                cookie.name,
                "Configure an appropriate SameSite attribute for the cookie"
            )

        # Secure check
        if cookie.secure:
            print(f"[PASS] {cookie.name}: secure flag is present")
            cookie_pass_count += 1
        else:
            print(f"[WARN] {cookie.name}: secure flag is not present")
            add_finding(
                "Cookie Missing Secure Flag",
                "Medium",
                cookie.name,
                "Set the Secure flag on the cookie"
            )

        # HttpOnly check
        if cookie.has_nonstandard_attr("HttpOnly"):
            print(f"[PASS] {cookie.name}: HttpOnly flag is present")
            cookie_pass_count += 1
        else:
            print(f"[WARN] {cookie.name}: HttpOnly flag is missing")
            add_finding(
                "Cookie Missing HttpOnly Flag",
                "Medium",
                cookie.name,
                "Set the HttpOnly flag on the cookie"
            )
    return cookie_pass_count