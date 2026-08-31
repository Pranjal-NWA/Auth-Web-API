from pathlib import Path
import sys
import uuid
import requests
import urllib3
import json

def load_settings():
    settings_path = Path(__file__).parent.parent/"appsettings.Testing.json"
    if not settings_path.exists():
        print(f"FAIL: settings file not found at {settings_path}")
        sys.exit(1)
    with open(settings_path) as f:
        return json.load(f)

settings = load_settings()
BASE_URL = settings["BASE_URL"]

PASSWORD = "Testpass1!"
WRONG_PASSWORD = "WrongPassword1!"

SIGNUP_ENDPOINT = f"{BASE_URL}/api/v1/auth/signup"
LOGIN_ENDPOINT = f"{BASE_URL}/api/v1/auth/login"


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def main():
    email = f"lockout-{uuid.uuid4()}@example.com"

    session = requests.Session()

    print(f"Creating smoke-test account: {email}")

    # ---------------------------------------------------------
    # 1. Create a dedicated smoke-test account
    # ---------------------------------------------------------
    try:
        signup_response = session.post(
            SIGNUP_ENDPOINT,
            json={
                "email": email,
                "password": PASSWORD,
            },
            verify=False,
            timeout=10,
        )
    except requests.RequestException as exc:
        print(f"FAIL: signup request failed: {exc}")
        sys.exit(1)

    if signup_response.status_code != 201:
        print(
            f"FAIL: signup returned "
            f"{signup_response.status_code}: "
            f"{signup_response.text}"
        )
        sys.exit(1)

    print("Signup successful.")

    # ---------------------------------------------------------
    # 2. Perform repeated failed login attempts
    # ---------------------------------------------------------
    locked = False

    for attempt in range(1, 8):
        try:
            response = session.post(
                LOGIN_ENDPOINT,
                json={
                    "email": email,
                    "password": WRONG_PASSWORD,
                },
                verify=False,
                timeout=10,
            )
        except requests.RequestException as exc:
            print(
                f"FAIL: login request failed on attempt "
                f"{attempt}: {exc}"
            )
            sys.exit(1)

        print(
            f"Wrong-password attempt {attempt}: "
            f"HTTP {response.status_code}"
        )

        # Your application is configured with:
        # MaxFailedAccessAttempts = 5
        if response.status_code == 423:
            locked = True
            break

    if not locked:
        print("FAIL: account was not locked after repeated failures.")
        sys.exit(1)

    print("PASS: account is locked.")

    # ---------------------------------------------------------
    # 3. Verify correct password is also rejected
    # ---------------------------------------------------------
    try:
        response = session.post(
            LOGIN_ENDPOINT,
            json={
                "email": email,
                "password": PASSWORD,
            },
            verify=False,
            timeout=10,
        )
    except requests.RequestException as exc:
        print(
            f"FAIL: correct-password request failed: {exc}"
        )
        sys.exit(1)

    print(
        f"Correct-password attempt after lockout: "
        f"HTTP {response.status_code}"
    )

    if response.status_code != 423:
        print(
            "FAIL: correct password was accepted after lockout."
        )
        sys.exit(1)

    print(
        "PASS: correct password is rejected while account is locked."
    )

    print()
    print("========================================")
    print("BRUTE-FORCE LOCKOUT SMOKE TEST PASSED")
    print("========================================")


if __name__ == "__main__":
    main()