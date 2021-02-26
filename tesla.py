import argparse
import base64
import hashlib
import os
import re
import time
from urllib.parse import parse_qs

import requests
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait

MAX_ATTEMPTS = 7
CLIENT_ID = "81527cff06843c8634fdc09e8ac0abefb46ac849f38fe1e431c2ef2106796384"
UA = "Mozilla/5.0 (Linux; Android 10; Pixel 3 Build/QQ2A.200305.002; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/85.0.4183.81 Mobile Safari/537.36"
X_TESLA_USER_AGENT = "TeslaApp/3.10.9-433/adff2e065/android/10"


def gen_params():
    verifier_bytes = os.urandom(86)
    code_verifier = base64.urlsafe_b64encode(verifier_bytes).rstrip(b"=")
    code_challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier).digest()).rstrip(b"=")
    state = base64.urlsafe_b64encode(os.urandom(16)).rstrip(b"=").decode("utf-8")
    return code_verifier, code_challenge, state


def create_driver():
    options = webdriver.ChromeOptions()
    options.headless = True
    driver = webdriver.Chrome(options=options)
    driver.execute_cdp_cmd("Network.setUserAgentOverride", {"userAgent": UA})
    return driver


def login(args):
    email, password = args.email, args.password
    session, resp, params, code_verifier = (None,) * 4
    vprint = print if args.verbose else lambda _: None

    headers = {
        "User-Agent": UA,
        "x-tesla-user-agent": X_TESLA_USER_AGENT,
        "X-Requested-With": "com.teslamotors.tesla",
    }

    # Step 1: Obtain the login page
    code_verifier, code_challenge, state = gen_params()

    params = (
        ("audience", ""),
        ("client_id", "ownerapi"),
        ("code_challenge", code_challenge),
        ("code_challenge_method", "S256"),
        ("locale", "en"),
        ("prompt", "login"),
        ("redirect_uri", "https://auth.tesla.com/void/callback"),
        ("response_type", "code"),
        ("scope", "openid email offline_access"),
        ("state", state),
    )

    session = requests.Session()
    resp = session.get("https://auth.tesla.com/oauth2/v3/authorize", headers=headers, params=params)

    if "<title>" not in resp.text:
        # response contains js, running headless chrome then
        driver = create_driver()
        driver.get(resp.request.url)
        WebDriverWait(driver, 20).until(EC.presence_of_element_located((By.CSS_SELECTOR, "input[name=identity]")))

        # inject browser cookies to requests.Session
        for cookie in driver.get_cookies():
            session.cookies.set(cookie["name"], cookie["value"])

        csrf = driver.find_element_by_css_selector("input[name=_csrf]").get_attribute("value")
        transaction_id = driver.find_element_by_css_selector("input[name=transaction_id]").get_attribute("value")
        driver.quit()

    else:
        # response is ok, contains csrf and transaction_id
        csrf = re.search(r'name="_csrf".+value="([^"]+)"', resp.text).group(1)
        transaction_id = re.search(r'name="transaction_id".+value="([^"]+)"', resp.text).group(1)

    # Step 2: Obtain an authorization code
    data = {
        "_csrf": csrf,
        "_phase": "authenticate",
        "_process": "1",
        "transaction_id": transaction_id,
        "cancel": "",
        "identity": email,
        "credential": password,
    }

    for attempt in range(MAX_ATTEMPTS):
        resp = session.post(
            "https://auth.tesla.com/oauth2/v3/authorize",
            headers=headers,
            params=params,
            data=data,
            allow_redirects=False,
        )

        if "We could not sign you in" in resp.text and resp.status_code == 401:
            raise ValueError("Invalid credentials.")

        if resp.ok and (resp.status_code == 302 or "<title>" in resp.text):
            vprint(f"Post auth form success - {attempt + 1} attempt(s).")
            break
        time.sleep(3)
    else:
        raise ValueError(f"Didn't post auth form in {MAX_ATTEMPTS} attempts.")

    # Determine if user has MFA enabled
    # In that case there is no redirect to `https://auth.tesla.com/void/callback` and app shows new form with Passcode / Backup Passcode field
    is_mfa = True if resp.status_code == 200 and "/mfa/verify" in resp.text else False

    if is_mfa:
        resp = session.get(
            f"https://auth.tesla.com/oauth2/v3/authorize/mfa/factors?transaction_id={transaction_id}", headers=headers,
        )
        # {
        #     "data": [
        #         {
        #             "dispatchRequired": false,
        #             "id": "41d6c32c-b14a-4cef-9834-36f819d1fb4b",
        #             "name": "Device #1",
        #             "factorType": "token:software",
        #             "factorProvider": "TESLA",
        #             "securityLevel": 1,
        #             "activatedAt": "2020-12-07T14:07:50.000Z",
        #             "updatedAt": "2020-12-07T06:07:49.000Z",
        #         }
        #     ]
        # }
        vprint(resp.text)

        # Can use Passcode
        if args.passcode:
            factors = resp.json()["data"]
            device_name = f"Device #{args.device}"
            devices = [f for f in factors if f["name"] == device_name]
            if not devices:
                raise ValueError(f"Can't find device `{device_name}`")
            factor_id = devices[0]["id"]

            data = {"transaction_id": transaction_id, "factor_id": factor_id, "passcode": args.passcode}
            resp = session.post("https://auth.tesla.com/oauth2/v3/authorize/mfa/verify", headers=headers, json=data)
            vprint(resp.text)
            # {
            #     "data": {
            #         "id": "63375dc0-3a11-11eb-8b23-75a3281a8aa8",
            #         "challengeId": "c7febba0-3a10-11eb-a6d9-2179cb5bc651",
            #         "factorId": "41d6c32c-b14a-4cef-9834-36f819d1fb4b",
            #         "passCode": "985203",
            #         "approved": true,
            #         "flagged": false,
            #         "valid": true,
            #         "createdAt": "2020-12-09T03:26:31.000Z",
            #         "updatedAt": "2020-12-09T03:26:31.000Z",
            #     }
            # }
            if "error" in resp.text or not resp.json()["data"]["approved"] or not resp.json()["data"]["valid"]:
                raise ValueError("Invalid passcode.")

        # Can use Backup Passcode
        if args.backup_passcode:
            data = {"transaction_id": transaction_id, "backup_code": args.backup_passcode}
            resp = session.post(
                "https://auth.tesla.com/oauth2/v3/authorize/mfa/backupcodes/attempt", headers=headers, json=data
            )
            vprint(resp.text)
            # {
            #     "data": {
            #         "valid": true,
            #         "reason": null,
            #         "message": null,
            #         "enrolled": true,
            #         "generatedAt": "2020-12-09T06:14:23.170Z",
            #         "codesRemaining": 9,
            #         "attemptsRemaining": 10,
            #         "locked": false,
            #     }
            # }
            if "error" in resp.text or not resp.json()["data"]["valid"]:
                raise ValueError("Invalid backup passcode.")

        if not args.passcode and not args.backup_passcode:
            raise ValueError("Account has MFA enabled. Please provide --passcode or --backup_passcode.")

        data = {"transaction_id": transaction_id}

        for attempt in range(MAX_ATTEMPTS):
            resp = session.post(
                "https://auth.tesla.com/oauth2/v3/authorize",
                headers=headers,
                params=params,
                data=data,
                allow_redirects=False,
            )
            if resp.headers.get("location"):
                vprint(f"Got location in {attempt + 1} attempt(s).")
                break
        else:
            raise ValueError(f"Didn't get location in {MAX_ATTEMPTS} attempts.")

    # Step 3: Exchange authorization code for bearer token
    code = parse_qs(resp.headers["location"])["https://auth.tesla.com/void/callback?code"]
    vprint = print if args.verbose else lambda *_: None

    headers = {"user-agent": UA, "x-tesla-user-agent": X_TESLA_USER_AGENT}
    payload = {
        "grant_type": "authorization_code",
        "client_id": "ownerapi",
        "code_verifier": code_verifier.decode("utf-8"),
        "code": code,
        "redirect_uri": "https://auth.tesla.com/void/callback",
    }

    resp = session.post("https://auth.tesla.com/oauth2/v3/token", headers=headers, json=payload)
    access_token = resp.json()["access_token"]

    # Step 4: Exchange bearer token for access token
    headers["authorization"] = "bearer " + access_token
    payload = {
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "client_id": CLIENT_ID,
    }
    resp = session.post("https://owner-api.teslamotors.com/oauth/token", headers=headers, json=payload)

    # Save tokens to file
    if args.file:
        with open(args.file, "wb") as f:
            f.write(resp.content)
        vprint(f"Saved tokens to '{args.file}'.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-e", "--email", type=str, required=True, help="Tesla account email")
    parser.add_argument("-p", "--password", type=str, required=True, help="Tesla account password")
    parser.add_argument("-f", "--file", type=str, required=False, default=None, help="Filename to save tokens")
    parser.add_argument("--verbose", required=False, default=False, action="store_true", help="Be verbose")
    parser.add_argument("--device", choices=["1", "2"], required=False, default="1", help="2FA device to use")

    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument("--passcode", help="Passcode generated by your authenticator app")
    group.add_argument("--backup_passcode", help="Unused backup passcode")

    args = parser.parse_args()
    login(args)
