import re
import random
import string
from urllib.parse import parse_qs

import requests

CLIENT_ID = "81527cff06843c8634fdc09e8ac0abefb46ac849f38fe1e431c2ef2106796384"
UA = "Mozilla/5.0 (Linux; Android 10; Pixel 3 Build/QQ2A.200305.002; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/85.0.4183.81 Mobile Safari/537.36"
X_TESLA_USER_AGENT = "TeslaApp/3.10.8-421/adff2e065/android/10"


def rand_str(chars=43):
    letters = string.ascii_lowercase + string.ascii_uppercase + string.digits + "-" + "_"
    return "".join(random.choice(letters) for i in range(chars))


def login(email, password):
    session = requests.Session()

    headers = {
        "User-Agent": UA,
        "x-tesla-user-agent": X_TESLA_USER_AGENT,
        "X-Requested-With": "com.teslamotors.tesla",
    }

    code_challenge = rand_str()
    state = rand_str()

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

    resp = session.get("https://auth-global.tesla.com/oauth2/v3/authorize", headers=headers, params=params)
    csrf = re.search(r'name="_csrf".+value="([^"]+)"', resp.text).group(1)
    transaction_id = re.search(r'name="transaction_id".+value="([^"]+)"', resp.text).group(1)

    data = {
        "_csrf": csrf,
        "_phase": "authenticate",
        "_process": "1",
        "transaction_id": transaction_id,
        "cancel": "",
        "identity": email,
        "credential": password,
    }

    resp = session.post(
        "https://auth.tesla.com/oauth2/v3/authorize", headers=headers, params=params, data=data, allow_redirects=False
    )

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
        print(resp.text)
        factor_id = resp.json()["data"][0]["id"]

        # Can use Passcode
        data = {"transaction_id": transaction_id, "factor_id": factor_id, "passcode": "YOUR_PASSCODE"}
        resp = session.post("https://auth.tesla.com/oauth2/v3/authorize/mfa/verify", headers=headers, json=data)
        # ^^ Content-Type - application/json
        print(resp.text)
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
        data = {"transaction_id": transaction_id, "backup_code": "ONE_OF_BACKUP_CODES"}
        resp = session.post(
            "https://auth.tesla.com/oauth2/v3/authorize/mfa/backupcodes/attempt", headers=headers, json=data
        )
        # ^^ Content-Type - application/json
        print(resp.text)
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

        data = {"transaction_id": transaction_id}
        resp = session.post(
            "https://auth.tesla.com/oauth2/v3/authorize",
            headers=headers,
            params=params,
            data=data,
            allow_redirects=False,
        )

    code = parse_qs(resp.headers["location"])["https://auth.tesla.com/void/callback?code"]

    headers = {"user-agent": UA, "x-tesla-user-agent": X_TESLA_USER_AGENT}
    payload = {
        "grant_type": "authorization_code",
        "client_id": "ownerapi",
        "code_verifier": rand_str(108),
        "code": code,
        "redirect_uri": "https://auth.tesla.com/void/callback",
    }

    resp = session.post("https://auth.tesla.com/oauth2/v3/token", headers=headers, json=payload)
    access_token = resp.json()["access_token"]

    headers["authorization"] = "bearer " + access_token
    payload = {
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "client_id": CLIENT_ID,
    }
    resp = session.post("https://owner-api.teslamotors.com/oauth/token", headers=headers, json=payload)
    owner_access_token = resp.json()["access_token"]
    owner_headers = {**headers, "authorization": "bearer " + owner_access_token}

    resp = session.get("https://owner-api.teslamotors.com/api/1/users/referral_data", headers=owner_headers)
    print(resp.text)
    print()

    resp = session.get("https://owner-api.teslamotors.com/api/1/vehicles", headers=owner_headers)
    print(resp.text)
    print()

if __name__ == "__main__":
    login("youlookgoodtoday@domain.com", "Shhhh!")
