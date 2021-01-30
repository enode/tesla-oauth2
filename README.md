# Tesla MFA
A "proof-of-concept" on how to interact with the recent OAuth2 changes from Tesla and the new `/oauth2/` endpoint.

Please note as of 29.01.21 (?) the reverse-engineered 2FA code is broken. Only non-2FA-accounts will give you a valid refresh/access token pair. I will update this script as soon as I have figured out what is going on.

## How to run
- Pass a valid non-2fa-account details in the `login("youlookgoodtoday@domain.com", "Shhhh!")` function

## Troubleshooting
Sometimes you have to run it a few times. I have not figured out why that is.
If you have 2FA enabled, the script currently fails on the `location` header parsing.

If you want to play with 2FA, you need to provide either a valid `ONE_OF_BACKUP_CODES` or your `YOUR_PASSCODE` from your 2FA setup and comment out the flow you will not use.