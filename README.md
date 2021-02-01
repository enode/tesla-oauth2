# Tesla OAuth script
A "proof-of-concept" script on how to interact with the recent OAuth2 changes from Tesla and the new `/oauth2/` endpoint.

## How to run
- Pass a valid account details in the `login("youlookgoodtoday@domain.com", "Shhhh!")` function

## Troubleshooting
If you want to play with 2FA, you need to provide either a valid `ONE_OF_BACKUP_CODES` or your `YOUR_PASSCODE` from your 2FA setup and comment out the flow you will not use. If you are looking for documenation I suggest you check out https://github.com/timdorr/tesla-api
