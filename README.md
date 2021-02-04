# Tesla OAuth Token Generation
A "proof-of-concept" script on how to interact with the recent OAuth2 changes from Tesla and the new `/oauth2/` endpoint. It was open sources so we could let other people in the community better understand the flow of how secrets were passed around in a token exchange.

## How to run
- Make sure you have Python 3 installed
- Make sure you have ``Requests`` installed
- Run the script while passing in email and password along with a token file and setting your `YOUR_PASSCODE`

## Troubleshooting
If you want to play with 2FA, you need to provide either a valid `ONE_OF_BACKUP_CODES` or your `YOUR_PASSCODE` from your 2FA setup and comment out the flow you will not use. If you are looking for documentation I suggest you check out https://github.com/timdorr/tesla-api
