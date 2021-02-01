#!/usr/bin/env ruby
# frozen_string_literal: true

require 'base64'
require 'digest'
require 'rest-client'
require 'json'
require 'addressable/uri'

MAX_ATTEMPTS = 10
CLIENT_ID = '81527cff06843c8634fdc09e8ac0abefb46ac849f38fe1e431c2ef2106796384'
UA = 'Mozilla/5.0 (Linux; Android 10; Pixel 3 Build/QQ2A.200305.002; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/85.0.4183.81 Mobile Safari/537.36'
X_TESLA_USER_AGENT = 'TeslaApp/3.10.9-433/adff2e065/android/10'

def gen_params
  verifier_bytes = Random.urandom(86)
  code_verifier = Base64.urlsafe_encode64(verifier_bytes).delete_suffix('=')
  code_challenge = Base64.urlsafe_encode64(Digest::SHA256.digest(code_verifier)).delete_suffix('=')
  state = Base64.urlsafe_encode64(Random.urandom(16)).delete_suffix('=').force_encoding('utf-8')
  [code_verifier, code_challenge, state]
end

def login(email, password)
  resp = ''
  jar = nil

  headers = {
    user_agent: UA,
    x_tesla_user_agent: X_TESLA_USER_AGENT,
    x_requested_with: 'com.teslamotors.tesla'
  }

  code_verifier, code_challenge, state = gen_params
  params = {
    client_id: 'ownerapi',
    code_challenge: code_challenge,
    code_challenge_method: 'S256',
    redirect_uri: 'https://auth.tesla.com/void/callback',
    response_type: 'code',
    scope: 'openid email offline_access',
    state: state
  }

  (1..MAX_ATTEMPTS).each do |attempt|
    resp = RestClient.get('https://auth.tesla.com/oauth2/v3/authorize', headers: headers, params: params)
    if resp.code >= 400 || !resp.include?('<title>')
      raise ValueError "Didn't get auth form in #{MAX_ATTEMPTS} attempts." unless attempt < MAX_ATTEMPTS
    else
      puts "Get auth form success - #{attempt} attempt(s)."
      break
    end
    sleep 3
  end
  jar = resp.cookie_jar

  csrf = /name="_csrf".+value="([^"]+)"/.match(resp).captures.first
  transaction_id = /name="transaction_id".+value="([^"]+)"/.match(resp).captures.first

  data = {
    _csrf: csrf,
    _phase: 'authenticate',
    _process: '1',
    transaction_id: transaction_id,
    cancel: '',
    identity: email,
    credential: password
  }
  (1..MAX_ATTEMPTS).each do |attempt|
    uri = Addressable::URI.parse 'https://auth.tesla.com/oauth2/v3/authorize'
    uri.query_values = params
    resp = RestClient::Request.execute(method: :post, url: uri.to_s, headers: headers, payload: data, cookies: jar, max_redirects: 0) { |response, _request, _result| response; }
    if resp.code != 302 && !resp.include?('<title>')
      raise ValueError "Didn't post auth form in #{MAX_ATTEMPTS} attempts." unless attempt < MAX_ATTEMPTS
    else
      puts "Post auth form success - #{attempt + 1} attempt(s)."
      break
    end
    sleep 3
  end

  # Determine if user has MFA enabled
  # In that case there is no redirect to `https://auth.tesla.com/void/callback` and app shows new form with Passcode / Backup Passcode field
  is_mfa = (resp.code == 200 && resp.text.include?('/mfa/verify'))

  if is_mfa
    resp = RestClient.get("https://auth.tesla.com/oauth2/v3/authorize/mfa/factors?transaction_id=#{transaction_id}", headers)
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
    puts resp.body
    factor_id = JSON.parse(resp)['data'][0]['id']

    # Can use Passcode
    headers[:content_type] = :json
    data = {
      transaction_id: transaction_id,
      factor_id: factor_id,
      passcode: 'YOUR_PASSCODE'
    }
    resp = RestClient.post('https://auth.tesla.com/oauth2/v3/authorize/mfa/verify', data.to_json, headers)
    # ^^ Content-Type - application/json
    puts resp.body
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
    raise ValueError 'Invalid passcode.' if resp.include?('error') || !JSON.parse(resp)['data']['approved'] || !JSON.parse(resp)['data']['valid']

    # Can use Backup Passcode
    # data = { transaction_id: transaction_id, backup_code: '3HZRJVC6D' }
    # resp = RestClient.post('https://auth.tesla.com/oauth2/v3/authorize/mfa/backupcodes/attempt', data.to_json, headers)
    # # ^^ Content-Type - application/json
    # puts resp.body
    # # {
    # #     "data": {
    # #         "valid": true,
    # #         "reason": null,
    # #         "message": null,
    # #         "enrolled": true,
    # #         "generatedAt": "2020-12-09T06:14:23.170Z",
    # #         "codesRemaining": 9,
    # #         "attemptsRemaining": 10,
    # #         "locked": false,
    # #     }
    # # }
    # raise ValueError 'Invalid backup passcode.' if resp.include?('error') || !JSON.parse(resp)["data"]["valid"]

    data = {
      transaction_id: transaction_id
    }

    (1..MAX_ATTEMPTS).each do |attempt|
      uri = Addressable::URI.parse 'https://auth.tesla.com/oauth2/v3/authorize'
      uri.query_values = params
      resp = RestClient::Request.execute(method: :post, url: uri.to_s, headers: headers, payload: data.to_json, max_redirects: 0) { |response, _request, _result| response }
      if !resp.headers['location']
        raise ValueError("Didn't get location in #{MAX_ATTEMPTS} attempts.") unless attempts < MAX_ATTEMPTS
      else
        puts "Got location in #{attempt + 1} attempt(s)."
        break
      end
      sleep 3
    end
  end

  code = Addressable::URI.parse(resp.headers[:location]).query_values['code']
  puts "Code - #{code}"

  headers = {
    user_agent: UA,
    x_tesla_user_agent: X_TESLA_USER_AGENT,
    content_type: :json
  }
  payload = {
    grant_type: 'authorization_code',
    client_id: 'ownerapi',
    code_verifier: code_verifier.force_encoding('utf-8'),
    code: [code],
    redirect_uri: 'https://auth.tesla.com/void/callback'
  }

  resp = RestClient.post('https://auth.tesla.com/oauth2/v3/token', payload.to_json, headers)
  access_token = JSON.parse(resp)['access_token']

  headers[:authorization] = "bearer #{access_token}"
  payload = {
    grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
    client_id: CLIENT_ID
  }
  resp = RestClient.post('https://owner-api.teslamotors.com/oauth/token', payload.to_json, headers)
  owner_access_token = JSON.parse(resp)['access_token']
  owner_headers = headers.merge(authorization: "bearer #{owner_access_token}")

  resp = RestClient.get('https://owner-api.teslamotors.com/api/1/users/referral_data', owner_headers)
  puts resp.body

  resp = RestClient.get('https://owner-api.teslamotors.com/api/1/vehicles', owner_headers)
  puts resp.body
end

# login "youlookgoodtoday@domain.com", "Shhhh!"
