import base64
import hashlib
import hmac
import json
import requests
from datetime import datetime, timezone


def stream_API_token():
    '''
    Calling the Discover Streams URL.

    The first GET request to the Discover Streams URL must be signed with a hash of your API key
    and the body of the request. This allows the request to be authorized without having to send
    your API key.

    '''

    url = "https://firehose.crowdstrike.com/sensors/entities/datafeed/v1?appId=app5"

    key = "---CROWDSTRIKE-API-KEY---"
    UUID = "---CROWDSTRIKE-UUID---"
    keyEncoded = bytes(key.encode('utf-8'))

    requestMethod = "GET"
    # ContentMD5 = base64.b64encode(hashlib.md5(''.encode('utf-8')).digest()).decode()
    contentMD5 = ""
    # RequestDate = Tue, 02 Apr 2019 22:00:00 +0000
    requestDate = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S %z")
    canonicalURI = "firehose.crowdstrike.com/sensors/entities/datafeed/v1"
    canonicalQS = "appId=app5"

    requestString = "%s\n%s\n%s\n%s\n%s" % (requestMethod, contentMD5, requestDate, canonicalURI, canonicalQS)
    requestStringEncoded = bytes(requestString.encode('utf-8'))

    # Base64(HMAC?SHA256(ApiSecretKey,RequestString))
    hash = hmac.new(keyEncoded, requestStringEncoded, digestmod=hashlib.sha256)
    signature = base64.b64encode(hash.digest()).decode()

    # Header Authorization:cs-hmac UUID:Signature:customers
    authHeader = "cs-hmac %s:%s:customers" % (UUID, signature)

    # print("Now: %s" % requestDate)
    # print("Request String:\n------\n%s\n-------" % requestString)
    # print("Signature: %s" % signature)
    # print("Authentication Header: %s" % authHeader)

    headers = {'Authorization': authHeader, 'Date': requestDate}

    try:
        r = requests.get(url, headers=headers)
    except Exception as e:
        print('Exception %s' % e)
    print(r.text[100:])
    data = json.loads(r.content)

    token = ''

    for d in data['resources']:
        token = (d['sessionToken']['token'])

    return token


def discover_API_request():
    '''
    Calling the Stream Data URL.

    This establishes a long-lived HTTP connection to receive event data. After you establish a connection to the client,
    you will begin receiving a stream of data.
    '''

    url_stream = 'https://firehose.crowdstrike.com/sensors/entities/datafeed/v1/0?appId=app5'
    authHeader_new = ''

    try:
        authHeader_new = "Token %s" % (stream_API_token())
        headers = {'Authorization': authHeader_new,
                   'Connection': "Keep-Alive",
                   }
    except UnboundLocalError:
        print("Token didn't generate properly.")

    headers = {'Authorization': authHeader_new,
               'Connection': "Keep-Alive",
               }

    # Use stream instead of a simple GET request, we are using the "Keep-Alive" header.
    s = requests.Session()

    req = requests.Request("GET", url_stream,
                           headers=headers).prepare()

    try:
        resp = s.send(req, stream=True)

        print('---- CROWDSTRIKE STREAMING API ----')

        for line in resp.iter_lines():
            if line:
                data = json.loads(line)
                data_indented = json.dumps(data, indent=4, sort_keys=False)
                print(data_indented)
    except Exception as e:
        print('Exception %s' % e)
        print('Nothing to show here.')


if __name__ == '__main__':
    discover_API_request()
