import requests, datetime, json
from secp256k1_utils import get_signature_hex_str

host_url = 'https://testnet.api.deepwaters.xyz'
api_route = '/rest/v1/'
# to be distributed
api_key = None
api_secret = None
nonce_d = {'nonce': None}
base_asset_id = 'WBTC.GOERLI.5.TESTNET.PROD'
quote_asset_id = 'USDC.GOERLI.5.TESTNET.PROD'

def now_micros():
    return str(int(datetime.datetime.now().timestamp() * 1e6))

def get_request_uri_and_url_from_extension(extension):
    request_uri = api_route + extension
    url = host_url + request_uri
    return request_uri, url

# some requests require authentication.
# those that modify the customer state require that the next nonce value be submitted, as part of authentication.
# for example, getting the API key status does not require nonce submission,
# but submitting an order does require nonce submission.
# note: upon receiving an error, the user should immediately resync the nonce
# see "sync_nonce", below
# this function increments the nonce if the nonce_d argument is applied
def get_authentication_headers(api_key, api_secret, verb, request_uri, nonce_d = None, payload = None):
    
    headers = {'X-DW-APIKEY': api_key}

    now_micros_str = now_micros()
    headers['X-DW-TSUS'] = now_micros_str

    to_hash_and_sign = verb + request_uri.lower() + now_micros_str

    if nonce_d is not None:
        nonce_str = str(nonce_d['nonce'])
        headers['X-DW-NONCE'] = nonce_str
        to_hash_and_sign += nonce_str
        nonce_d['nonce'] += 1

    if payload is not None:
        to_hash_and_sign += json.dumps(payload)

    headers['X-DW-SIGHEX'] = get_signature_hex_str(to_hash_and_sign, api_secret)

    return headers

def sync_nonce(api_key, api_secret, nonce_d):
    extension = 'customer/api-key-status'
    request_uri, url = get_request_uri_and_url_from_extension(extension)
    headers = get_authentication_headers(api_key, api_secret, 'GET', request_uri)
    r = requests.get(url, headers=headers)
    response = r.json()
    nonce_d['nonce'] = response['result']['nonce']

sync_nonce(api_key, api_secret, nonce_d)

# GET /pairs

request_uri, url = get_request_uri_and_url_from_extension('pairs')

print('GET %s ... ' % url)
r = requests.get(url)
response = r.json()
print(response)
print()

# GET /pairs/{pair_name}

pair_name = base_asset_id + '-' + quote_asset_id
extension = f'pairs/{pair_name}'
request_uri, url = get_request_uri_and_url_from_extension(extension)

print('GET %s ... ' % url)
r = requests.get(url)
response = r.json()
print(response)
print()

# GET /pairs/{pair_name}/orderbook?depth={depth}

extension = f'pairs/{pair_name}/orderbook?depth=12'
request_uri, url = get_request_uri_and_url_from_extension(extension)

print('GET %s ... ' % url)
r = requests.get(url)
response = r.json()
print(response)
print()

# GET /assets

url = host_url + api_route + 'assets'

print('GET %s ... ' % url)
r = requests.get(url)
response = r.json()
print(response)
print()

# authentication required, including nonce
# POST /orders

request_uri, url = get_request_uri_and_url_from_extension('orders')

payload = {"type": "LIMIT", "side": "BUY", "quantity": "1.00000", "price": "17000.00", "baseAssetID": base_asset_id, "quoteAssetID": quote_asset_id, "durationType": "GOOD_TILL_EXPIRY", "customerObjectID": now_micros(), "expiresAt": int(int(now_micros()) + 10*1e6)}

headers = get_authentication_headers(api_key, api_secret, 'POST', request_uri, nonce_d, payload)

print('POST %s ... ' % url)
r = requests.post(url, headers=headers, json=payload)
response = r.json()
print(response)
print()

# authentication required, including nonce
# delete all orders (for only a specific pair, when specified)
# DELETE /orders?pair={pair}

extension = f'orders?pair={pair_name}'
request_uri, url = get_request_uri_and_url_from_extension(extension)

headers = get_authentication_headers(api_key, api_secret, 'DELETE', request_uri, nonce_d)

print('DELETE %s with get params ... ' % url)
r = requests.delete(url, headers=headers)
response = r.json()
print(response)
print()

extension = 'orders'
request_uri, url = get_request_uri_and_url_from_extension(extension)

headers = get_authentication_headers(api_key, api_secret, 'DELETE', request_uri, nonce_d)

print('DELETE %s without get params ... ' % url)
r = requests.delete(url, headers=headers)
response = r.json()
print(response)
print()

# per-user
# requires authentication, without nonce
# GET /orders?pair={pair}&type={type}&side={side}&status-in={status-in}&skip={skip}&limit={limit}

extension = f'orders?pair={pair_name}&type=LIMIT&side=BUY&status-in=ACTIVE-PARTIALLY_FILLED-FILLED&skip=0&limit=5'
request_uri, url = get_request_uri_and_url_from_extension(extension)

headers = get_authentication_headers(api_key, api_secret, 'GET', request_uri)

print('GET %s ... ' % url)
r = requests.get(url, headers=headers)
response = r.json()
print(response)
print()

# per-user
# requires authentication, without nonce
# GET /trades?pair={pair}&type={type}&skip={skip}&limit={limit}

extension = f'trades?pair={pair_name}&type=FILL&skip=0&limit=1'
request_uri, url = get_request_uri_and_url_from_extension(extension)

headers = get_authentication_headers(api_key, api_secret, 'GET', request_uri)

print('GET %s ... ' % url)
r = requests.get(url, headers=headers)
response = r.json()
print(response)
print()

# per-user
# requires authentication, without nonce
# GET /customer

extension = 'customer'
request_uri, url = get_request_uri_and_url_from_extension(extension)

headers = get_authentication_headers(api_key, api_secret, 'GET', request_uri)

print('GET %s ... ' % url)
r = requests.get(url, headers=headers)
response = r.json()
print(response)
print()

# per API key
# requires authentication, without nonce
# GET /customer/api-key-status

extension = 'customer/api-key-status'
request_uri, url = get_request_uri_and_url_from_extension(extension)

headers = get_authentication_headers(api_key, api_secret, 'GET', request_uri)

print('GET %s ... ' % url)
r = requests.get(url, headers=headers)
response = r.json()
print(response)
print()

# requires authentication
# GET /orders/by-venue-order-id/{venue_order_id} <- without nonce
# DELETE /orders/by-venue-order-id/{venue_order_id} <- with nonce

# first create an order to GET and then DELETE

extension = 'orders'
request_uri, url = get_request_uri_and_url_from_extension(extension)

payload = {'type': 'LIMIT', 'side': 'BUY',
'quantity': '1.0000', 'price': '17000.00', 'baseAssetID': base_asset_id, 'quoteAssetID': quote_asset_id}

headers = get_authentication_headers(api_key, api_secret, 'POST', request_uri, nonce_d, payload)

print('POST %s ... ' % url)
r = requests.post(url, headers=headers, json=payload)
response = r.json()
print(response)
print()

venue_order_id = response['result']['venueOrderID']

extension = f'orders/by-venue-order-id/{venue_order_id}'
request_uri, url = get_request_uri_and_url_from_extension(extension)

headers = get_authentication_headers(api_key, api_secret, 'GET', request_uri)

print('GET %s ... ' % url)
r = requests.get(url, headers=headers)
response = r.json()
print(response)
print()

extension = f'orders/by-venue-order-id/{venue_order_id}'
request_uri, url = get_request_uri_and_url_from_extension(extension)

headers = get_authentication_headers(api_key, api_secret, 'DELETE', request_uri, nonce_d)

print('DELETE %s ... ' % url)
r = requests.delete(url, headers=headers)
response = r.json()
print(response)
print()

# requires authentication
# GET /orders/by-customer-object-id/{customer_object_id} <- without nonce
# DELETE /orders/by-customer-object-id/{customer_object_id} <- with nonce

# first create an order to GET and then DELETE

extension = 'orders'
request_uri, url = get_request_uri_and_url_from_extension(extension)

customer_object_id = str(datetime.datetime.now().timestamp())

payload = {'type': 'LIMIT', 'side': 'BUY',
'customerObjectID': customer_object_id,
'quantity': '10.0000', 'price': '17000.00', 'baseAssetID': base_asset_id, 'quoteAssetID': quote_asset_id}

headers = get_authentication_headers(api_key, api_secret, 'POST', request_uri, nonce_d, payload)

print('POST %s ... ' % url)
r = requests.post(url, headers=headers, json=payload)
response = r.json()
print(response)
print()

extension = f'orders/by-customer-object-id/{customer_object_id}'
request_uri, url = get_request_uri_and_url_from_extension(extension)

headers = get_authentication_headers(api_key, api_secret, 'GET', request_uri)

print('GET %s ... ' % url)
r = requests.get(url, headers=headers)
response = r.json()
print(response)
print()

extension = f'orders/by-customer-object-id/{customer_object_id}'
request_uri, url = get_request_uri_and_url_from_extension(extension)

headers = get_authentication_headers(api_key, api_secret, 'DELETE', request_uri, nonce_d)

print('DELETE %s ... ' % url)
r = requests.delete(url, headers=headers)
response = r.json()
print(response)
print()
