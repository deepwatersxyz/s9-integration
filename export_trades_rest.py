import requests, datetime, json, csv, dotenv, os
from secp256k1 import PrivateKey # pip3 install secp256k1
import eth_account # pip3 install eth_account
from Crypto.Hash import keccak # pip3 install pycryptodome

dotenv.load_dotenv()

host_url = 'https://api.deepwaters.xyz'
api_route = '/rest/v1/'
api_key = os.getenv('API_KEY')
api_secret = os.getenv('API_SECRET')
nonce_d = {'nonce': 0}
base_asset_id = 'WTR_AM_MB'
quote_asset_id = 'USDC_EM_MB'

def now_micros():
    return str(int(datetime.datetime.now().timestamp() * 1e6))

def get_request_uri_and_url_from_extension(extension):
    request_uri = api_route + extension
    url = host_url + request_uri
    return request_uri, url

def check_private_key_hex_str(private_key_hex_str):
    if private_key_hex_str[:2] != '0x':
        raise Exception('private key must be a hex string beginning with \'0x\'')
    if len(private_key_hex_str) != 66:
        raise Exception('private key must have length: 66')

def get_public_key_hex_str(private_key_hex_str):
    check_private_key_hex_str(private_key_hex_str)
    privkey = PrivateKey(bytes(bytearray.fromhex(private_key_hex_str[2:])))
    pubkey_ser_uncompressed = privkey.pubkey.serialize(compressed=False)
    return '0x' + pubkey_ser_uncompressed.hex()

def get_ethereum_address_hex_str(private_key_hex_str):
    check_private_key_hex_str(private_key_hex_str)
    account = eth_account.Account().from_key(private_key_hex_str)
    return account.address # already has '0x'

def get_keccak_256_hash_hex_str(input_str):
    k = keccak.new(digest_bits=256)
    k.update(input_str.encode())
    return '0x' + k.hexdigest()

def get_signature_bytes(message_str, private_key_hex_str):
    check_private_key_hex_str(private_key_hex_str)
    privkey = PrivateKey(bytes(bytearray.fromhex(private_key_hex_str[2:])))
    hashed_message_hex_str = get_keccak_256_hash_hex_str(message_str)
    unserialized_signature = privkey.ecdsa_sign_recoverable(bytes(bytearray.fromhex(hashed_message_hex_str[2:])), raw=True)
    signature, rec_id = privkey.ecdsa_recoverable_serialize(unserialized_signature)
    complete_signature_bytes = bytearray(signature)
    complete_signature_bytes.extend(rec_id.to_bytes(1, byteorder='big'))
    return bytes(complete_signature_bytes)

def get_signature_hex_str(message_str, private_key_hex_str):
    return '0x' + get_signature_bytes(message_str, private_key_hex_str).hex()

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

    # print('headers: %s' % headers)

    return headers

def sync_nonce(api_key, api_secret, nonce_d):
    extension = 'customer/api-key-status'
    request_uri, url = get_request_uri_and_url_from_extension(extension)
    headers = get_authentication_headers(api_key, api_secret, 'GET', request_uri)
    r = requests.get(url, headers=headers)
    response = r.json()
    nonce_d['nonce'] = response['result']['nonce']

def getTrades(skipNum):
    get_authentication_headers(api_key, api_secret, 'GET', '/rest/v1/customer/api-key-status', nonce_d)
    sync_nonce(api_key, api_secret, nonce_d)

    # extension = f'trades'
    extension = f'trades?pair={base_asset_id + "-" + quote_asset_id}&skip={skipNum}&limit=100'
    request_uri, url = get_request_uri_and_url_from_extension(extension)

    headers = get_authentication_headers(api_key, api_secret, 'GET', request_uri)

    # print('GET %s ... ' % url)
    r = requests.get(url, headers=headers)
    response = r.json()
    # print(response)
    # print()

    data = response

    json_data = json.dumps(data)
    data_dict = json.loads(json_data)

    trades = data_dict['result']['trades']
    with open('trades.csv', 'a', newline='') as csvfile:
        csv_writer = csv.writer(csvfile)
        if csvfile.tell() == 0:  # write header row only if file is empty
            csv_writer.writerow(trades[0].keys())
        for trade in trades:
            csv_writer.writerow(trade.values())
    # with open('trades.csv', 'w', newline='') as csvfile:
    #     csv_writer = csv.writer(csvfile)
    #     csv_writer.writerow(trades[0].keys())
    #     for trade in trades:
    #         csv_writer.writerow(trade.values())
    return str(data_dict['result']['count'])

doneGettingTrades = False
counter = 0
numTrades = 0

while doneGettingTrades == False:
    incTrades = getTrades(counter)
    numTrades += int(incTrades)
    counter += 100
    if incTrades == '0':
        doneGettingTrades = True
        print("Trades: " + str(numTrades))
