from secp256k1 import PrivateKey # pip3 install secp256k1
import eth_account # pip3 install eth_account
from Crypto.Hash import keccak # pip3 install pycryptodome

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
