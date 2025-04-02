from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import os
import hashlib
import hmac

shared_key = b'secure_banking_application_key_1'

def verify_hmac(received_hmac, data, mac_key):
    computed_hmac = hmac.new(mac_key, data, hashlib.sha256).digest()
    return hmac.compare_digest(received_hmac, computed_hmac)

def decrypt_AES(nonce, tag, cipher, string=True, decryption_key = None):
    if decryption_key is None: decryption_key = shared_key
    try:
        c = Cipher(algorithms.AES(shared_key), modes.GCM(nonce, tag))
        decryptor = c.decryptor()
        plaintext = decryptor.update(cipher) + decryptor.finalize()
        if string:
            plaintext = plaintext.decode('utf-8')
        return plaintext
    except Exception as e:
        print(f'Error during decryption: {e}')

def encrypt_AES(plaintext, encryption_key = None):
    if encryption_key is None: encryption_key = shared_key
    try:
        nonce = os.urandom(12)
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        c = Cipher(algorithms.AES(shared_key), modes.GCM(nonce))
        encryptor = c.encryptor()
        cipher = encryptor.update(plaintext) + encryptor.finalize()
        tag = encryptor.tag
        return nonce, tag, cipher
    except Exception as e:
        print(f'Error during encrypotion: {e}')

def derive_keys(master_secret):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=b'fixedsalt12345678',
        info=b'atm_transaction'
    )
    derived_key_material = hkdf.derive(master_secret)
    encryption_key = derived_key_material[:32]
    mac_key = derived_key_material[32:]
    return encryption_key, mac_key