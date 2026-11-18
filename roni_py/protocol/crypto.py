from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

import constants

ZERO_IV = bytes(16)   # protocol uses a zero IV


def new_aes_key():
    return get_random_bytes(constants.AES_KEY_SIZE)


def import_public_key(public_key):
    try:
        return RSA.import_key(public_key)
    except (ValueError, IndexError, TypeError):
        return RSA.import_key(public_key.rstrip(b'\x00'))   # drop field padding


def encrypt_aes_key(aes_key, public_key):
    return PKCS1_OAEP.new(import_public_key(public_key)).encrypt(aes_key)


def decrypt_file(ciphertext, aes_key):
    return AES.new(aes_key, AES.MODE_CBC, iv=ZERO_IV).decrypt(ciphertext)
