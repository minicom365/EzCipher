# -*- coding: utf-8 -*-

from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

# [Architecture 1.0] PBKDF2를 사용하여 패스워드 기반 키 유도 구현. 단순 해시는 무차별 대입 공격에 취약함.
def generate_secret_key(passphrase, salt=None, iterations=100000):
    """
    PBKDF2-HMAC-SHA256을 사용하여 패스워드로부터 32바이트(256비트) 키를 유도합니다.
    """
    if salt is None:
        salt = get_random_bytes(16)
    
    key = PBKDF2(passphrase, salt, dkLen=32, count=iterations, hmac_hash_module=SHA256)
    return key, salt
