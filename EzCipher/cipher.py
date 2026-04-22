# -*- coding: utf-8 -*-

import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from mnemonic import Mnemonic
import hashlib
from .secret_key import generate_secret_key

# [Architecture 2.0] AES-GCM을 사용한 인증 암호화 구현. 
# CBC 모드와 수동 패딩의 보안 취약점을 해결하고, nonce와 tag를 자동으로 관리함.


class EzCipher(object):
    """
    안전한 기본값을 제공하는 AES-GCM 기반 암호화 클래스.
    포맷: [1바이트 버전][16바이트 Salt][12바이트 Nonce][16바이트 Tag][암호문]
    """
    VERSION = b'\x01'
    SALT_SIZE = 16
    NONCE_SIZE = 12
    TAG_SIZE = 16

    def __init__(self, key=None, password=None):
        """
        key: bytes 형태의 AES 키 (16, 24, 32 bytes)
        password: 키 유도를 위한 패스워드 문자열
        """
        self.key = key
        self.password = password

    @staticmethod
    def generate_mnemonic(language="english"):
        """12개의 단어로 구성된 복구 문구(Mnemonic)를 생성합니다."""
        mnemo = Mnemonic(language)
        return mnemo.generate(strength=128)

    @classmethod
    def from_mnemonic(cls, words, language="english"):
        """12개의 복구 단어로부터 EzCipher 인스턴스를 초기화합니다."""
        mnemo = Mnemonic(language)
        if not mnemo.check(words):
            raise ValueError("Invalid mnemonic recovery phrase")
        seed = mnemo.to_seed(words, passphrase="")
        # 64바이트 시드를 SHA-256으로 해싱하여 32바이트 키 생성
        key = hashlib.sha256(seed).digest()
        return cls(key=key)

    @classmethod
    def from_password(cls, password):
        """
        패스워드로부터 초기화된 SimpleAES 인스턴스를 반환합니다.
        암호화 시에는 새로운 Salt가 생성되어 결과물에 포함됩니다.
        """
        return cls(password=password)

    def encrypt(self, data):
        """
        데이터를 암호화하여 Base64 인코딩된 문자열을 반환합니다.
        """
        if isinstance(data, str):
            data = data.encode('utf-8')

        current_key = self.key
        salt = b'\x00' * self.SALT_SIZE
        
        if self.password:
            # 암호화 시마다 새로운 salt를 생성하여 보안성 강화
            current_key, salt = generate_secret_key(self.password)
        
        if not current_key:
            raise ValueError("Key or Password must be provided")

        nonce = get_random_bytes(self.NONCE_SIZE)
        cipher = AES.new(current_key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        
        blob = self.VERSION + salt + nonce + tag + ciphertext
        return base64.b64encode(blob).decode('utf-8')

    def decrypt(self, enc_b64):
        """
        Base64 인코딩된 암호문을 복호화하여 평문을 반환합니다.
        """
        try:
            blob = base64.b64decode(enc_b64)
            if len(blob) < 1 + self.SALT_SIZE + self.NONCE_SIZE + self.TAG_SIZE:
                raise ValueError("Invalid ciphertext format")

            version = blob[0:1]
            ptr = 1
            salt = blob[ptr:ptr+self.SALT_SIZE]
            ptr += self.SALT_SIZE
            nonce = blob[ptr:ptr+self.NONCE_SIZE]
            ptr += self.NONCE_SIZE
            tag = blob[ptr:ptr+self.TAG_SIZE]
            ptr += self.TAG_SIZE
            ciphertext = blob[ptr:]
            
            current_key = self.key
            if self.password:
                # 암호문에 포함된 salt를 사용하여 동일한 키를 유도
                current_key, _ = generate_secret_key(self.password, salt=salt)
                
            if not current_key:
                raise ValueError("Key or Password must be provided")

            cipher = AES.new(current_key, AES.MODE_GCM, nonce=nonce)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            return plaintext.decode('utf-8')
        except (ValueError, KeyError, IndexError) as e:
            raise ValueError("Decryption failed: Likely incorrect key or corrupted data") from e
