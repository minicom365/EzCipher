# -*- coding: utf-8 -*-

import unittest
import string
import random
import base64

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)) + '/../')

from EzCipher import EzCipher, generate_secret_key, SecureConfig


class TestAESCipher(unittest.TestCase):
    def setUp(self):
        pass_phrase = self._choice_randome_string()
        self.secret_key, self.salt = generate_secret_key(pass_phrase)

    def _choice_randome_string(self):
        return ''.join([random.choice(string.ascii_letters + string.digits) for _ in range(16)])

    def _get_cipher(self, key_length=256):
        return EzCipher(self.secret_key)

    def test_encrypt_128(self):
        text = self._choice_randome_string()
        encrypt_text = self._get_cipher(key_length=128).encrypt(text)
        self.assertNotEqual(text, encrypt_text)

    def test_encrypt_192(self):
        text = self._choice_randome_string()
        encrypt_text = self._get_cipher(key_length=192).encrypt(text)
        self.assertNotEqual(text, encrypt_text)

    def test_encrypt_256(self):
        text = self._choice_randome_string()
        encrypt_text = self._get_cipher(key_length=256).encrypt(text)
        self.assertNotEqual(text, encrypt_text)

    def test_decrypt(self):
        text = self._choice_randome_string()

        encrypt_text = self._get_cipher().encrypt(text)
        self.assertNotEqual(text, encrypt_text)

        decrypt_text = self._get_cipher().decrypt(encrypt_text)
        self.assertNotEqual(encrypt_text, decrypt_text)
        self.assertEqual(text, decrypt_text)

    def test_password_based_cipher(self):
        password = "my-secure-password"
        cipher = EzCipher.from_password(password)
        text = "Hello, high-level abstraction!"

        encrypted = cipher.encrypt(text)
        blob = base64.b64decode(encrypted)
        self.assertEqual(blob[0], 1)  # Check if version is 1

        # New instance with same password should be able to decrypt
        new_cipher = EzCipher.from_password(password)
        decrypted = new_cipher.decrypt(encrypted)
        self.assertEqual(text, decrypted)


class TestSecureConfig(unittest.TestCase):
    def setUp(self):
        self.test_file = "test_config.vault"
        self.password = "test_pass"
        if os.path.exists(self.test_file):
            os.remove(self.test_file)

    def tearDown(self):
        if os.path.exists(self.test_file):
            os.remove(self.test_file)

    def test_config_save_read(self):
        conf = SecureConfig(self.test_file, self.password)
        conf.save("DB", {"user": "admin", "pass": "1234"})

        # Check if hash is correct in file
        with open(self.test_file, 'r') as f:
            header = f.readline().strip()
            self.assertNotEqual(header, self.password)

        # Re-open with same password
        conf2 = SecureConfig(self.test_file, self.password)
        db_keys = conf2.read("DB")
        self.assertEqual(db_keys["user"], "admin")
        self.assertEqual(db_keys["pass"], "1234")

    def test_invalid_password(self):
        conf = SecureConfig(self.test_file, self.password)
        conf.save("TEST", {"key": "val"})

        with self.assertRaises(ValueError):
            SecureConfig(self.test_file, "wrong_pass")


if __name__ == "__main__":
    unittest.main()
