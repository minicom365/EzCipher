EzCipher
========

**EzCipher** is a modern, lightweight, and zero-boilerplate AES-256-GCM encryption utility for Python.
Designed for developers who need secure encryption without dealing with the complexities of cryptographic primitives.

Features
--------

- **Authenticated Encryption (AEAD)**: Uses AES-GCM to ensure data integrity and confidentiality.
- **Zero Boilerplate**: No need to manually manage Initialization Vectors (IVs), salts, or authentication tags.
- **Secure Key Derivation**: Hardened password-based key derivation using PBKDF2-HMAC-SHA256.
- **SecureConfig**: Built-in layer for managing encrypted configuration/vault files.
- **Command Line Interface (CLI)**: Encrypt and manage secrets directly from your terminal.

Installation
------------

.. code-block:: bash

    pip install EzCipher

Library Usage
-------------

.. code-block:: python

    from EzCipher import EzCipher

    cipher = EzCipher.from_password("my-pass")
    encrypted = cipher.encrypt("Hello")
    decrypted = cipher.decrypt(encrypted)

CLI Usage
---------

.. code-block:: bash

    ezcipher encrypt "message" -p "pass"
    ezcipher config -f secrets.vault -p "pass" --set db user admin

License
-------

MIT License. Copyright (c) 2026 **minicom365**
