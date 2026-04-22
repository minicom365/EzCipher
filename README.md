# 🛡️ EzCipher

**EzCipher** is a modern, lightweight, and zero-boilerplate AES-256-GCM encryption utility for Python.  
Designed for developers who need secure encryption without dealing with the complexities of cryptographic primitives.

[Korean Version (한국어 버전)](./README_KR.md)

## ✨ Features

- **Authenticated Encryption (AEAD)**: Uses AES-GCM to ensure data integrity and confidentiality.
- **Zero Boilerplate**: No need to manually manage Initialization Vectors (IVs), salts, or authentication tags.
- **Secure Key Derivation**: Hardened password-based key derivation using PBKDF2-HMAC-SHA256 with 100,000 iterations.
- **SecureConfig**: Built-in layer for managing encrypted configuration/vault files.
- **Command Line Interface (CLI)**: Encrypt and manage secrets directly from your terminal.

## 🚀 Installation

```bash
pip install EzCipher
```

## 🛠️ Library Usage

### Simple String Encryption
```python
from EzCipher import EzCipher

# Initialize with a password
cipher = EzCipher.from_password("my-secret-password")

# Encrypt
encrypted_blob = cipher.encrypt("Hello, World!")
print(encrypted_blob) # Returns a versioned Base64 string

# Decrypt
original_text = cipher.decrypt(encrypted_blob)
assert original_text == "Hello, World!"
```

### Encrypted Configuration (Vault)
```python
from EzCipher import SecureConfig

# Create or load an encrypted vault
vault = SecureConfig("secrets.vault", "vault-password")

# Save encrypted data into groups
vault.save("database", {"user": "admin", "password": "db-password-123"})

# Read and decrypt
db_secrets = vault.read("database")
print(db_secrets['password']) # "db-password-123"
```

## 💻 CLI Usage

Once installed, use the `ezcipher` command:

### Encrypt/Decrypt Strings
```bash
# Encrypt
ezcipher encrypt "secret message" -p "my-pass"

# Decrypt
ezcipher decrypt "AQ==..." -p "my-pass"
```

### Manage Vault Files
```bash
# Set a secret
ezcipher config -f keys.vault -p "pass" --set production api_key "sk-12345"

# Get a secret
ezcipher config -f keys.vault -p "pass" --get production api_key

# List all
ezcipher config -f keys.vault -p "pass"
```

## 📖 Architecture & Format

EzCipher uses a unified binary format for its output:
`[VERSION(1 byte)] | [SALT(16 bytes)] | [NONCE(12 bytes)] | [TAG(16 bytes)] | [CIPHERTEXT]`

This ensures that every piece of encrypted data carries everything it needs to be safely decrypted with the correct password.

## ⚖️ License
Licensed under the [MIT License](LICENSE).  
Copyright (c) 2026 **minicom365**
