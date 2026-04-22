# -*- coding: utf-8 -*-

import argparse
import sys
import os
from EzCipher import EzCipher, SecureConfig

def main():
    parser = argparse.ArgumentParser(description="EzCipher - Simple and Secure AES CLI Tool")
    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # Encrypt command
    enc_parser = subparsers.add_parser("encrypt", help="Encrypt a string")
    enc_parser.add_argument("text", help="Text to encrypt")
    group = enc_parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-p", "--password", help="Password for encryption")
    group.add_argument("-w", "--words", help="12-word recovery phrase for encryption")

    # Decrypt command
    dec_parser = subparsers.add_parser("decrypt", help="Decrypt a string")
    dec_parser.add_argument("data", help="Base64 encoded ciphertext")
    group_dec = dec_parser.add_mutually_exclusive_group(required=True)
    group_dec.add_argument("-p", "--password", help="Password for decryption")
    group_dec.add_argument("-w", "--words", help="12-word recovery phrase for decryption")

    # Recovery command
    rec_parser = subparsers.add_parser("recovery", help="Manage recovery phrases")
    rec_parser.add_argument("--generate", action="store_true", help="Generate a new 12-word recovery phrase")

    # Config command
    conf_parser = subparsers.add_parser("config", help="Manage encrypted configuration")
    conf_parser.add_argument("-f", "--file", default="config.vault", help="Vault file path")
    conf_parser.add_argument("-p", "--password", required=True, help="Vault password")
    conf_parser.add_argument("--set", nargs=3, metavar=("GROUP", "KEY", "VALUE"), help="Set a value in a group")
    conf_parser.add_argument("--get", nargs=2, metavar=("GROUP", "KEY"), help="Get a value from a group")
    conf_parser.add_argument("--list", metavar="GROUP", help="List all keys in a group")

    args = parser.parse_args()

    try:
        if args.command == "encrypt":
            if args.password:
                cipher = EzCipher.from_password(args.password)
            else:
                cipher = EzCipher.from_mnemonic(args.words)
            print(cipher.encrypt(args.text))

        elif args.command == "decrypt":
            if args.password:
                cipher = EzCipher.from_password(args.password)
            else:
                cipher = EzCipher.from_mnemonic(args.words)
            print(cipher.decrypt(args.data))

        elif args.command == "recovery":
            if args.generate:
                print("[*] Generated Recovery Phrase (KEEP IT SAFE!):")
                print(f"\n    {EzCipher.generate_mnemonic()}\n")

        elif args.command == "config":
            conf = SecureConfig(args.file, args.password)
            if args.set:
                group, key, val = args.set
                conf.save(group, {key: val})
                print(f"[*] Saved {key} in [{group}]")
            elif args.get:
                group, key = args.get
                data = conf.read(group)
                print(data.get(key, "Key not found."))
            elif args.list:
                data = conf.read(args.list)
                for k, v in data.items():
                    print(f"{k}: {v}")
            else:
                # Default list all
                all_data = conf.read()
                for group, keys in all_data.items():
                    print(f"[{group}]")
                    for k, v in keys.items():
                        print(f"  {k}: {v}")
        else:
            parser.print_help()

    except Exception as e:
        print(f"[!] Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
