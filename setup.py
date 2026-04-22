#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages

# [Architecture 4.0] EzCipher - Modern AES Utility by minicom365
# This is a complete rebuild of the simple-aes-cipher concept.

with open('README.md', encoding='utf-8') as f:
    long_description = f.read()

VERSION = "1.0.0"

setup(
    name='EzCipher',
    version=VERSION,
    description='A modern, zero-boilerplate AES-GCM encryption library and CLI tool.',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='minicom365',
    author_email='3387910@naver.com',
    url='https://github.com/minicom365/EzCipher',
    packages=find_packages(),
    include_package_data=True,
    license='MIT',
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Topic :: Security :: Cryptography",
    ],
    install_requires=[
        "pycryptodome>=3.10.1",
    ],
    entry_points={
        'console_scripts': [
            'ezcipher=EzCipher.cli:main',
        ],
    },
    keywords=['AES', 'GCM', 'Encryption', 'CLI', 'SecureConfig', 'EzCipher'],
    python_requires='>=3.7',
)
