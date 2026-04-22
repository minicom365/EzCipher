# -*- coding: utf-8 -*-

from .cipher import EzCipher
from .config import SecureConfig
AESCipher = EzCipher
from .secret_key import generate_secret_key
from .version import VERSION

__VERSION__ = VERSION
