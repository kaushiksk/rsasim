#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File              : rsa.py
# Author            : Kaushik S Kalmady
# Date              : 12.12.2017
# Last Modified Date: 13.12.2017
# Last Modified By  : Kaushik S Kalmady

import random
from struct import pack, unpack

from rsasim.gcd_utils import gcd, inverse
from rsasim.primality_tests import miller_rabin, solovay_strassen
from rsasim.prime_utils import generate_large_prime
from rsasim.utils import as_bytes, exp


class RSA(object):
    """RSA Cryptosystem
    This Class is to be used as proof of concept for the demonstation of the
    RSA cryptosystem.

    REFERENCES
    ==========
    https://en.wikipedia.org/wiki/RSA_(cryptosystem)
    """

    def __init__(self, size=128, primality_test="miller_rabin"):
        """__init__


        Args:
            size: bit size of generated primes
            primality_test: primality test to be used for generating large
                            primes. Has to be one of miller_rabin or
                            solovay_strassen.
        """
        self.bit_size = size

        assert primality_test in ("miller_rabin", "solovay_strassen")
        if primality_test == "miller_rabin":
            self.primality_test = miller_rabin
        else:
            self.primality_test = solovay_strassen

        self.__p = generate_large_prime(self.bit_size, self.primality_test)
        self.__q = generate_large_prime(self.bit_size, self.primality_test)
        while self.__p == self.__q:
            self.__q = generate_large_prime(self.bit_size, self.primality_test)

        self.n = self.__p * self.__q
        self.phi = (self.__p - 1) * (self.__q - 1)
        self.__public_key, self.__private_key = self.__generate_keys()

    def __generate_keys(self):
        """generate public and private keys for current session

        REFERENCES
        ==========
        https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Key_generation
        """

        # choose e < phi and co-prime to phi
        e = random.randint(2, self.phi - 1)
        while gcd(e, self.phi) != 1:
            e = random.randint(2, self.phi - 1)

        # choose d, the modular inverse of e mod phi
        d = inverse(e, self.phi)
        public_key = (e, self.n)
        private_key = (d, self.n)

        return public_key, private_key

    @property
    def public_key(self):
        return self.__public_key

    @public_key.setter
    def public_key(self, val):
        raise Exception("You are not allowed to alter generated keys")

    @classmethod
    def process_string(self, message):
        """Convert string to long integer

        Args:
            message: string

        REFERENCE
        =========
        https://github.com/dlitz/pycrypto/blob/master/lib/Crypto/Util/number.py
        """

        acc = 0
        length = len(message)
        if length % 4:
            extra = (4 - length % 4)
            message = as_bytes('\000') * extra + as_bytes(message)

        for i in range(0, length, 4):
            acc = (acc << 32) + unpack('>I', message[i:i+4])[0]

        return acc

    @classmethod
    def recover_string(self, number):
        """Convert long to byte string

        Args:
                number: long integer to convert to string

        REFERENCE
        =========
        https://github.com/dlitz/pycrypto/blob/master/lib/Crypto/Util/number.py
        """

        s = as_bytes('')
        while number > 0:
            s = pack('>I', number & 0xffffffff) + s
            number = number >> 32

        # remove padded zeros
        i = 0
        while i < len(s):
            if s[i] != as_bytes('\000')[0]:
                break
            i += 1
        return s[i:]

    @classmethod
    def encrypt(self, message, key):
        """RSA Encryption

        Args:
            message: message to encrypt
            key: public key to use for encryption

        REFERENCES
        ==========
        https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Encryption
        """

        # If input is string, convert it to long first
        if type(message) is str:
            if len(message) > 32:
                raise ValueError("Please enter a smaller string")
            message = self.process_string(message)

        e, n = key
        return exp(message, e, n)

    def decrypt(self, ciphertext):
        """RSA Decryption

        Args:
            ciphertext: Ciphertext object to decrypt

        REFERENCES
        ==========
        https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Decryption
        """

        d, n = self.__private_key
        return exp(ciphertext.ciphertext, d, n)

    def sign(self, message):
        """RSA signing
        Similar to RSA encryption but we use private key to sign.
        Note that this is merely for proof of concept and should not be used
        in production

        Args:
                message: message to sign

        REFERENCES
        ==========
        https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Signing_messages
        """
        # If input is string, convert it to long first
        if type(message) is str:
            if len(message) > 32:
                raise ValueError("Please enter a smaller string")
            message = self.process_string(message)

        assert message.bit_length() <= self.n.bit_length()

        d, n = self.__private_key
        return exp(message, d, n)

    def verify(self, signature, key):
        """RSA signature verification

        Args:
            signature: signature we want to verify
            key: public key of the person who's signature we want to verify

        REFERENCES
        ==========
        https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Signing_messages
        """

        e, n = key
        return exp(signature.ciphertext, e, n)


class Ciphertext():
    """Ciphertext
    Wrapper class for ciphertext"""
    def __init__(self, text, is_str=0):
        """__init__


        Args:
            text: ciphertext(long int)
            is_str: boolean to specify if original message was string or not
        """

        self.ciphertext = text
        self.is_str = is_str
