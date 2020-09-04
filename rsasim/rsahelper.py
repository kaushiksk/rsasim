"""
File         : rsahelper.py
Author       : Kaushik S Kalmady
Date Created : 1/13/2020, 9:06:15 PM
Description  : RSA Helper to decrypt ciphertext for cracked RSA publickeys
"""
from rsasim.rsa import RSA
from rsasim.primality_tests import miller_rabin
from rsasim.gcd_utils import inverse


def is_prime(n):
    """
    Returns True is number supplied is a prime.
    Uses miller rabin primality test with k = 100
    Larger the value of k we choose, better is the chance of reducing
    false positives.
    """

    return miller_rabin(n, k=100)


class RSAHelper:

    num_to_bytes = RSA.recover_string

    def __init__(self, p, q, e, n):
        """Helper class to perform decryption when RSA has been cracked

        Arguments:
            p, q  -- prime factors of n
            e     -- rsa public exponent
            n     -- rsa modulus
        """

        assert is_prime(p), "p is not prime"
        assert is_prime(q), "q is not prime"
        assert n == p * q, "n != p * q, the prime factors are incorrect"

        self.p = p
        self.q = q
        self.e = e
        self.n = n

        self.phi = (p - 1) * (q - 1)
        self.d = self.compute_private_exponent()

        assert (self.e * self.d) % self.phi == 1, \
            "private/public exponent mismatch"

    def compute_private_exponent(self):
        """Compute private exponent d given public key (e,n)

        Returns:
            private exponent d of the rsa cryptosystem
        """
        return inverse(self.e, self.phi)

    def decrypt(self, c):
        """RSA decryption

        Arguments:
            c {long} -- ciphertext

        Returns:
            decrypted ciphertext as an integer
        """

        return pow(c, self.d, self.n)

    def decrypt_as_bytes(self, c):
        """Decrypts ciphertext and converts it to bytes to be read as a
        string if applicable

        Arguments:
            c {long} -- ciphertext

        Returns:
            decrypted ciphertext as a byte string
        """
        return self.num_to_bytes(self.decrypt(c))
