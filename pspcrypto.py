#!/usr/bin/env python3

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidSignature
import itertools


class MGF1(object):
    def __init__(self, hashf):
        self.hashf = hashf
        self.digest_size = hashf().digest_size

    def gen(self, seed):
        for counter in itertools.count():
            c = counter.to_bytes(4, 'big')
            yield from self.hashf(seed + c).digest()

    def compute(self, seed, size):
        return bytes(itertools.islice(self.gen(seed), size))


class SignKey(object):
    def __init__(self, exp, mod):
        nums = rsa.RSAPublicNumbers(exp, mod)
        self.pub = nums.public_key(backend=default_backend())

    @classmethod
    def build(cls, o):
        return cls(o.pubexp, o.modulus)

    def verify(self, signed_data, signature):
        # In some cases, we may give more data than necessary
        split = self.pub.key_size // 8
        signature, rest = signature[:split], signature[split:]

        assert len(signature) == split
        assert not rest.strip(b'\xff')

        h = hashes.SHA256() if len(signature) == 256 else hashes.SHA384()

        try:
            self.pub.verify(
                signature,
                signed_data,
                padding.PSS(
                    mgf=padding.MGF1(h),
                    salt_length=h.digest_size,
                ),
                h
            )
            return True
        except InvalidSignature:
            return False

    @classmethod
    def build_priv(cls):
        priv = rsa.generate_private_key(public_exponent=65537, key_size=0x800)
        pub = priv.public_key()
        nums = pub.public_numbers()
        res = cls(nums.e, nums.n)
        res.priv = priv
        return res

    def sign(self, data, size):
        h = hashes.SHA256() if size == 256 else hashes.SHA384()
        return self.priv.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(h),
                salt_length=h.digest_size,
            ),
            h
        )


class CryptKey(object):
    # Taken from PSPTool
    KNOWN_KEYS = {
        # ZEN+
        '2ef9a17d93ae1b7307845b22b2883dc2': '4c77636532fe4c6fd6b9d6d7b51ede59',
        # ZEN ? Either the key is wrong, or the algorithm differs
        # '50d00f3cbcb8f1945a7daa872224107b':
        # '491e401a401ec1b2284600f099fde868',
    }
    KNOWN_KEYS = {
        bytes.fromhex(k): bytes.fromhex(v)
        for k, v in KNOWN_KEYS.items()
    }

    def __init__(self, key):
        self.key = key

    @classmethod
    def build(cls, wrapped_key):
        assert len(wrapped_key) == 0x10
        key = cls.KNOWN_KEYS.get(wrapped_key)
        if key:
            return cls(key)
        else:
            return None

    def decrypt(self, data, wrapped_key, iv):
        ecb_decrypt = Cipher(
            algorithms.AES(self.key), modes.ECB(),
            backend=default_backend()
        ).decryptor()
        key = ecb_decrypt.update(wrapped_key) + ecb_decrypt.finalize()

        cbc_decrypt = Cipher(
            algorithms.AES(key), modes.CBC(iv),
            backend=default_backend()
        ).decryptor()
        return cbc_decrypt.update(data) + cbc_decrypt.finalize()


def fletcher32(data):
    c0 = 0xffff
    c1 = 0xffff
    pptr = [
        int.from_bytes(data[i:i+2], 'little')
        for i in range(0, len(data), 2)
    ]

    for i in range(0, len(pptr), 359):
        for b in pptr[i:i+359]:
            c0 += b
            c1 += c0
        c0 = (c0 & 0xffff) + (c0 >> 16)
        c1 = (c1 & 0xffff) + (c1 >> 16)

    c0 = (c0 & 0xffff) + (c0 >> 16)
    c1 = (c1 & 0xffff) + (c1 >> 16)
    checksum = (c1 << 16) + c0
    return checksum
