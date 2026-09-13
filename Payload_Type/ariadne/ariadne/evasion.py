import hashlib
import hmac
import os
import struct
from typing import Optional

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

STANDARD_B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
AES_KEY_SIZE = 32
AES_BLOCK_SIZE = 16
HMAC_SIZE = 32


def generate_deformed_alphabet(password: str) -> str:
    """Generate a deterministic shuffled base64 alphabet from a password.

    Uses SHA-256 to derive seed bytes, then performs a Fisher-Yates shuffle
    on the standard base64 alphabet. Same password always produces the same
    shuffled alphabet.
    """
    seed = hashlib.sha256(password.encode("utf-8")).digest()
    chars = list(STANDARD_B64_ALPHABET)

    seed_bytes = seed
    byte_idx = 0

    for i in range(len(chars) - 1, 0, -1):
        if byte_idx + 2 > len(seed_bytes):
            seed_bytes = hashlib.sha256(seed_bytes).digest()
            byte_idx = 0
        rand_val = struct.unpack(">H", seed_bytes[byte_idx:byte_idx + 2])[0]
        byte_idx += 2
        j = rand_val % (i + 1)
        chars[i], chars[j] = chars[j], chars[i]

    return "".join(chars)


def _make_trans_tables(deformed_alphabet: str):
    encode_table = str.maketrans(STANDARD_B64_ALPHABET, deformed_alphabet)
    decode_table = str.maketrans(deformed_alphabet, STANDARD_B64_ALPHABET)
    return encode_table, decode_table


def encode_payload(data: bytes, encoding: str, deformed_alphabet: Optional[str] = None) -> str:
    """Encode binary data using the specified encoding scheme."""
    import base64

    if encoding == "deformed_base64":
        if not deformed_alphabet:
            raise ValueError("deformed_alphabet required for deformed_base64 encoding")
        standard = base64.b64encode(data).decode("ascii")
        encode_table, _ = _make_trans_tables(deformed_alphabet)
        return standard.translate(encode_table)

    elif encoding == "standard_base64":
        return base64.b64encode(data).decode("ascii")

    elif encoding == "hex":
        return data.hex()

    raise ValueError(f"Unknown encoding: {encoding}")


def decode_payload(encoded: str, encoding: str, deformed_alphabet: Optional[str] = None) -> bytes:
    """Decode an encoded string back to binary data."""
    import base64

    if encoding == "deformed_base64":
        if not deformed_alphabet:
            raise ValueError("deformed_alphabet required for deformed_base64 encoding")
        _, decode_table = _make_trans_tables(deformed_alphabet)
        standard = encoded.translate(decode_table)
        return base64.b64decode(standard)

    elif encoding == "standard_base64":
        return base64.b64decode(encoded)

    elif encoding == "hex":
        return bytes.fromhex(encoded)

    raise ValueError(f"Unknown encoding: {encoding}")


def encrypt_payload(plaintext: bytes, aes_key: bytes) -> bytes:
    """Encrypt with AES-256-CBC + HMAC-SHA256.

    Returns: IV (16 bytes) || ciphertext || HMAC (32 bytes)
    """
    if len(aes_key) != AES_KEY_SIZE:
        raise ValueError(f"AES key must be {AES_KEY_SIZE} bytes")

    iv = os.urandom(AES_BLOCK_SIZE)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES_BLOCK_SIZE))

    blob = iv + ciphertext
    mac = hmac.new(aes_key, blob, hashlib.sha256).digest()

    return blob + mac


def decrypt_payload(blob: bytes, aes_key: bytes) -> bytes:
    """Decrypt AES-256-CBC + HMAC-SHA256.

    Expects: IV (16 bytes) || ciphertext || HMAC (32 bytes)
    """
    if len(aes_key) != AES_KEY_SIZE:
        raise ValueError(f"AES key must be {AES_KEY_SIZE} bytes")

    if len(blob) < AES_BLOCK_SIZE + AES_BLOCK_SIZE + HMAC_SIZE:
        raise ValueError("Encrypted blob too short")

    mac_received = blob[-HMAC_SIZE:]
    iv_and_ct = blob[:-HMAC_SIZE]

    mac_computed = hmac.new(aes_key, iv_and_ct, hashlib.sha256).digest()
    if not hmac.compare_digest(mac_received, mac_computed):
        raise ValueError("HMAC verification failed")

    iv = iv_and_ct[:AES_BLOCK_SIZE]
    ciphertext = iv_and_ct[AES_BLOCK_SIZE:]

    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES_BLOCK_SIZE)


def generate_test_vectors(password: str, aes_key: bytes) -> dict:
    """Generate known-good test vectors for cross-language verification."""
    alphabet = generate_deformed_alphabet(password)
    test_plaintext = b"shell|test-0001|whoami"

    return {
        "password": password,
        "alphabet": alphabet,
        "aes_key_hex": aes_key.hex(),
        "plaintext_hex": test_plaintext.hex(),
        "encoded_deformed": encode_payload(test_plaintext, "deformed_base64", alphabet),
        "encoded_standard": encode_payload(test_plaintext, "standard_base64"),
        "encoded_hex": encode_payload(test_plaintext, "hex"),
    }
