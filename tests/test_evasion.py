"""Unit tests for Ariadne evasion module: encoding, encryption, deformed base64."""

import base64
import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "Payload_Type", "ariadne"))

from ariadne.evasion import (
    generate_deformed_alphabet,
    encode_payload,
    decode_payload,
    encrypt_payload,
    decrypt_payload,
    generate_test_vectors,
)

STANDARD_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


class TestDeformedAlphabet:
    def test_deterministic(self):
        a1 = generate_deformed_alphabet("password123")
        a2 = generate_deformed_alphabet("password123")
        assert a1 == a2

    def test_different_passwords_different_alphabets(self):
        a1 = generate_deformed_alphabet("password1")
        a2 = generate_deformed_alphabet("password2")
        assert a1 != a2

    def test_correct_length(self):
        alphabet = generate_deformed_alphabet("test")
        assert len(alphabet) == 64

    def test_contains_all_chars(self):
        alphabet = generate_deformed_alphabet("test")
        assert set(alphabet) == set(STANDARD_ALPHABET)

    def test_is_permutation(self):
        alphabet = generate_deformed_alphabet("test")
        assert sorted(alphabet) == sorted(STANDARD_ALPHABET)

    def test_differs_from_standard(self):
        alphabet = generate_deformed_alphabet("any_password")
        assert alphabet != STANDARD_ALPHABET


class TestEncoding:
    @pytest.mark.parametrize("encoding", ["deformed_base64", "standard_base64", "hex"])
    def test_roundtrip(self, encoding):
        alphabet = generate_deformed_alphabet("test_password")
        data = b"Hello, World! This is a test payload."
        encoded = encode_payload(data, encoding, alphabet)
        decoded = decode_payload(encoded, encoding, alphabet)
        assert decoded == data

    def test_deformed_differs_from_standard(self):
        alphabet = generate_deformed_alphabet("test")
        data = b"test data for encoding"
        deformed = encode_payload(data, "deformed_base64", alphabet)
        standard = encode_payload(data, "standard_base64", alphabet)
        assert deformed != standard

    def test_hex_encoding(self):
        data = b"\x00\x01\x02\xff"
        encoded = encode_payload(data, "hex", "")
        assert encoded == "000102ff"
        decoded = decode_payload(encoded, "hex", "")
        assert decoded == data

    def test_empty_data(self):
        alphabet = generate_deformed_alphabet("test")
        for encoding in ["deformed_base64", "standard_base64", "hex"]:
            encoded = encode_payload(b"", encoding, alphabet)
            decoded = decode_payload(encoded, encoding, alphabet)
            assert decoded == b""

    def test_binary_data(self):
        alphabet = generate_deformed_alphabet("test")
        data = bytes(range(256))
        for encoding in ["deformed_base64", "standard_base64", "hex"]:
            encoded = encode_payload(data, encoding, alphabet)
            decoded = decode_payload(encoded, encoding, alphabet)
            assert decoded == data


class TestEncryption:
    def setup_method(self):
        self.key = os.urandom(32)

    def test_roundtrip(self):
        plaintext = b"Secret message for testing"
        encrypted = encrypt_payload(plaintext, self.key)
        decrypted = decrypt_payload(encrypted, self.key)
        assert decrypted == plaintext

    def test_different_ciphertexts(self):
        plaintext = b"Same message"
        enc1 = encrypt_payload(plaintext, self.key)
        enc2 = encrypt_payload(plaintext, self.key)
        assert enc1 != enc2  # different IVs

    def test_wrong_key_fails(self):
        plaintext = b"Secret"
        encrypted = encrypt_payload(plaintext, self.key)
        wrong_key = os.urandom(32)
        with pytest.raises(ValueError):
            decrypt_payload(encrypted, wrong_key)

    def test_tampered_data_fails(self):
        plaintext = b"Important data"
        encrypted = encrypt_payload(plaintext, self.key)
        tampered = bytearray(encrypted)
        tampered[20] ^= 0xFF
        with pytest.raises(ValueError):
            decrypt_payload(bytes(tampered), self.key)

    def test_empty_plaintext(self):
        encrypted = encrypt_payload(b"", self.key)
        decrypted = decrypt_payload(encrypted, self.key)
        assert decrypted == b""

    def test_large_plaintext(self):
        plaintext = os.urandom(65536)
        encrypted = encrypt_payload(plaintext, self.key)
        decrypted = decrypt_payload(encrypted, self.key)
        assert decrypted == plaintext

    def test_wire_format_length(self):
        plaintext = b"Test"
        encrypted = encrypt_payload(plaintext, self.key)
        # IV(16) + ciphertext(at least 16 for one AES block) + HMAC(32)
        assert len(encrypted) >= 16 + 16 + 32


class TestTestVectors:
    def test_generate_vectors(self):
        vectors = generate_test_vectors("password", os.urandom(32))
        assert "password" in vectors
        assert "alphabet" in vectors
        assert "aes_key_hex" in vectors
        assert "encoded_deformed" in vectors
        assert "encoded_standard" in vectors


class TestFullPipeline:
    def test_encode_encrypt_decrypt_decode(self):
        password = "pipeline_test"
        key = os.urandom(32)
        alphabet = generate_deformed_alphabet(password)
        original = b"action|task_id|shell|whoami"

        encrypted = encrypt_payload(original, key)
        encoded = encode_payload(encrypted, "deformed_base64", alphabet)

        decoded = decode_payload(encoded, "deformed_base64", alphabet)
        decrypted = decrypt_payload(decoded, key)

        assert decrypted == original
