"""
Unit tests for Encryption Toolkit
"""

import pytest
import json
import os
import sys

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from encryption_toolkit import EncryptionToolkit, app


@pytest.fixture
def toolkit():
    return EncryptionToolkit()


@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as c:
        yield c


class TestGenerateKey:
    def test_returns_valid_fernet_key(self, toolkit):
        key = toolkit.generate_key()
        assert isinstance(key, bytes)
        assert len(key) == 44  # Fernet keys are 44 url-safe base64 bytes

    def test_keys_are_unique(self, toolkit):
        k1 = toolkit.generate_key()
        k2 = toolkit.generate_key()
        assert k1 != k2


class TestEncryptDecrypt:
    def test_roundtrip(self, toolkit):
        key = toolkit.generate_key()
        plaintext = "Hello, world!"
        encrypted = toolkit.encrypt_text(plaintext, key)
        assert encrypted is not None
        assert encrypted != plaintext
        decrypted = toolkit.decrypt_text(encrypted, key)
        assert decrypted == plaintext

    def test_wrong_key_returns_none(self, toolkit):
        key1 = toolkit.generate_key()
        key2 = toolkit.generate_key()
        encrypted = toolkit.encrypt_text("secret", key1)
        result = toolkit.decrypt_text(encrypted, key2)
        assert result is None

    def test_invalid_ciphertext_returns_none(self, toolkit):
        key = toolkit.generate_key()
        result = toolkit.decrypt_text("not-valid-ciphertext", key)
        assert result is None


class TestHashText:
    def test_sha256_consistent(self, toolkit):
        h1 = toolkit.hash_text("test")
        h2 = toolkit.hash_text("test")
        assert h1 == h2
        assert len(h1) == 64  # SHA-256 hex digest length

    def test_different_inputs_different_hashes(self, toolkit):
        h1 = toolkit.hash_text("abc")
        h2 = toolkit.hash_text("xyz")
        assert h1 != h2

    def test_unsupported_algorithm_returns_none(self, toolkit):
        assert toolkit.hash_text("test", algorithm="blake2") is None


class TestGeneratePassword:
    def test_correct_length(self, toolkit):
        for length in [8, 16, 32]:
            pw = toolkit.generate_password(length=length)
            assert len(pw) == length

    def test_returns_string(self, toolkit):
        pw = toolkit.generate_password()
        assert isinstance(pw, str)

    def test_no_symbols(self, toolkit):
        pw = toolkit.generate_password(length=100, include_symbols=False)
        assert all(c.isalnum() for c in pw)


class TestBase64:
    def test_roundtrip(self, toolkit):
        text = "Hello, Base64!"
        encoded = toolkit.encode_base64(text)
        assert encoded != text
        decoded = toolkit.decode_base64(encoded)
        assert decoded == text

    def test_invalid_base64_returns_none(self, toolkit):
        result = toolkit.decode_base64("!!!not-base64!!!")
        assert result is None


class TestFlaskEncryptRoute:
    def test_encrypt_valid(self, client, toolkit):
        key = toolkit.generate_key().decode()
        resp = client.post('/api/encrypt',
                           data=json.dumps({'text': 'hello', 'key': key}),
                           content_type='application/json')
        assert resp.status_code == 200
        data = resp.get_json()
        assert 'encrypted' in data
        assert data['encrypted'] is not None

    def test_encrypt_missing_data_returns_400(self, client):
        resp = client.post('/api/encrypt',
                           data=json.dumps({'text': 'hello'}),
                           content_type='application/json')
        assert resp.status_code == 400

    def test_encrypt_no_json_returns_400(self, client):
        resp = client.post('/api/encrypt', data='not json')
        assert resp.status_code == 400


class TestFlaskDecryptRoute:
    def test_decrypt_missing_data_returns_400(self, client):
        resp = client.post('/api/decrypt',
                           data=json.dumps({'encrypted_text': 'abc'}),
                           content_type='application/json')
        assert resp.status_code == 400


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
