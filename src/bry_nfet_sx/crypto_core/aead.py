from __future__ import annotations

from hashlib import sha256
import hmac

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


def derive_aead_key(master_key: bytes, context: bytes) -> bytes:
    """
    Derive a 32-byte AEAD key.
    """
    return hmac.new(
        master_key,
        b"BRY-NFET-SX|AEAD|KEY|" + context,
        sha256,
    ).digest()


def derive_aead_nonce(aead_key: bytes, packet_nonce: bytes, context: bytes) -> bytes:
    """
    Derive a 12-byte ChaCha20-Poly1305 nonce from the user packet nonce.

    IMPORTANT:
    Reusing the same packet_nonce under the same master key/context reuses
    the effective AEAD nonce. That is unsafe for real deployment.
    """
    material = hmac.new(
        aead_key,
        b"BRY-NFET-SX|AEAD|NONCE|" + packet_nonce + b"|" + context,
        sha256,
    ).digest()
    return material[:12]


def encrypt_bytes(
    master_key: str,
    packet_nonce: str,
    context: str,
    plaintext: bytes,
    aad: bytes,
) -> bytes:
    key = derive_aead_key(master_key.encode("utf-8"), context.encode("utf-8"))
    nonce = derive_aead_nonce(key, packet_nonce.encode("utf-8"), context.encode("utf-8"))
    aead = ChaCha20Poly1305(key)
    return aead.encrypt(nonce, plaintext, aad)


def decrypt_bytes(
    master_key: str,
    packet_nonce: str,
    context: str,
    ciphertext: bytes,
    aad: bytes,
) -> bytes:
    key = derive_aead_key(master_key.encode("utf-8"), context.encode("utf-8"))
    nonce = derive_aead_nonce(key, packet_nonce.encode("utf-8"), context.encode("utf-8"))
    aead = ChaCha20Poly1305(key)
    return aead.decrypt(nonce, ciphertext, aad)
