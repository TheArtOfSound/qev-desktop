declare module "libsodium-wrappers-sumo" {
  const sodium: {
    ready: Promise<void>;
    crypto_pwhash_ALG_ARGON2ID13: number;
    randombytes_buf(length: number): Uint8Array;
    randombytes_uniform(upperBound: number): number;
    crypto_pwhash(
      outputLength: number,
      password: Uint8Array,
      salt: Uint8Array,
      opsLimit: number,
      memLimit: number,
      algorithm: number
    ): Uint8Array;
    crypto_aead_xchacha20poly1305_ietf_encrypt(
      message: Uint8Array,
      additionalData: Uint8Array | null,
      secretNonce: null,
      publicNonce: Uint8Array,
      key: Uint8Array
    ): Uint8Array;
    crypto_aead_xchacha20poly1305_ietf_decrypt(
      secretNonce: null,
      ciphertext: Uint8Array,
      additionalData: Uint8Array | null,
      publicNonce: Uint8Array,
      key: Uint8Array
    ): Uint8Array;
    memzero(bytes: Uint8Array): void;
  };

  export default sodium;
}
