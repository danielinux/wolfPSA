# Changelog

## v5.9.4

PSA Certified Crypto API 1.4 + PQC extension 1.4.

Upgrade of the public API surface and implementation to PSA Certified
Crypto API 1.4 Final and the PQC extension 1.4. This release is validated
against wolfSSL `v5.9.4-stable`: unit tests, TLS client/server, wolfCrypt
benchmark, the Arm PSA Architecture Test Suite and the Zephyr 4.3/4.4
samples run in CI against both that tag and wolfSSL master.

### Breaking changes

- ML-DSA now follows the PSA 1.4 PQC extension: key bits are 128/192/256
  (security strength, ML-DSA-44/65/87) instead of the previous 2/3/5
  level convention, and the key-pair import/export format is the 32-byte
  FIPS 204 seed xi (public keys remain raw pk bytes).
- The nonstandard `psa_ml_dsa_generate_key/sign/verify` exports and the
  `PSA_ML_DSA_PARAMETER_*` / `psa_ml_dsa_parameter_t` macros were removed;
  use the standard PSA key management and signature APIs instead.
- Key derivation now follows the PSA error-state rule: once a call on a
  `psa_key_derivation_operation_t` fails, the operation is in an error state
  and every later call reports `PSA_ERROR_BAD_STATE` until
  `psa_key_derivation_abort()`. Code that ignored a rejected input and kept
  deriving will now fail. Three statuses are outside the rule:
  `psa_key_derivation_get_capacity()` stays callable (it is a read-only
  query), `PSA_ERROR_INVALID_SIGNATURE` from a verify step is a completed
  operation reporting a mismatch, and `PSA_ERROR_INVALID_HANDLE` is a key
  argument rejected before the operation is touched.
- `psa_key_derivation_set_capacity()` is outside the error-state rule as well:
  PSA specifies that a rejected capacity leaves the operation valid and its
  capacity unchanged, so it no longer poisons the operation.
- `wolfPSA_Store_Close()` returns `int` instead of `void`, so that a write
  handle whose write failed reports `WOLFPSA_STORE_IO_ERROR` at close rather
  than silently succeeding. Out-of-tree `WOLFPSA_CUSTOM_STORE` backends must
  update the signature.
- `psa_import_key()` validates key data more strictly: a zero-length blob, an
  ECC point whose length contradicts the declared curve, and a Weierstrass
  public key that is not `0x04 || X || Y` of the exact expected length are now
  rejected. A curve wolfPSA does not implement reports
  `PSA_ERROR_NOT_SUPPORTED`; data that contradicts a curve it does implement
  reports `PSA_ERROR_INVALID_ARGUMENT`.
- The POSIX store requires a private store directory on the read path too, not
  only when creating it. A directory that is group- or other-writable, or owned
  by neither the effective uid nor root, is refused, and every ancestor is
  checked as well (a shared parent such as `/tmp` is accepted when sticky).
  Stores that relied on a permissive directory will stop opening.

### Added

- Key encapsulation: `psa_encapsulate()` / `psa_decapsulate()` with
  PSA_ALG_ML_KEM. ML-KEM key pairs use the 64-byte d||z seed format with
  bits 512/768/1024; the shared secret is returned as a new key.
- ML-DSA through the standard APIs: hedged and deterministic pure ML-DSA
  via `psa_sign_message`/`psa_verify_message`, plus HashML-DSA variants
  usable through both the message and hash entry points.
- Context-aware signatures: `psa_sign_message_with_context()`,
  `psa_verify_message_with_context()`, `psa_sign_hash_with_context()`,
  `psa_verify_hash_with_context()` and PSA_ALG_EDDSA_CTX (Ed25519ctx),
  with context support for Ed25519ph/Ed448 and the ML-DSA family.
- Verify-only LMS/HSS and XMSS/XMSS^MT public-key support through
  `psa_verify_message` (PSA_ALG_LMS/HSS/XMSS/XMSS_MT).
- XOF API: incremental SHAKE128/SHAKE256 via `psa_xof_setup/update/
  output/abort` (Ascon XOFs report NOT_SUPPORTED).
- Key wrapping: `psa_wrap_key()` / `psa_unwrap_key()` with PSA_ALG_KW
  (AES-KW, RFC 3394) and the new WRAP/UNWRAP usage flags (PSA_ALG_KWP
  reports NOT_SUPPORTED).
- Ascon-Hash256 and Ascon-AEAD128 (one-shot), XChaCha20-Poly1305
  (one-shot, 24-byte nonce) with the PSA_KEY_TYPE_XCHACHA20/ASCON key
  types.
- SP800-108r1 counter-mode KDFs: PSA_ALG_SP800_108_COUNTER_HMAC(hash)
  and PSA_ALG_SP800_108_COUNTER_CMAC.
- `psa_check_key_usage()`, `psa_generate_key_custom()` and
  `psa_key_derivation_output_key_custom()` (default parameters only).
- 1.4 semantic change: ECDSA and deterministic ECDSA are treated as
  equivalent when verifying signatures.
- Complete 1.4 macro surface: PQC classifier/encoding macros (ML-DSA,
  ML-KEM, SLH-DSA, LMS/HSS, XMSS), WPA3-SAE values, encapsulation and
  key-wrap size macros, hash-suspend format constants, and PQC arms in
  the signature/export size macros (PSA_SIGNATURE_MAX_SIZE is now 4627).
- Stubs returning PSA_ERROR_NOT_SUPPORTED for the interruptible
  operations, `psa_attach_key()` and `psa_hash_suspend/resume()`.
  SLH-DSA key types are recognized but report NOT_SUPPORTED.
- New coverage tests: ML-DSA, ML-KEM/KEM API, XOF, AES-KW, signature
  contexts, LMS/XMSS verify, Ascon/XChaCha, SP800-108 and 1.4 misc.
- `psa_purge_key()`: confirms a key exists and reports its status (wolfPSA
  keeps no in-RAM cache of persistent key material, so there is nothing to
  evict).
- Crypto callback offload: `wolfPSA_SetDefaultDevID()` now reaches every
  algorithm whose wolfCrypt initializer accepts a devId, adding RSA, ECC,
  Ed25519, Ed448, X25519, X448, CMAC, HKDF, PBKDF2, the RNG and the
  SHA-1/SHA-2 families. The setting is held in one atomic, an unset devId
  defers to `wc_CryptoCb_DefaultDevID()`, and `WOLFPSA_DEVID_DEFAULT`
  restores that, so no setting is a one-way door. New
  `wolfPSA_RegisterCryptoCb()` / `wolfPSA_UnRegisterCryptoCb()` register
  against the device table wolfPSA dispatches through. Deterministic ECDSA,
  AES-KW, RIPEMD-160, MD5, Ascon and ChaCha20-Poly1305 stay local;
  `wolfpsa/psa_engine.h` documents why, plus the X25519 and
  `WOLF_CRYPTO_CB_FIND` caveats.
- Fixed: the HMAC path of `psa_mac_*` never called `wc_HmacInit()`, so it
  ran with devId 0 and a callback registered on device 0 captured wolfPSA's
  HMACs while every other algorithm stayed local.
- Fixed: the one-shot AEAD paths called `wc_AesFree()` on uninitialized heap
  when `wc_AesInit()` failed, reading `Aes.devId` and freeing `Aes.streamData`
  from unwritten memory. Allocation and init are now one step.
- Optional thread-safe key store: with `WOLFPSA_THREAD_SAFE` a single mutex
  built on wolfCrypt's portable `wc_*Mutex` API (created in `psa_crypto_init()`)
  guards the volatile-key list and id counter for concurrent PSA callers; a
  no-op in single-threaded builds.

### Build configuration

- AES backend policy (`src/psa_config.h`, included by every wolfPSA source):
  PSA expects constant-time AES, so the build now fails unless it selects a
  backend with no secret-indexed table load -- `WC_AES_BITSLICED`,
  `WOLFSSL_AES_TOUCH_LINES`, or one of the hardware AES cores that compile no
  software tables. Define `WOLFPSA_AES_FAST` (or build with `AES_FAST=1`) to
  waive the requirement and take wolfCrypt's faster T-table core instead.
  `WOLFSSL_AESNI` is not accepted on its own: wolfCrypt falls back to the
  T-table `AesSetKey_C()` when AES-NI is unavailable at runtime.
  `WC_AES_BITSLICED` requires `HAVE_AES_ECB` and adds
  `bs_word bs_key[15 * 16 * WC_AES_BS_WORD_SIZE]` to `Aes`: 122,880 bytes at
  the default word size of 64, taking `sizeof(Aes)` to 123,296. Hence
  `zephyr/user_settings_example.h` selects `WOLFSSL_AES_TOUCH_LINES`, which
  leaves `sizeof(Aes)` at 416.
- The one-shot AEAD `Aes` and the PBKDF2/SP800-108 `Cmac` objects moved from
  the stack to `XMALLOC`, so a frame no longer grows with the AES backend.
- `WC_ALLOW_ECC_ZERO_HASH` is required for any build with `HAVE_ECC`, checked
  from the same shared header rather than from `psa_ecc.c` alone.
- The multipart AEAD context holds its GCM and CCM `Aes` in a union, since an
  operation is one or the other. Under `WC_AES_BITSLICED` that takes
  `sizeof(wolfpsa_aead_ctx_t)` from 247,032 bytes to 123,736.

### Zephyr module

- Added wolfPSA as a Zephyr **PSA Crypto provider**: selected via
  `CONFIG_PSA_CRYPTO_PROVIDER_CUSTOM` (Zephyr >= 4.3), it supplies the PSA Crypto
  API in place of Mbed TLS while reusing the wolfCrypt core built by the wolfSSL
  Zephyr module. Volatile and persistent keys, RNG, and the standard PSA surface
  work with no Mbed TLS symbol in the image.
- wolfCrypt AES-256-GCM custom ITS transform
  (`CONFIG_SECURE_STORAGE_ITS_TRANSFORM_IMPLEMENTATION_CUSTOM`) provides
  encryption-at-rest for persistent keys, replacing Zephyr's Mbed-TLS-coupled
  AEAD transform. `psa_get_key_attributes()` restores the key id, for volatile
  keys too; key creation ignores that id when the lifetime is volatile, so the
  returned attributes stay usable as a key-creation template. Persistent keys
  use the crypto-provider ITS namespace (isolated from application
  `psa_its_*`/`psa_ps_*`).
- wolfPSA follows the user's wolfCrypt configuration and exposes exactly the
  enabled, wolfPSA-implemented algorithms as the PSA API.


## v5.9.1

Initial official release of `wolfPSA`. This project follows wolfSSL version numbering.

- First public wolfPSA release: a PSA Crypto engine implemented in C on top of wolfCrypt.
- Provides PSA Crypto API entry points intended for PSA clients such as wolfSSL built with `WOLFSSL_HAVE_PSA` and the Arm PSA Architecture Test Suite.
- Ships both static and shared builds: `libwolfpsa.a` and `libwolfpsa.so`.
- Includes core PSA lifecycle, random generation, key management, key storage, cipher, AEAD, hash, MAC, asymmetric crypto, key derivation, and TLS 1.3 PRF/HKDF support.
- Symmetric crypto coverage includes AES, ChaCha20, ChaCha20-Poly1305, and configured legacy compatibility paths such as DES/3DES where enabled.
- Hash and MAC support includes SHA-1, SHA-2, SHA-3, HMAC, CMAC, plus configured compatibility support for MD5 and RIPEMD-160.
- Asymmetric crypto support includes RSA, ECC/ECDSA/ECDH, Curve25519/Curve448, and Ed25519/Ed448.
- Includes persistent PSA key storage with a default POSIX filesystem-backed store for local and test deployments.
- Includes post-quantum and hash-based crypto integration sources for builds that enable wolfCrypt support, including ML-KEM, ML-DSA, LMS, and XMSS.
- Includes standalone integration tests and demos for PSA API calls, PSA-backed wolfCrypt benchmarking, and a TLS server/client flow using PSA-managed keys and certificate pinning.
- Includes target integration and scripts for running the Arm PSA Architecture Test Suite; current documented crypto results are 65 passed tests, 13 skipped, and 0 failed.
