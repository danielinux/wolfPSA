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
- wolfSSL >= 5.9.2 is required: the ML-DSA backend moved to `wc_mldsa.c`,
  which wolfSSL v5.9.1 does not ship (this release is tested against
  v5.9.4-stable). Custom `user_settings.h` files enable ML-DSA with
  `WOLFSSL_HAVE_MLDSA`, not `HAVE_DILITHIUM`.
- Overlapping input and output buffers are refused with
  `PSA_ERROR_NOT_SUPPORTED` in `psa_cipher_encrypt()`/`psa_cipher_decrypt()`
  (every mode with an IV) and in `psa_cipher_update()` for the block modes
  (ECB, CBC, CBC-PKCS7). In-place `psa_cipher_update()` still works for the
  stream modes (CTR, CFB, OFB, CCM*, ChaCha20).
- Multipart AEAD streams: `psa_aead_update()` returns output as it goes and
  `psa_aead_finish()`/`psa_aead_verify()` emit only the tag, per the PSA
  contract, instead of buffering the whole payload until finish. Callers must
  size the update output buffers accordingly. Additional data supplied after
  payload has started is rejected with `PSA_ERROR_BAD_STATE`.
- Auto-assigned key ids come from the vendor range
  (`PSA_KEY_ID_VENDOR_MIN`..`PSA_KEY_ID_VENDOR_MAX`) instead of starting at 1,
  so they can no longer collide with caller-chosen persistent ids.
- Importing a persistent key under an id already in use fails with
  `PSA_ERROR_ALREADY_EXISTS` instead of overwriting the stored key.
- Key lifetimes that name a storage location other than local storage are
  rejected instead of being stored locally in plaintext.
- Stricter key policies: key-derivation inputs require
  `PSA_KEY_USAGE_DERIVE`; key agreement checks the full policy algorithm, not
  only its base; permission checks require every requested usage bit;
  `PSA_ALG_ANY_HASH` signature policies are honoured (within one family for
  HashML-DSA); `psa_copy_key()` accepts narrowing a wildcard policy to a
  concrete algorithm and intersects MAC/AEAD length wildcards.
- `psa_import_key()` checks declared bits against the data length for
  byte-string key types (HMAC, RAW_DATA, DERIVE, PASSWORD, PASSWORD_HASH,
  PEPPER), and refuses imports whose inferred bits overflow.
- Changed status codes: an empty signature, tag or reference digest reports
  `PSA_ERROR_INVALID_SIGNATURE`, as does a wrong-length raw ECDSA signature;
  a failed RSA decrypt unpad reports `PSA_ERROR_INVALID_PADDING`; an
  unsupported GCM nonce length reports `PSA_ERROR_NOT_SUPPORTED`; store
  allocation failures report `PSA_ERROR_INSUFFICIENT_MEMORY`; a store record
  that exists but cannot be opened reports `PSA_ERROR_STORAGE_FAILURE`
  instead of `PSA_ERROR_INVALID_HANDLE`.
- `NULL` buffers with zero length or zero capacity are accepted across the
  API (outputs, nonces, tags, exports, IV generation, encapsulation), and a
  zero-byte generation request succeeds.
- Shortened-tag ChaCha20-Poly1305, XChaCha20-Poly1305 and Ascon AEAD
  algorithms are rejected at setup. Ed448 PureEdDSA rejects a non-empty
  context. TLS 1.2 PSK-to-MS rejects PSKs above
  `PSA_TLS12_PSK_TO_MS_PSK_MAX_SIZE` (128).

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
- Optional thread-safe key store: with `WOLFPSA_THREAD_SAFE` a single mutex
  built on wolfCrypt's portable `wc_*Mutex` API (created in `psa_crypto_init()`)
  guards the volatile-key list and id counter for concurrent PSA callers; a
  no-op in single-threaded builds.

### Security

- Side-channel hardening is on in the default build: `WC_NO_HARDEN` was
  replaced with `TFM_TIMING_RESISTANT`, `ECC_TIMING_RESISTANT` and
  `WC_RSA_BLINDING`, so RSA and ECC private-key operations use the
  constant-time paths and RSA blinding.
- `psa_import_key()` rejects a `data_length` that would wrap the internal
  buffer size (a heap overflow for key types without an exact-length check).
- ECC keys are pinned to their curve: a public key on import and verify, the
  peer point in ECDH, and the exported public key. secp256k1 and Brainpool
  are only accepted when `HAVE_ECC_KOBLITZ` / `HAVE_ECC_BRAINPOOL` are set.
- Sensitive intermediate data is zeroized: cipher partial blocks and padded
  plaintext on every exit, the CCM init/update/finish stack state, the
  computed tag in multipart verify, KDF output on a mid-stream error, and
  export buffers on a short key-data read.
- A failed `psa_copy_key()` clears the target id, and the interruptible
  max-ops setting is held in an atomic.

### Fixed

- RSA PKCS#1 v1.5 hashed verify compared the recovered DigestInfo with the
  raw hash, so every valid signature failed; `hash_length` is now bound to
  the algorithm's digest length on sign and verify.
- PBKDF2-AES-CMAC-PRF-128 normalized 16-byte passwords instead of using them
  directly (RFC 4615), deriving keys that disagreed with other implementations.
- The CCM counter increment lost its carry for nonces shorter than 13 bytes,
  silently corrupting multipart CCM output past the first block.
- The TLS 1.2 PRF KDFs passed the wrong MAC algorithm id to `wc_PRF_TLS()`.
- OFB and CFB decryption keyed AES for the decrypt direction; both modes
  run the block cipher forward, so they now use the encrypt key schedule.
- Ed25519ph/Ed448ph sign/verify enforce a 64-byte prehash, and SHAKE256-512
  was added to the hash engine so `psa_sign_message()` and
  `psa_verify_message()` work for Ed448ph.
- Standalone EdDSA and Montgomery key generation and public-key export work in
  builds without `HAVE_ECC`; `psa_export_public_key()` no longer falls through
  for disabled PQC backends.
- A second `psa_aead_set_lengths()` call reports `PSA_ERROR_BAD_STATE`;
  multipart AEAD length checks and the streaming GCM guards were corrected.
- `psa_hash_compare()` rejects a `NULL` reference hash; generic ECDH reports
  NOT_SUPPORTED up front when no RNG is built, instead of failing at the end.
- The HMAC path of `psa_mac_*` never called `wc_HmacInit()`, so it
  ran with devId 0 and a callback registered on device 0 captured wolfPSA's
  HMACs while every other algorithm stayed local.
- The one-shot AEAD paths called `wc_AesFree()` on uninitialized heap
  when `wc_AesInit()` failed, reading `Aes.devId` and freeing `Aes.streamData`
  from unwritten memory. Allocation and init are now one step.

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
- `make unit-run` builds and runs every unit and regression test, and
  `make cov` produces an HTML gcov coverage report for `src/`.
- CI runs the regression suite, a build-configuration matrix with each
  feature switched off, and every functional workflow against both wolfSSL
  master and `v5.9.4-stable`.

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
- The module selects the wolfSSL module's constant-time AES backend and ECC
  zero-hash allowance by default, and the store returns `MEMORY_E` when an
  allocation fails.


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
