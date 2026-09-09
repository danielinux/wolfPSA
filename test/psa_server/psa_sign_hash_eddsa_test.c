/* psa_sign_hash_eddsa_test.c
 *
 * Regression test for F-13268: the hash-signing workers must reject
 * message-only EdDSA algorithms (PSA_ALG_PURE_EDDSA and
 * PSA_ALG_EDDSA_CTX). Before the fix, psa_sign_hash() /
 * psa_verify_hash() accepted these algorithms and the Ed25519/Ed448
 * helpers interpreted the supplied hash buffer as a raw message,
 * performing a message-only EdDSA operation through the hash API.
 *
 * A PureEdDSA key (policy = PSA_ALG_PURE_EDDSA) is used as the fixture:
 * psa_sign_hash_with_context() and psa_verify_hash_with_context() with
 * that key and the PureEdDSA algorithm must return
 * PSA_ERROR_INVALID_ARGUMENT (the hash workers only accept SIGN_HASH
 * algorithms such as Ed25519ph / Ed448ph).
 *
 * Build:
 *   gcc -o /tmp/psa_sign_hash_eddsa_test \
 *       test/psa_server/psa_sign_hash_eddsa_test.c \
 *       -I/opt/dev/src/wolfssl -I/opt/dev/src/wolfssl/wolfssl \
 *       -I/opt/dev/src/wolfPSA -I/opt/dev/src/wolfPSA/wolfpsa \
 *       -I/opt/dev/src/wolfPSA/src -I/opt/dev/src/wolfPSA/test/psa_server \
 *       /opt/dev/src/wolfPSA/libwolfpsa.a
 */

#include <stdio.h>
#include <wolfpsa/psa/crypto.h>

static int test_sign_hash_rejects_pure_eddsa(void)
{
    psa_key_attributes_t attrs;
    psa_key_id_t key = PSA_KEY_ID_NULL;
    uint8_t hash[32];
    uint8_t sig[114];
    size_t sig_len = 0;
    psa_status_t status;
    int ret = 0;

    attrs = psa_key_attributes_init();
    psa_set_key_type(&attrs,
                     PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS));
    psa_set_key_bits(&attrs, 448);
    psa_set_key_usage_flags(&attrs,
                            PSA_KEY_USAGE_SIGN_HASH |
                            PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&attrs, PSA_ALG_PURE_EDDSA);
    psa_set_key_lifetime(&attrs, PSA_KEY_LIFETIME_VOLATILE);

    status = psa_generate_key(&attrs, &key);
    if (status != PSA_SUCCESS) {
        printf("FAIL pure_eddsa sign_hash: key gen status=%d\n", (int)status);
        return 1;
    }

    for (int i = 0; i < 32; i++) {
        hash[i] = (uint8_t)(i + 1);
    }

    status = psa_sign_hash_with_context(key, PSA_ALG_PURE_EDDSA,
                                        hash, sizeof(hash), NULL, 0, sig, sizeof
                                        (sig), &sig_len);
    if (status != PSA_ERROR_INVALID_ARGUMENT) {
        printf("FAIL pure_eddsa sign_hash: expected INVALID_ARGUMENT, "
               "got %d\n", (int)status);
        ret = 1;
    } else {
        printf("PASS pure_eddsa sign_hash rejected\n");
    }

    (void)psa_destroy_key(key);
    return ret;
}

static int test_sign_hash_rejects_eddsa_ctx(void)
{
    psa_key_attributes_t attrs;
    psa_key_id_t key = PSA_KEY_ID_NULL;
    uint8_t hash[32];
    uint8_t ctx[16];
    uint8_t sig[114];
    size_t sig_len = 0;
    psa_status_t status;
    int ret = 0;

    attrs = psa_key_attributes_init();
    psa_set_key_type(&attrs,
                     PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS));
    psa_set_key_bits(&attrs, 448);
    psa_set_key_usage_flags(&attrs,
                            PSA_KEY_USAGE_SIGN_HASH |
                            PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&attrs, PSA_ALG_EDDSA_CTX);
    psa_set_key_lifetime(&attrs, PSA_KEY_LIFETIME_VOLATILE);

    status = psa_generate_key(&attrs, &key);
    if (status != PSA_SUCCESS) {
        printf("FAIL eddsa_ctx sign_hash: key gen status=%d\n", (int)status);
        return 1;
    }

    for (int i = 0; i < 32; i++) {
        hash[i] = (uint8_t)(i + 10);
    }
    for (int i = 0; i < 16; i++) {
        ctx[i] = (uint8_t)(i + 100);
    }

    status = psa_sign_hash_with_context(key, PSA_ALG_EDDSA_CTX,
                                        hash, sizeof(hash), ctx, sizeof(ctx),
                                        sig, sizeof(sig), &sig_len);
    if (status != PSA_ERROR_INVALID_ARGUMENT) {
        printf("FAIL eddsa_ctx sign_hash: expected INVALID_ARGUMENT, "
               "got %d\n", (int)status);
        ret = 1;
    } else {
        printf("PASS eddsa_ctx sign_hash rejected\n");
    }

    (void)psa_destroy_key(key);
    return ret;
}

static int test_verify_hash_rejects_pure_eddsa(void)
{
    psa_key_attributes_t attrs;
    psa_key_id_t key = PSA_KEY_ID_NULL;
    uint8_t hash[32];
    uint8_t sig[114];
    psa_status_t status;
    int ret = 0;

    attrs = psa_key_attributes_init();
    psa_set_key_type(&attrs,
                     PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS));
    psa_set_key_bits(&attrs, 448);
    psa_set_key_usage_flags(&attrs,
                            PSA_KEY_USAGE_SIGN_HASH |
                            PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&attrs, PSA_ALG_PURE_EDDSA);
    psa_set_key_lifetime(&attrs, PSA_KEY_LIFETIME_VOLATILE);

    status = psa_generate_key(&attrs, &key);
    if (status != PSA_SUCCESS) {
        printf("FAIL pure_eddsa verify_hash: key gen status=%d\n",
               (int)status);
        return 1;
    }

    for (int i = 0; i < 32; i++) {
        hash[i] = (uint8_t)(i + 1);
    }
    for (int i = 0; i < (int)sizeof(sig); i++) {
        sig[i] = (uint8_t)i;
    }

    status = psa_verify_hash_with_context(key, PSA_ALG_PURE_EDDSA,
                                          hash, sizeof(hash), NULL, 0, sig,
                                          sizeof(sig));
    if (status != PSA_ERROR_INVALID_ARGUMENT) {
        printf("FAIL pure_eddsa verify_hash: expected INVALID_ARGUMENT, "
               "got %d\n", (int)status);
        ret = 1;
    } else {
        printf("PASS pure_eddsa verify_hash rejected\n");
    }

    (void)psa_destroy_key(key);
    return ret;
}

static int test_verify_hash_rejects_eddsa_ctx(void)
{
    psa_key_attributes_t attrs;
    psa_key_id_t key = PSA_KEY_ID_NULL;
    uint8_t hash[32];
    uint8_t ctx[16];
    uint8_t sig[114];
    psa_status_t status;
    int ret = 0;

    attrs = psa_key_attributes_init();
    psa_set_key_type(&attrs,
                     PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS));
    psa_set_key_bits(&attrs, 448);
    psa_set_key_usage_flags(&attrs,
                            PSA_KEY_USAGE_SIGN_HASH |
                            PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&attrs, PSA_ALG_EDDSA_CTX);
    psa_set_key_lifetime(&attrs, PSA_KEY_LIFETIME_VOLATILE);

    status = psa_generate_key(&attrs, &key);
    if (status != PSA_SUCCESS) {
        printf("FAIL eddsa_ctx verify_hash: key gen status=%d\n",
               (int)status);
        return 1;
    }

    for (int i = 0; i < 32; i++) {
        hash[i] = (uint8_t)(i + 10);
    }
    for (int i = 0; i < 16; i++) {
        ctx[i] = (uint8_t)(i + 100);
    }
    for (int i = 0; i < (int)sizeof(sig); i++) {
        sig[i] = (uint8_t)i;
    }

    status = psa_verify_hash_with_context(key, PSA_ALG_EDDSA_CTX,
                                          hash, sizeof(hash), ctx,
                                          sizeof(ctx), sig, sizeof(sig));
    if (status != PSA_ERROR_INVALID_ARGUMENT) {
        printf("FAIL eddsa_ctx verify_hash: expected INVALID_ARGUMENT, "
               "got %d\n", (int)status);
        ret = 1;
    } else {
        printf("PASS eddsa_ctx verify_hash rejected\n");
    }

    (void)psa_destroy_key(key);
    return ret;
}

int main(void)
{
    int ret = 0;

    if (psa_crypto_init() != PSA_SUCCESS) {
        printf("psa_crypto_init failed\n");
        return 1;
    }

    ret += test_sign_hash_rejects_pure_eddsa();
    ret += test_sign_hash_rejects_eddsa_ctx();
    ret += test_verify_hash_rejects_pure_eddsa();
    ret += test_verify_hash_rejects_eddsa_ctx();

    if (ret != 0) {
        printf("psa_sign_hash_eddsa_test: %d test(s) failed\n", ret);
        return 1;
    }
    printf("psa_sign_hash_eddsa_test: all tests passed\n");
    return 0;
}
