/*
 * psa_copy_key_narrowing_test.c
 *
 * Regression test for F-12502: psa_copy_key must accept a valid
 * wildcard-to-concrete algorithm narrowing (an HMAC(ANY_HASH) source copied
 * to an HMAC(SHA_256) destination) instead of requiring exact algorithm
 * equality, which rejected that valid copy.
 *
 * Per the PSA spec the copy must conform to both policies: when one side is
 * the inclusive wildcard of the other's concrete algorithm, the copy is
 * accepted and the stored policy is the concrete one. The second test
 * covers the inverse direction (concrete source, wildcard destination) and
 * asserts the stored policy is concrete.
 *
 * Copyright (C) 2026 wolfSSL Inc.
 */

#include <stdio.h>
#include <wolfpsa/psa/crypto.h>

/* Copy an HMAC(ANY_HASH) key to an HMAC(SHA_256) destination. Before the
 * fix the exact-algorithm comparison rejected this with INVALID_ARGUMENT. */
static int test_wildcard_to_concrete_narrowing(void)
{
    static const uint8_t key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    psa_key_attributes_t src_attrs = psa_key_attributes_init();
    psa_key_attributes_t dst_attrs = psa_key_attributes_init();
    psa_key_id_t src_key = 0;
    psa_key_id_t copy_key = 0;
    psa_status_t st;
    int ret = 0;

    /* Source: HMAC key with a wildcard (ANY_HASH) algorithm. */
    psa_set_key_type(&src_attrs, PSA_KEY_TYPE_HMAC);
    psa_set_key_bits(&src_attrs, (size_t)sizeof(key) * 8u);
    psa_set_key_usage_flags(&src_attrs,
                            PSA_KEY_USAGE_COPY |
                            PSA_KEY_USAGE_SIGN_MESSAGE |
                            PSA_KEY_USAGE_VERIFY_MESSAGE);
    psa_set_key_algorithm(&src_attrs, PSA_ALG_HMAC(PSA_ALG_ANY_HASH));
    psa_set_key_lifetime(&src_attrs, PSA_KEY_LIFETIME_VOLATILE);
    st = psa_import_key(&src_attrs, key, sizeof(key), &src_key);
    if (st != PSA_SUCCESS) {
        printf("FAIL narrowing: psa_import_key(HMAC ANY_HASH) status=%d\n",
               (int)st);
        return 1;
    }

    /* Destination: concrete HMAC(SHA_256) algorithm (a valid narrowing of
     * the source wildcard). */
    psa_set_key_type(&dst_attrs, PSA_KEY_TYPE_HMAC);
    psa_set_key_bits(&dst_attrs, (size_t)sizeof(key) * 8u);
    psa_set_key_usage_flags(&dst_attrs,
                            PSA_KEY_USAGE_COPY |
                            PSA_KEY_USAGE_SIGN_MESSAGE |
                            PSA_KEY_USAGE_VERIFY_MESSAGE);
    psa_set_key_algorithm(&dst_attrs, PSA_ALG_HMAC(PSA_ALG_SHA_256));
    psa_set_key_lifetime(&dst_attrs, PSA_KEY_LIFETIME_VOLATILE);
    st = psa_copy_key(src_key, &dst_attrs, &copy_key);
    if (st != PSA_SUCCESS) {
        printf("FAIL narrowing: psa_copy_key(ANY_HASH -> SHA_256) status=%d "
               "(expected SUCCESS)\n", (int)st);
        ret = 1;
    } else   {
        printf("PASS narrowing: wildcard -> concrete copy accepted\n");
        if (copy_key != 0) {
            psa_destroy_key(copy_key);
        }
    }

    psa_destroy_key(src_key);
    return ret;
}

/* Concrete source, wildcard destination: the copy must succeed and the
 * stored policy must be the concrete algorithm (the wildcard would permit
 * more than the source policy allows). */
static int test_concrete_to_wildcard_stores_concrete(void)
{
    static const uint8_t key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    psa_key_attributes_t src_attrs = psa_key_attributes_init();
    psa_key_attributes_t dst_attrs = psa_key_attributes_init();
    psa_key_id_t src_key = 0;
    psa_key_id_t copy_key = 0;
    psa_status_t st;
    int ret = 0;

    /* Source: concrete HMAC(SHA_256) algorithm. */
    psa_set_key_type(&src_attrs, PSA_KEY_TYPE_HMAC);
    psa_set_key_bits(&src_attrs, (size_t)sizeof(key) * 8u);
    psa_set_key_usage_flags(&src_attrs,
                            PSA_KEY_USAGE_COPY |
                            PSA_KEY_USAGE_SIGN_MESSAGE |
                            PSA_KEY_USAGE_VERIFY_MESSAGE);
    psa_set_key_algorithm(&src_attrs, PSA_ALG_HMAC(PSA_ALG_SHA_256));
    psa_set_key_lifetime(&src_attrs, PSA_KEY_LIFETIME_VOLATILE);
    st = psa_import_key(&src_attrs, key, sizeof(key), &src_key);
    if (st != PSA_SUCCESS) {
        printf("FAIL widen: psa_import_key(HMAC SHA_256) status=%d\n",
               (int)st);
        return 1;
    }

    /* Destination: wildcard HMAC(ANY_HASH) - the inclusive wildcard of the
     * source's concrete algorithm. */
    psa_set_key_type(&dst_attrs, PSA_KEY_TYPE_HMAC);
    psa_set_key_bits(&dst_attrs, (size_t)sizeof(key) * 8u);
    psa_set_key_usage_flags(&dst_attrs,
                            PSA_KEY_USAGE_COPY |
                            PSA_KEY_USAGE_SIGN_MESSAGE |
                            PSA_KEY_USAGE_VERIFY_MESSAGE);
    psa_set_key_algorithm(&dst_attrs, PSA_ALG_HMAC(PSA_ALG_ANY_HASH));
    psa_set_key_lifetime(&dst_attrs, PSA_KEY_LIFETIME_VOLATILE);
    st = psa_copy_key(src_key, &dst_attrs, &copy_key);
    if (st != PSA_SUCCESS) {
        printf("FAIL widen: psa_copy_key(SHA_256 -> ANY_HASH) status=%d "
               "(expected SUCCESS)\n", (int)st);
        ret = 1;
    }
    else   {
        psa_key_attributes_t copy_attrs = psa_key_attributes_init();
        psa_algorithm_t copy_alg;

        st = psa_get_key_attributes(copy_key, &copy_attrs);
        if (st != PSA_SUCCESS) {
            printf("FAIL widen: psa_get_key_attributes status=%d\n",
                   (int)st);
            ret = 1;
        }
        else {
            copy_alg = psa_get_key_algorithm(&copy_attrs);
            if (copy_alg != PSA_ALG_HMAC(PSA_ALG_SHA_256)) {
                printf("FAIL widen: copied policy algorithm=0x%08x "
                       "(expected concrete HMAC(SHA_256))\n",
                       (unsigned)copy_alg);
                ret = 1;
            }
            else {
                printf("PASS widen: concrete -> wildcard copy accepted, "
                       "concrete policy stored\n");
            }
        }
        if (copy_key != 0) {
            psa_destroy_key(copy_key);
        }
    }

    psa_destroy_key(src_key);
    return ret;
}

int main(void)
{
    int ret = 0;

    if (psa_crypto_init() != PSA_SUCCESS) {
        printf("psa_copy_key_narrowing_test: psa_crypto_init failed\n");
        return 1;
    }

    if (test_wildcard_to_concrete_narrowing() != 0) {
        ret = 1;
    }
    if (test_concrete_to_wildcard_stores_concrete() != 0) {
        ret = 1;
    }

    if (ret == 0) {
        printf("psa_copy_key_narrowing_test: all tests passed\n");
    }
    return ret;
}
