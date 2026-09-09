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
 * accepted and the stored policy is the concrete one. Both directions are
 * covered, for volatile and for persistent keys (psa_copy_key applies the
 * policy intersection in both storage branches), and every case asserts the
 * stored policy is the concrete algorithm.
 *
 * Copyright (C) 2026 wolfSSL Inc.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <wolfpsa/psa/crypto.h>

/* Import an HMAC key with src_alg, copy it under the dst_alg policy, require
 * success, and require the stored policy to be the concrete algorithm (the
 * intersection of the two policies). With a persistent lifetime the source
 * and destination are given explicit user key ids. */
static int run_copy_case(psa_algorithm_t src_alg, psa_algorithm_t dst_alg,
                         psa_key_lifetime_t lifetime, psa_key_id_t src_id,
                         psa_key_id_t dst_id, const char *label)
{
    static const uint8_t key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    psa_key_attributes_t src_attrs = psa_key_attributes_init();
    psa_key_attributes_t dst_attrs = psa_key_attributes_init();
    psa_key_attributes_t copy_attrs = psa_key_attributes_init();
    psa_key_id_t src_key = 0;
    psa_key_id_t copy_key = 0;
    psa_algorithm_t copy_alg;
    psa_status_t st;
    int ret = 0;

    psa_set_key_type(&src_attrs, PSA_KEY_TYPE_HMAC);
    psa_set_key_bits(&src_attrs, (size_t)sizeof(key) * 8u);
    psa_set_key_usage_flags(&src_attrs,
                            PSA_KEY_USAGE_COPY |
                            PSA_KEY_USAGE_SIGN_MESSAGE |
                            PSA_KEY_USAGE_VERIFY_MESSAGE);
    psa_set_key_algorithm(&src_attrs, src_alg);
    psa_set_key_lifetime(&src_attrs, lifetime);
    if (lifetime == PSA_KEY_LIFETIME_PERSISTENT) {
        psa_set_key_id(&src_attrs, src_id);
    }
    st = psa_import_key(&src_attrs, key, sizeof(key), &src_key);
    if (st != PSA_SUCCESS) {
        printf("FAIL %s: psa_import_key status=%d\n", label, (int)st);
        return 1;
    }

    psa_set_key_type(&dst_attrs, PSA_KEY_TYPE_HMAC);
    psa_set_key_bits(&dst_attrs, (size_t)sizeof(key) * 8u);
    psa_set_key_usage_flags(&dst_attrs,
                            PSA_KEY_USAGE_COPY |
                            PSA_KEY_USAGE_SIGN_MESSAGE |
                            PSA_KEY_USAGE_VERIFY_MESSAGE);
    psa_set_key_algorithm(&dst_attrs, dst_alg);
    psa_set_key_lifetime(&dst_attrs, lifetime);
    if (lifetime == PSA_KEY_LIFETIME_PERSISTENT) {
        psa_set_key_id(&dst_attrs, dst_id);
    }
    st = psa_copy_key(src_key, &dst_attrs, &copy_key);
    if (st != PSA_SUCCESS) {
        printf("FAIL %s: psa_copy_key status=%d (expected SUCCESS)\n",
               label, (int)st);
        ret = 1;
    }
    else {
        /* The stored policy must be the concrete algorithm: keeping the
         * wildcard would permit more than the other policy allows. */
        st = psa_get_key_attributes(copy_key, &copy_attrs);
        if (st != PSA_SUCCESS) {
            printf("FAIL %s: psa_get_key_attributes status=%d\n",
                   label, (int)st);
            ret = 1;
        }
        else {
            copy_alg = psa_get_key_algorithm(&copy_attrs);
            if (copy_alg != PSA_ALG_HMAC(PSA_ALG_SHA_256)) {
                printf("FAIL %s: copied policy algorithm=0x%08x "
                       "(expected concrete HMAC(SHA_256))\n",
                       label, (unsigned)copy_alg);
                ret = 1;
            }
            else {
                printf("PASS %s: copy accepted, concrete policy stored\n",
                       label);
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
    char store_dir[] = "/tmp/wolfpsa_copy_narrowing_XXXXXX";
    int ret = 0;

    /* The persistent cases need a key store; give each run its own. */
    if (mkdtemp(store_dir) == NULL) {
        printf("psa_copy_key_narrowing_test: mkdtemp failed\n");
        return 1;
    }
    if (setenv("WOLFPSA_TOKEN_PATH", store_dir, 1) != 0) {
        printf("psa_copy_key_narrowing_test: setenv failed\n");
        return 1;
    }

    if (psa_crypto_init() != PSA_SUCCESS) {
        printf("psa_copy_key_narrowing_test: psa_crypto_init failed\n");
        return 1;
    }

    ret |= run_copy_case(PSA_ALG_HMAC(PSA_ALG_ANY_HASH),
                         PSA_ALG_HMAC(PSA_ALG_SHA_256),
                         PSA_KEY_LIFETIME_VOLATILE, PSA_KEY_ID_NULL,
                         PSA_KEY_ID_NULL,
                         "volatile ANY_HASH -> SHA_256");
    ret |= run_copy_case(PSA_ALG_HMAC(PSA_ALG_SHA_256),
                         PSA_ALG_HMAC(PSA_ALG_ANY_HASH),
                         PSA_KEY_LIFETIME_VOLATILE, PSA_KEY_ID_NULL,
                         PSA_KEY_ID_NULL,
                         "volatile SHA_256 -> ANY_HASH");
    ret |= run_copy_case(PSA_ALG_HMAC(PSA_ALG_ANY_HASH),
                         PSA_ALG_HMAC(PSA_ALG_SHA_256),
                         PSA_KEY_LIFETIME_PERSISTENT,
                         PSA_KEY_ID_USER_MIN + 101, PSA_KEY_ID_USER_MIN + 102,
                         "persistent ANY_HASH -> SHA_256");
    ret |= run_copy_case(PSA_ALG_HMAC(PSA_ALG_SHA_256),
                         PSA_ALG_HMAC(PSA_ALG_ANY_HASH),
                         PSA_KEY_LIFETIME_PERSISTENT,
                         PSA_KEY_ID_USER_MIN + 103, PSA_KEY_ID_USER_MIN + 104,
                         "persistent SHA_256 -> ANY_HASH");

    if (ret == 0) {
        printf("psa_copy_key_narrowing_test: all tests passed\n");
    }
    return ret;
}
