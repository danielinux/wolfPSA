/*
 * psa_copy_key_narrowing_test.c
 *
 * Regression test for Fenrir finding #12502: psa_copy_key() must narrow
 * the destination policy to the intersection of source and destination
 * policies, and the copy must be rejected when the policies have no
 * common algorithm.
 *
 * Per the PSA Crypto API, PSA_ALG_ANY_HASH is a wildcard of a signature
 * scheme (e.g. PSA_ALG_ECDSA(PSA_ALG_ANY_HASH) is a valid key policy
 * while a concrete-hash policy is not). A copy between the wildcard and
 * a concrete hash of the same scheme is valid in either direction and
 * stores the concrete policy. HMAC(PSA_ALG_ANY_HASH) is NOT a supported
 * policy, so a copy involving it must be rejected.
 *
 * The test covers the signature wildcards (ECDSA, ML-DSA) in both
 * directions and both key lifetimes, the HMAC rejection in both
 * lifetimes (volatile and persistent copies take different code paths),
 * and the rejection of the hashless PSA_ALG_ECDSA_ANY against
 * PSA_ALG_ECDSA(PSA_ALG_ANY_HASH), which the PSA Crypto API defines as
 * two distinct algorithms.
 *
 * MAC and AEAD policies have their own wildcards: a minimum MAC length
 * and a minimum AEAD tag length. A copy narrows those to the algorithm
 * both policies allow, or to the more restrictive minimum when both
 * policies are wildcards, and is rejected when the concrete algorithm is
 * shorter than the minimum the other policy requires.
 *
 * This file is part of wolfPSA.
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is licensed under the 3-clause BSD license. See the file
 * LICENSE or wolfSSL.md in the distribution root for details.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>

#include <wolfpsa/psa/crypto.h>

/* Remove the key store directory and anything left in it. */
static void cleanup_store(const char *dir)
{
    DIR *d;
    struct dirent *ent;

    d = opendir(dir);
    if (d == NULL) {
        return;
    }
    while ((ent = readdir(d)) != NULL) {
        char path[4096];

        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) {
            continue;
        }
        snprintf(path, sizeof(path), "%s/%s", dir, ent->d_name);
        (void)unlink(path);
    }
    closedir(d);
    (void)rmdir(dir);
}

/* Fill in the attributes of a key with the given policy. */
static void set_key_attrs(psa_key_attributes_t *attrs, psa_key_type_t type,
                          size_t bits, psa_algorithm_t alg,
                          psa_key_lifetime_t lifetime, psa_key_id_t key_id)
{
    psa_set_key_type(attrs, type);
    psa_set_key_bits(attrs, bits);
    if (type == PSA_KEY_TYPE_HMAC) {
        psa_set_key_usage_flags(attrs, PSA_KEY_USAGE_COPY |
                                 PSA_KEY_USAGE_SIGN_MESSAGE |
                                 PSA_KEY_USAGE_VERIFY_MESSAGE);
    }
    else if (type == PSA_KEY_TYPE_AES) {
        psa_set_key_usage_flags(attrs, PSA_KEY_USAGE_COPY |
                                 PSA_KEY_USAGE_ENCRYPT |
                                 PSA_KEY_USAGE_DECRYPT);
    }
    else {
        psa_set_key_usage_flags(attrs, PSA_KEY_USAGE_COPY |
                                 PSA_KEY_USAGE_SIGN_HASH |
                                 PSA_KEY_USAGE_VERIFY_HASH);
    }
    psa_set_key_algorithm(attrs, alg);
    psa_set_key_lifetime(attrs, lifetime);
    if (lifetime == PSA_KEY_LIFETIME_PERSISTENT) {
        psa_set_key_id(attrs, key_id);
    }
}

/* Create a key with the given policy: HMAC keys are imported from a
 * fixed raw key, AES and asymmetric keys are generated. */
static psa_status_t make_key(psa_key_type_t type, size_t bits,
                             psa_algorithm_t alg,
                             psa_key_lifetime_t lifetime,
                             psa_key_id_t key_id, psa_key_id_t *key)
{
    static const uint8_t hmac_key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_status_t status;

    set_key_attrs(&attrs, type, bits, alg, lifetime, key_id);
    *key = PSA_KEY_ID_NULL;
    if (type == PSA_KEY_TYPE_HMAC) {
        status = psa_import_key(&attrs, hmac_key, sizeof(hmac_key), key);
    }
    else {
        status = psa_generate_key(&attrs, key);
    }
    return status;
}

/* Copy a key from the source policy to the destination policy, and
 * check the result and the stored policy of the destination key. The
 * source key must always be created successfully: an expected rejection
 * only counts when psa_copy_key() itself rejects the copy. */
static int run_copy_case(psa_key_type_t type, size_t bits,
                         psa_algorithm_t src_alg, psa_algorithm_t dst_alg,
                         psa_key_lifetime_t lifetime, psa_key_id_t src_id,
                         psa_key_id_t dst_id, int expect_success,
                         psa_algorithm_t expect_stored_alg,
                         const char *label)
{
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_key_id_t src_key = PSA_KEY_ID_NULL;
    psa_key_id_t dst_key = PSA_KEY_ID_NULL;
    psa_status_t status;
    int ok = 0;

    status = make_key(type, bits, src_alg, lifetime, src_id, &src_key);
    if (status != PSA_SUCCESS) {
        printf("FAIL %s: source key create: 0x%08x\n", label,
               (unsigned int)status);
        return 1;
    }
    set_key_attrs(&attrs, type, bits, dst_alg, lifetime, dst_id);
    status = psa_copy_key(src_key, &attrs, &dst_key);
    if (expect_success) {
        if (status != PSA_SUCCESS) {
            printf("FAIL %s: psa_copy_key: 0x%08x\n", label,
                   (unsigned int)status);
            ok = 1;
        }
        else if (psa_get_key_attributes(dst_key, &attrs) != PSA_SUCCESS) {
            printf("FAIL %s: psa_get_key_attributes: 0x%08x\n", label,
                   (unsigned int)status);
            ok = 1;
        }
        else if (psa_get_key_algorithm(&attrs) != expect_stored_alg) {
            printf("FAIL %s: stored algorithm 0x%08x, expected 0x%08x\n",
                   label, (unsigned int)psa_get_key_algorithm(&attrs),
                   (unsigned int)expect_stored_alg);
            ok = 1;
        }
        else {
            printf("PASS %s\n", label);
        }
    }
    else if (status != PSA_ERROR_INVALID_ARGUMENT) {
        printf("FAIL %s: expected 0x%08x, got 0x%08x\n", label,
               (unsigned int)PSA_ERROR_INVALID_ARGUMENT,
               (unsigned int)status);
        ok = 1;
    }
    else {
        printf("PASS %s (rejected)\n", label);
    }
    if (dst_key != PSA_KEY_ID_NULL) {
        (void)psa_destroy_key(dst_key);
    }
    (void)psa_destroy_key(src_key);
    return ok;
}

int main(void)
{
    char store_dir[] = "/tmp/wolfpsa_copy_narrowing_XXXXXX";
    int ret = 0;

    if (mkdtemp(store_dir) == NULL) {
        printf("psa_copy_key_narrowing_test: mkdtemp failed\n");
        return 1;
    }
    if (setenv("WOLFPSA_TOKEN_PATH", store_dir, 1) != 0) {
        printf("psa_copy_key_narrowing_test: setenv failed\n");
        ret = 1;
    }
    else if (psa_crypto_init() != PSA_SUCCESS) {
        printf("psa_copy_key_narrowing_test: psa_crypto_init failed\n");
        ret = 1;
    }
    else {
        /* Signature wildcard (ECDSA): both directions, both lifetimes,
         * concrete policy stored either way. */
        ret |= run_copy_case(PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1), 256,
                             PSA_ALG_ECDSA(PSA_ALG_ANY_HASH),
                             PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                             PSA_KEY_LIFETIME_VOLATILE, PSA_KEY_ID_NULL,
                             PSA_KEY_ID_NULL, 1,
                             PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                             "volatile ECDSA ANY_HASH -> SHA_256");
        ret |= run_copy_case(PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1), 256,
                             PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                             PSA_ALG_ECDSA(PSA_ALG_ANY_HASH),
                             PSA_KEY_LIFETIME_VOLATILE, PSA_KEY_ID_NULL,
                             PSA_KEY_ID_NULL, 1,
                             PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                             "volatile ECDSA SHA_256 -> ANY_HASH");
        ret |= run_copy_case(PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1), 256,
                             PSA_ALG_ECDSA(PSA_ALG_ANY_HASH),
                             PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                             PSA_KEY_LIFETIME_PERSISTENT,
                             PSA_KEY_ID_USER_MIN + 101,
                             PSA_KEY_ID_USER_MIN + 102, 1,
                             PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                             "persistent ECDSA ANY_HASH -> SHA_256");
        ret |= run_copy_case(PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1), 256,
                             PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                             PSA_ALG_ECDSA(PSA_ALG_ANY_HASH),
                             PSA_KEY_LIFETIME_PERSISTENT,
                             PSA_KEY_ID_USER_MIN + 103,
                             PSA_KEY_ID_USER_MIN + 104, 1,
                             PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                             "persistent ECDSA SHA_256 -> ANY_HASH");
        /* PSA_ALG_ECDSA_ANY is hashless, not a member of ANY_HASH: a copy
         * between it and PSA_ALG_ECDSA(PSA_ALG_ANY_HASH) must be rejected in
         * both directions, or the copy would gain a forbidden policy. */
        ret |= run_copy_case(PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1), 256,
                             PSA_ALG_ECDSA_ANY,
                             PSA_ALG_ECDSA(PSA_ALG_ANY_HASH),
                             PSA_KEY_LIFETIME_VOLATILE, PSA_KEY_ID_NULL,
                             PSA_KEY_ID_NULL, 0, PSA_ALG_NONE,
                             "volatile ECDSA_ANY -> ANY_HASH");
        ret |= run_copy_case(PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1), 256,
                             PSA_ALG_ECDSA(PSA_ALG_ANY_HASH),
                             PSA_ALG_ECDSA_ANY,
                             PSA_KEY_LIFETIME_VOLATILE, PSA_KEY_ID_NULL,
                             PSA_KEY_ID_NULL, 0, PSA_ALG_NONE,
                             "volatile ECDSA ANY_HASH -> ECDSA_ANY");
        ret |= run_copy_case(PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1), 256,
                             PSA_ALG_ECDSA_ANY,
                             PSA_ALG_ECDSA(PSA_ALG_ANY_HASH),
                             PSA_KEY_LIFETIME_PERSISTENT,
                             PSA_KEY_ID_USER_MIN + 107,
                             PSA_KEY_ID_USER_MIN + 108, 0, PSA_ALG_NONE,
                             "persistent ECDSA_ANY -> ANY_HASH");
        /* ML-DSA wildcard: guards the PSA_ALG_GET_HASH() path (its hash
         * field is not a sign-hash field). Skipped when ML-DSA is not
         * built into the library. */
        ret |= run_copy_case(PSA_KEY_TYPE_ML_DSA_KEY_PAIR, 128,
                             PSA_ALG_HASH_ML_DSA(PSA_ALG_ANY_HASH),
                             PSA_ALG_HASH_ML_DSA(PSA_ALG_SHA_256),
                             PSA_KEY_LIFETIME_VOLATILE, PSA_KEY_ID_NULL,
                             PSA_KEY_ID_NULL, 1,
                             PSA_ALG_HASH_ML_DSA(PSA_ALG_SHA_256),
                             "volatile ML-DSA ANY_HASH -> SHA_256");
        /* HMAC(ANY_HASH) is not a supported policy: the copy is
         * rejected. */
        ret |= run_copy_case(PSA_KEY_TYPE_HMAC, 256,
                             PSA_ALG_HMAC(PSA_ALG_ANY_HASH),
                             PSA_ALG_HMAC(PSA_ALG_SHA_256),
                             PSA_KEY_LIFETIME_VOLATILE, PSA_KEY_ID_NULL,
                             PSA_KEY_ID_NULL, 0, PSA_ALG_NONE,
                             "volatile HMAC ANY_HASH -> SHA_256");
        ret |= run_copy_case(PSA_KEY_TYPE_HMAC, 256,
                             PSA_ALG_HMAC(PSA_ALG_ANY_HASH),
                             PSA_ALG_HMAC(PSA_ALG_SHA_256),
                             PSA_KEY_LIFETIME_PERSISTENT,
                             PSA_KEY_ID_USER_MIN + 105,
                             PSA_KEY_ID_USER_MIN + 106, 0, PSA_ALG_NONE,
                             "persistent HMAC ANY_HASH -> SHA_256");
        /* MAC minimum-length wildcard: the copy keeps the algorithm both
         * policies allow, and is rejected when the truncated MAC is
         * shorter than the minimum the other policy requires. */
        ret |= run_copy_case(PSA_KEY_TYPE_HMAC, 256,
                             PSA_ALG_HMAC(PSA_ALG_SHA_256),
                             PSA_ALG_AT_LEAST_THIS_LENGTH_MAC(
                                 PSA_ALG_HMAC(PSA_ALG_SHA_256), 16),
                             PSA_KEY_LIFETIME_VOLATILE, PSA_KEY_ID_NULL,
                             PSA_KEY_ID_NULL, 1,
                             PSA_ALG_HMAC(PSA_ALG_SHA_256),
                             "volatile HMAC full -> at least 16");
        ret |= run_copy_case(PSA_KEY_TYPE_HMAC, 256,
                             PSA_ALG_AT_LEAST_THIS_LENGTH_MAC(
                                 PSA_ALG_HMAC(PSA_ALG_SHA_256), 16),
                             PSA_ALG_TRUNCATED_MAC(
                                 PSA_ALG_HMAC(PSA_ALG_SHA_256), 20),
                             PSA_KEY_LIFETIME_VOLATILE, PSA_KEY_ID_NULL,
                             PSA_KEY_ID_NULL, 1,
                             PSA_ALG_TRUNCATED_MAC(
                                 PSA_ALG_HMAC(PSA_ALG_SHA_256), 20),
                             "volatile HMAC at least 16 -> truncated 20");
        ret |= run_copy_case(PSA_KEY_TYPE_HMAC, 256,
                             PSA_ALG_AT_LEAST_THIS_LENGTH_MAC(
                                 PSA_ALG_HMAC(PSA_ALG_SHA_256), 20),
                             PSA_ALG_AT_LEAST_THIS_LENGTH_MAC(
                                 PSA_ALG_HMAC(PSA_ALG_SHA_256), 16),
                             PSA_KEY_LIFETIME_PERSISTENT,
                             PSA_KEY_ID_USER_MIN + 109,
                             PSA_KEY_ID_USER_MIN + 110, 1,
                             PSA_ALG_AT_LEAST_THIS_LENGTH_MAC(
                                 PSA_ALG_HMAC(PSA_ALG_SHA_256), 20),
                             "persistent HMAC at least 16 -> at least 20");
        ret |= run_copy_case(PSA_KEY_TYPE_HMAC, 256,
                             PSA_ALG_AT_LEAST_THIS_LENGTH_MAC(
                                 PSA_ALG_HMAC(PSA_ALG_SHA_256), 20),
                             PSA_ALG_TRUNCATED_MAC(
                                 PSA_ALG_HMAC(PSA_ALG_SHA_256), 16),
                             PSA_KEY_LIFETIME_VOLATILE, PSA_KEY_ID_NULL,
                             PSA_KEY_ID_NULL, 0, PSA_ALG_NONE,
                             "volatile HMAC at least 20 -> truncated 16");
        /* AEAD minimum-tag-length wildcard: same rules on the tag. */
        ret |= run_copy_case(PSA_KEY_TYPE_AES, 128,
                             PSA_ALG_AEAD_WITH_AT_LEAST_THIS_LENGTH_TAG(
                                 PSA_ALG_GCM, 12),
                             PSA_ALG_GCM,
                             PSA_KEY_LIFETIME_VOLATILE, PSA_KEY_ID_NULL,
                             PSA_KEY_ID_NULL, 1, PSA_ALG_GCM,
                             "volatile GCM at least 12 -> GCM");
        ret |= run_copy_case(PSA_KEY_TYPE_AES, 128,
                             PSA_ALG_AEAD_WITH_AT_LEAST_THIS_LENGTH_TAG(
                                 PSA_ALG_GCM, 12),
                             PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_GCM, 8),
                             PSA_KEY_LIFETIME_VOLATILE, PSA_KEY_ID_NULL,
                             PSA_KEY_ID_NULL, 0, PSA_ALG_NONE,
                             "volatile GCM at least 12 -> tag 8");
        ret |= run_copy_case(PSA_KEY_TYPE_AES, 128,
                             PSA_ALG_AEAD_WITH_AT_LEAST_THIS_LENGTH_TAG(
                                 PSA_ALG_GCM, 12),
                             PSA_ALG_AEAD_WITH_AT_LEAST_THIS_LENGTH_TAG(
                                 PSA_ALG_GCM, 8),
                             PSA_KEY_LIFETIME_PERSISTENT,
                             PSA_KEY_ID_USER_MIN + 111,
                             PSA_KEY_ID_USER_MIN + 112, 1,
                             PSA_ALG_AEAD_WITH_AT_LEAST_THIS_LENGTH_TAG(
                                 PSA_ALG_GCM, 12),
                             "persistent GCM at least 8 -> at least 12");
        if (ret == 0) {
            printf("psa_copy_key_narrowing_test: all tests passed\n");
        }
    }
    cleanup_store(store_dir);
    return ret;
}
