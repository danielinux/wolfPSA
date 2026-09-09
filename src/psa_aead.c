/* psa_aead.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfPSA.
 *
 * wolfPSA is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfPSA is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_PSA_ENGINE)

#include <psa/crypto.h>
#include <wolfpsa/psa_engine.h>
#include <wolfpsa/psa_key_storage.h>
#include <wolfpsa/psa_chacha20_poly1305.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/mem_track.h>
#if defined(HAVE_XCHACHA) || (defined(HAVE_CHACHA) && defined(HAVE_POLY1305))
#include <wolfssl/wolfcrypt/chacha20_poly1305.h>
#endif
#ifdef HAVE_ASCON
#include <wolfssl/wolfcrypt/ascon.h>
#endif
#include "psa_aead_internal.h"
#include "psa_size.h"

static wolfpsa_aead_ctx_t* wolfpsa_aead_get_ctx(psa_aead_operation_t *operation)
{
    return wolfpsa_aead_get_ctx_ptr(operation);
}

static psa_status_t wolfpsa_aead_append(uint8_t **buf, size_t *len,
                                        const uint8_t *data, size_t data_length)
{
    uint8_t *new_buf;

    if (buf == NULL || len == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (data == NULL && data_length > 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (data_length == 0) {
        return PSA_SUCCESS;
    }
    if (*len > SIZE_MAX - data_length) {
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    }

    new_buf = (uint8_t *)XMALLOC(*len + data_length, NULL,
                                 DYNAMIC_TYPE_TMP_BUFFER);
    if (new_buf == NULL) {
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    }

    if (*buf != NULL) {
        XMEMCPY(new_buf, *buf, *len);
        wc_ForceZero(*buf, *len);
        XFREE(*buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }

    XMEMCPY(new_buf + *len, data, data_length);
    *buf = new_buf;
    *len += data_length;

    return PSA_SUCCESS;
}

static const uint8_t* wolfpsa_aead_nonnull_data(const uint8_t *data,
                                                size_t data_length)
{
    static const uint8_t empty = 0;

    if (data == NULL && data_length == 0) {
        return &empty;
    }

    return data;
}

static size_t wolfpsa_aead_tag_length(psa_algorithm_t alg)
{
    return PSA_ALG_AEAD_GET_TAG_LENGTH(alg);
}

#ifdef HAVE_AESGCM
static int wolfpsa_aead_gcm_check_tag_size(size_t tag_length)
{
    return tag_length == 4 || tag_length == 8 ||
           (tag_length >= 12 && tag_length <= WC_AES_BLOCK_SIZE);
}
#endif

static psa_status_t wolfpsa_aead_check_key(psa_key_id_t key,
                                           psa_key_usage_t usage,
                                           psa_algorithm_t alg,
                                           psa_key_attributes_t *attributes,
                                           uint8_t **key_data,
                                           size_t *key_data_length)
{
    psa_status_t status;
    psa_key_usage_t key_usage;
    psa_algorithm_t key_alg;
    psa_algorithm_t key_base;
    psa_algorithm_t req_base;
    size_t key_tag_len;
    size_t req_tag_len;

    status = wolfpsa_get_key_data(key, attributes, key_data, key_data_length);
    if (status != PSA_SUCCESS) {
        return status;
    }

    if (PSA_ALG_AEAD_EQUAL(alg, PSA_ALG_GCM) ||
        PSA_ALG_AEAD_EQUAL(alg, PSA_ALG_CCM)) {
        if (attributes->type != PSA_KEY_TYPE_AES) {
            wolfpsa_forcezero_free_key_data(*key_data, *key_data_length);
            *key_data = NULL;
            *key_data_length = 0;
            return PSA_ERROR_INVALID_ARGUMENT;
        }
    }
    else if (PSA_ALG_AEAD_EQUAL(alg, PSA_ALG_CHACHA20_POLY1305)) {
        if (attributes->type != PSA_KEY_TYPE_CHACHA20) {
            wolfpsa_forcezero_free_key_data(*key_data, *key_data_length);
            *key_data = NULL;
            *key_data_length = 0;
            return PSA_ERROR_INVALID_ARGUMENT;
        }
    }
    else {
        /* XChaCha20-Poly1305 and Ascon-AEAD128 never reach this function:
         * they are one-shot only and rejected by wolfpsa_aead_setup before
         * the key is checked; the one-shot paths validate the key inline. */
        wolfpsa_forcezero_free_key_data(*key_data, *key_data_length);
        *key_data = NULL;
        *key_data_length = 0;
        return PSA_ERROR_NOT_SUPPORTED;
    }

    key_usage = psa_get_key_usage_flags(attributes);
    if ((key_usage & usage) != usage) {
        wolfpsa_forcezero_free_key_data(*key_data, *key_data_length);
        *key_data = NULL;
        *key_data_length = 0;
        return PSA_ERROR_NOT_PERMITTED;
    }

    key_alg = psa_get_key_algorithm(attributes);
    if (key_alg == PSA_ALG_NONE) {
        wolfpsa_forcezero_free_key_data(*key_data, *key_data_length);
        *key_data = NULL;
        *key_data_length = 0;
        return PSA_ERROR_NOT_PERMITTED;
    }

    /* Algorithm match checks */
    key_base = PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG(key_alg);
    req_base = PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG(alg);
    key_tag_len = wolfpsa_aead_tag_length(key_alg);
    req_tag_len = wolfpsa_aead_tag_length(alg);

    if (key_tag_len == 0 || req_tag_len == 0) {
        wolfpsa_forcezero_free_key_data(*key_data, *key_data_length);
        *key_data = NULL;
        *key_data_length = 0;
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (key_base != req_base) {
        wolfpsa_forcezero_free_key_data(*key_data, *key_data_length);
        *key_data = NULL;
        *key_data_length = 0;
        return PSA_ERROR_NOT_PERMITTED;
    }

    if ((key_alg & PSA_ALG_AEAD_AT_LEAST_THIS_LENGTH_FLAG) != 0) {
        if (req_tag_len < key_tag_len) {
            wolfpsa_forcezero_free_key_data(*key_data, *key_data_length);
            *key_data = NULL;
            *key_data_length = 0;
            return PSA_ERROR_NOT_PERMITTED;
        }
    }
    else if (req_tag_len != key_tag_len) {
        wolfpsa_forcezero_free_key_data(*key_data, *key_data_length);
        *key_data = NULL;
        *key_data_length = 0;
        return PSA_ERROR_NOT_PERMITTED;
    }

    return PSA_SUCCESS;
}

static psa_status_t wolfpsa_aead_setup(psa_aead_operation_t *operation,
                                       psa_key_id_t key,
                                       psa_algorithm_t alg,
                                       psa_key_usage_t usage)
{
    psa_key_attributes_t attributes;
    uint8_t *key_data = NULL;
    size_t key_data_length = 0;
    wolfpsa_aead_ctx_t *ctx;
    psa_status_t status;

    if (operation == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (operation->opaque != (uintptr_t)NULL) {
        return PSA_ERROR_BAD_STATE;
    }

    if (!PSA_ALG_IS_AEAD(alg) || PSA_ALG_AEAD_EQUAL(alg, PSA_ALG_CCM_STAR_NO_TAG)) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    if ((alg & PSA_ALG_AEAD_AT_LEAST_THIS_LENGTH_FLAG) != 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
#ifndef HAVE_AESGCM
    if (PSA_ALG_AEAD_EQUAL(alg, PSA_ALG_GCM)) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
#endif
#ifndef HAVE_AESCCM
    if (PSA_ALG_AEAD_EQUAL(alg, PSA_ALG_CCM)) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
#endif
#if !defined(HAVE_CHACHA) || !defined(HAVE_POLY1305)
    if (PSA_ALG_AEAD_EQUAL(alg, PSA_ALG_CHACHA20_POLY1305)) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
#endif
    /* XChaCha20-Poly1305 and Ascon-AEAD128 are one-shot only; wolfCrypt
     * provides no streaming API for these algorithms. */
    if (PSA_ALG_AEAD_EQUAL(alg, PSA_ALG_XCHACHA20_POLY1305) ||
        PSA_ALG_AEAD_EQUAL(alg, PSA_ALG_ASCON_AEAD128)) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    status = wolfpsa_aead_check_key(key, usage, alg, &attributes,
                                    &key_data, &key_data_length);
    if (status != PSA_SUCCESS) {
        return status;
    }

    ctx = (wolfpsa_aead_ctx_t *)XMALLOC(sizeof(*ctx), NULL,
                                        DYNAMIC_TYPE_TMP_BUFFER);
    if (ctx == NULL) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    }
    XMEMSET(ctx, 0, sizeof(*ctx));

    ctx->alg = alg;
    ctx->key_type = attributes.type;
    ctx->key_bits = attributes.bits;
    ctx->tag_length = wolfpsa_aead_tag_length(alg);
    if (ctx->tag_length == 0) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    ctx->direction = (usage == PSA_KEY_USAGE_ENCRYPT) ? 1 : 0;
#ifdef HAVE_AESCCM
    if (PSA_ALG_AEAD_EQUAL(alg, PSA_ALG_CCM) &&
        wc_AesCcmCheckTagSize((int)ctx->tag_length) != 0) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return PSA_ERROR_INVALID_ARGUMENT;
    }
#endif
#ifdef HAVE_AESGCM
    if (PSA_ALG_AEAD_EQUAL(alg, PSA_ALG_GCM) &&
        !wolfpsa_aead_gcm_check_tag_size(ctx->tag_length)) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return PSA_ERROR_INVALID_ARGUMENT;
    }
#endif
#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
    /* ChaCha20-Poly1305 has no truncated-tag interface; only the native
     * 16-byte tag is supported. Reject shortened-tag variants here rather than
     * accepting them and failing the encrypt/decrypt roundtrip later. */
    if (PSA_ALG_AEAD_EQUAL(alg, PSA_ALG_CHACHA20_POLY1305) &&
        ctx->tag_length != CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return PSA_ERROR_NOT_SUPPORTED;
    }
#endif

    ctx->key = (uint8_t *)XMALLOC(key_data_length, NULL,
                                  DYNAMIC_TYPE_TMP_BUFFER);
    if (ctx->key == NULL) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    }
    XMEMCPY(ctx->key, key_data, key_data_length);
    ctx->key_length = key_data_length;

    wolfpsa_forcezero_free_key_data(key_data, key_data_length);
    operation->opaque = (uintptr_t)ctx;
    return PSA_SUCCESS;
}

psa_status_t psa_aead_encrypt_setup(psa_aead_operation_t *operation,
                                    psa_key_id_t key,
                                    psa_algorithm_t alg)
{
    return wolfpsa_aead_setup(operation, key, alg, PSA_KEY_USAGE_ENCRYPT);
}

psa_status_t psa_aead_decrypt_setup(psa_aead_operation_t *operation,
                                    psa_key_id_t key,
                                    psa_algorithm_t alg)
{
    return wolfpsa_aead_setup(operation, key, alg, PSA_KEY_USAGE_DECRYPT);
}

psa_status_t psa_aead_set_lengths(psa_aead_operation_t *operation,
                                  size_t ad_length,
                                  size_t plaintext_length)
{
    wolfpsa_aead_ctx_t *ctx = wolfpsa_aead_get_ctx(operation);

    if (ctx == NULL) {
        return PSA_ERROR_BAD_STATE;
    }
    if (ctx->lengths_set) {
        return PSA_ERROR_BAD_STATE;
    }
    if (ctx->nonce_length != 0 || ctx->aad_length != 0 || ctx->input_length != 0) {
        return PSA_ERROR_BAD_STATE;
    }

    ctx->ad_expected = ad_length;
    ctx->plaintext_expected = plaintext_length;
    ctx->lengths_set = 1;
    return PSA_SUCCESS;
}

psa_status_t psa_aead_set_nonce(psa_aead_operation_t *operation,
                                const uint8_t *nonce,
                                size_t nonce_length)
{
    wolfpsa_aead_ctx_t *ctx = wolfpsa_aead_get_ctx(operation);
    size_t expected;

    if (ctx == NULL) {
        return PSA_ERROR_BAD_STATE;
    }
    if (nonce == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (ctx->nonce_length != 0) {
        return PSA_ERROR_BAD_STATE;
    }

    if (PSA_ALG_AEAD_EQUAL(ctx->alg, PSA_ALG_CCM) && !ctx->lengths_set) {
        return PSA_ERROR_BAD_STATE;
    }

    if (PSA_ALG_AEAD_EQUAL(ctx->alg, PSA_ALG_GCM)) {
        /* GCM (SP 800-38D) accepts any non-empty nonce. A zero-length nonce is
         * invalid for the algorithm; other lengths outside the supported 12 to
         * 24 byte range are valid for GCM but not supported by this
         * implementation. */
        if (nonce_length == 0) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        if (nonce_length < 12 || nonce_length > PSA_AEAD_NONCE_MAX_SIZE) {
            return PSA_ERROR_NOT_SUPPORTED;
        }
    }
    else if (PSA_ALG_AEAD_EQUAL(ctx->alg, PSA_ALG_CCM)) {
        if (nonce_length < 7 || nonce_length > 13) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
    }
    else {
        expected = PSA_AEAD_NONCE_LENGTH(ctx->key_type, ctx->alg);
        if (expected == 0 || nonce_length != expected) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
    }

    XMEMCPY(ctx->nonce, nonce, nonce_length);
    ctx->nonce_length = nonce_length;
    return PSA_SUCCESS;
}

psa_status_t psa_aead_generate_nonce(psa_aead_operation_t *operation,
                                     uint8_t *nonce,
                                     size_t nonce_size,
                                     size_t *nonce_length)
{
    wolfpsa_aead_ctx_t *ctx = wolfpsa_aead_get_ctx(operation);
    size_t expected;
    psa_status_t status;

    if (ctx == NULL) {
        return PSA_ERROR_BAD_STATE;
    }
    if (nonce == NULL || nonce_length == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (!ctx->direction) {
        return PSA_ERROR_BAD_STATE;
    }
    if (ctx->nonce_length != 0) {
        return PSA_ERROR_BAD_STATE;
    }
    if (PSA_ALG_AEAD_EQUAL(ctx->alg, PSA_ALG_CCM) && !ctx->lengths_set) {
        return PSA_ERROR_BAD_STATE;
    }

    expected = PSA_AEAD_NONCE_LENGTH(ctx->key_type, ctx->alg);
    if (expected == 0 || nonce_size < expected) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    status = psa_generate_random(nonce, expected);
    if (status != PSA_SUCCESS) {
        return status;
    }

    status = psa_aead_set_nonce(operation, nonce, expected);
    if (status != PSA_SUCCESS) {
        return status;
    }

    *nonce_length = expected;
    return PSA_SUCCESS;
}

psa_status_t psa_aead_update_ad(psa_aead_operation_t *operation,
                                const uint8_t *input,
                                size_t input_length)
{
    wolfpsa_aead_ctx_t *ctx = wolfpsa_aead_get_ctx(operation);
    psa_status_t status;

    if (ctx == NULL) {
        return PSA_ERROR_BAD_STATE;
    }
    if (PSA_ALG_AEAD_EQUAL(ctx->alg, PSA_ALG_CCM) && !ctx->lengths_set) {
        return PSA_ERROR_BAD_STATE;
    }
    if (ctx->nonce_length == 0) {
        return PSA_ERROR_BAD_STATE;
    }
    if (ctx->lengths_set &&
        (input_length > SIZE_MAX - ctx->aad_length ||
         ctx->aad_length + input_length > ctx->ad_expected)) {
        status = PSA_ERROR_INVALID_ARGUMENT;
        psa_aead_abort(operation);
        return status;
    }

    status = wolfpsa_aead_append(&ctx->aad, &ctx->aad_length, input, input_length);
    if (status != PSA_SUCCESS) {
        psa_aead_abort(operation);
    }
    return status;
}

#ifdef HAVE_AESCCM
/* Big-endian increment of the last lenSz bytes of a CCM counter block. */
static void wolfpsa_aead_ccm_ctr_inc(uint8_t *ctr, size_t lenSz)
{
    size_t i;

    for (i = 0; i < lenSz; i++) {
        if (++ctr[15 - i] != 0) {
            return;
        }
    }
}

/* Build B0, run the AAD through the CBC-MAC (length prefix + authenticated
 * data) and prime the CTR. CCM requires set_lengths, so the message length is
 * known here. */
static psa_status_t wolfpsa_aead_ccm_init(wolfpsa_aead_ctx_t *ctx)
{
    uint8_t block[16];
    const uint8_t *aad;
    size_t aad_len;
    size_t nonce_len = ctx->nonce_length;
    size_t lenSz = 15 - nonce_len;
    size_t tag_len = ctx->tag_length;
    int ret;
    size_t i;

    if (nonce_len < 7 || nonce_len > 13) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    ctx->ccm_lenSz = lenSz;
    ctx->ccm_tag_len = tag_len;

    ret = wc_AesInit(&ctx->ccm_aes, NULL, wolfPSA_GetDefaultDevID());
    if (ret == 0) {
        ret = wc_AesSetKeyDirect(&ctx->ccm_aes, ctx->key,
                                (word32)ctx->key_length, NULL, 0);
    }
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }

    /* B0 = [flags][nonce][message length]; A = E(K, B0). */
    XMEMSET(block, 0, sizeof(block));
    block[0] = (uint8_t)((ctx->aad_length > 0 ? 64 : 0) +
                         8 * ((tag_len - 2) / 2) + (lenSz - 1));
    XMEMCPY(block + 1, ctx->nonce, nonce_len);
    for (i = 0; i < lenSz; i++) {
        block[15 - i] = (uint8_t)((ctx->plaintext_expected >> (8 * i)) &
                                  0xff);
    }
    ret = wc_AesEncryptDirect(&ctx->ccm_aes, block, block);
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }
    XMEMCPY(ctx->ccm_mac, block, 16);

    /* AAD: 2- or 6-byte length prefix + authenticated data, in 16-byte
     * blocks. */
    aad = wolfpsa_aead_nonnull_data(ctx->aad, ctx->aad_length);
    aad_len = ctx->aad_length;
    if (aad_len > 0) {
        size_t authLenSz = (aad_len <= 0xFEFF) ? 2 : 6;
        size_t rem;

        XMEMSET(block, 0, sizeof(block));
        if (authLenSz == 2) {
            block[0] = (uint8_t)(aad_len >> 8);
            block[1] = (uint8_t)(aad_len & 0xff);
        }
        else {
            block[0] = 0xff;
            block[1] = 0xfe;
            block[2] = (uint8_t)(aad_len >> 24);
            block[3] = (uint8_t)(aad_len >> 16);
            block[4] = (uint8_t)(aad_len >> 8);
            block[5] = (uint8_t)(aad_len & 0xff);
        }
        rem = 16 - authLenSz;
        if (aad_len >= rem) {
            XMEMCPY(block + authLenSz, aad, rem);
            aad_len -= rem;
            aad += rem;
        }
        else {
            XMEMCPY(block + authLenSz, aad, aad_len);
            aad_len = 0;
        }
        for (i = 0; i < 16; i++) {
            ctx->ccm_mac[i] ^= block[i];
        }
        ret = wc_AesEncryptDirect(&ctx->ccm_aes, ctx->ccm_mac, ctx->ccm_mac);
        if (ret != 0) {
            return wc_error_to_psa_status(ret);
        }
        while (aad_len > 0) {
            size_t n = (aad_len >= 16) ? 16 : aad_len;

            XMEMSET(block, 0, sizeof(block));
            XMEMCPY(block, aad, n);
            for (i = 0; i < 16; i++) {
                ctx->ccm_mac[i] ^= block[i];
            }
            ret = wc_AesEncryptDirect(&ctx->ccm_aes, ctx->ccm_mac, ctx->ccm_mac);
            if (ret != 0) {
                return wc_error_to_psa_status(ret);
            }
            aad += n;
            aad_len -= n;
        }
    }

    /* CTR: counter block [lenSz-1][nonce][counter=1]; first keystream block.
     * The MAC over the message starts from a fresh (zero) partial block. */
    XMEMSET(ctx->ccm_ctr, 0, sizeof(ctx->ccm_ctr));
    ctx->ccm_ctr[0] = (uint8_t)(lenSz - 1);
    XMEMCPY(ctx->ccm_ctr + 1, ctx->nonce, nonce_len);
    ctx->ccm_ctr[15] = 1;
    XMEMSET(ctx->ccm_mblk, 0, sizeof(ctx->ccm_mblk));
    ctx->ccm_mfill = 0;
    ret = wc_AesEncryptDirect(&ctx->ccm_aes, ctx->ccm_ks, ctx->ccm_ctr);
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }
    ctx->ccm_ks_off = 0;
    ctx->ccm_ks_valid = 1;

    return PSA_SUCCESS;
}

/* Stream n message bytes: advance the running CBC-MAC over the plaintext and
 * emit the CTR ciphertext. */
static psa_status_t wolfpsa_aead_ccm_update(wolfpsa_aead_ctx_t *ctx,
                                            const uint8_t *in, size_t n,
                                            uint8_t *out)
{
    uint8_t tmp[16];
    const uint8_t *pt;
    size_t i;
    int ret;

    /* The CBC-MAC is over the plaintext: the input when encrypting, the
     * output when decrypting. */
    pt = (ctx->direction) ? in : out;

    for (i = 0; i < n; i++) {
        if (ctx->ccm_ks_off == 16) {
            wolfpsa_aead_ccm_ctr_inc(ctx->ccm_ctr, ctx->ccm_lenSz);
            ret = wc_AesEncryptDirect(&ctx->ccm_aes, ctx->ccm_ks, ctx->ccm_ctr);
            if (ret != 0) {
                return wc_error_to_psa_status(ret);
            }
            ctx->ccm_ks_off = 0;
        }
        out[i] = (uint8_t)(in[i] ^ ctx->ccm_ks[ctx->ccm_ks_off]);
        ctx->ccm_ks_off++;

        ctx->ccm_mblk[ctx->ccm_mfill] =
            (uint8_t)(ctx->ccm_mblk[ctx->ccm_mfill] ^ pt[i]);
        ctx->ccm_mfill++;
        if (ctx->ccm_mfill == 16) {
            size_t j;

            for (j = 0; j < 16; j++) {
                ctx->ccm_mac[j] =
                    (uint8_t)(ctx->ccm_mac[j] ^ ctx->ccm_mblk[j]);
            }
            ret = wc_AesEncryptDirect(&ctx->ccm_aes, tmp, ctx->ccm_mac);
            if (ret != 0) {
                return wc_error_to_psa_status(ret);
            }
            XMEMCPY(ctx->ccm_mac, tmp, 16);
            ctx->ccm_mfill = 0;
            XMEMSET(ctx->ccm_mblk, 0, sizeof(ctx->ccm_mblk));
        }
    }

    return PSA_SUCCESS;
}

/* Finalize the last (possibly partial) message block and emit the tag:
 * tag = MAC XOR E(K, B1) where B1 = [lenSz-1][nonce][zeros]. */
static psa_status_t wolfpsa_aead_ccm_finish(wolfpsa_aead_ctx_t *ctx,
                                            uint8_t *tag, size_t tag_len)
{
    uint8_t tmp[16];
    uint8_t b1[16];
    size_t i;
    int ret;

    if (ctx->ccm_mfill > 0) {
        for (i = 0; i < 16; i++) {
            ctx->ccm_mac[i] =
                (uint8_t)(ctx->ccm_mac[i] ^ ctx->ccm_mblk[i]);
        }
        ret = wc_AesEncryptDirect(&ctx->ccm_aes, tmp, ctx->ccm_mac);
        if (ret != 0) {
            return wc_error_to_psa_status(ret);
        }
        XMEMCPY(ctx->ccm_mac, tmp, 16);
    }

    XMEMSET(b1, 0, sizeof(b1));
    b1[0] = (uint8_t)(ctx->ccm_lenSz - 1);
    XMEMCPY(b1 + 1, ctx->nonce, ctx->nonce_length);
    ret = wc_AesEncryptDirect(&ctx->ccm_aes, tmp, b1);
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }
    for (i = 0; i < tag_len; i++) {
        tag[i] = (uint8_t)(ctx->ccm_mac[i] ^ tmp[i]);
    }

    return PSA_SUCCESS;
}
#endif /* HAVE_AESCCM */

/* Stream one update() chunk through the per-algorithm streaming primitive.
 * On the first call the algorithm context is initialised and the AAD is fed
 * (which must precede data for GCM). */
static psa_status_t wolfpsa_aead_stream_update(wolfpsa_aead_ctx_t *ctx,
                                               const uint8_t *in, size_t n,
                                               uint8_t *out)
{
    const uint8_t *aad;
    size_t aad_len;
    int first = !ctx->streaming;
    int ret;

    aad = wolfpsa_aead_nonnull_data(ctx->aad, ctx->aad_length);
    aad_len = ctx->aad_length;

    if (PSA_ALG_AEAD_EQUAL(ctx->alg, PSA_ALG_GCM)) {
#ifdef HAVE_AESGCM
        if (first) {
            ret = (ctx->direction) ?
                wc_AesGcmEncryptInit(&ctx->gcm, ctx->key,
                                     (word32)ctx->key_length, ctx->nonce,
                                     (word32)ctx->nonce_length) :
                wc_AesGcmDecryptInit(&ctx->gcm, ctx->key,
                                     (word32)ctx->key_length, ctx->nonce,
                                     (word32)ctx->nonce_length);
            if (ret != 0) {
                return wc_error_to_psa_status(ret);
            }
        }
        ret = (ctx->direction) ?
            wc_AesGcmEncryptUpdate(&ctx->gcm, out, in, (word32)n,
                                   first ? aad : NULL,
                                   first ? (word32)aad_len : 0) :
            wc_AesGcmDecryptUpdate(&ctx->gcm, out, in, (word32)n,
                                   first ? aad : NULL,
                                   first ? (word32)aad_len : 0);
        if (ret != 0) {
            return wc_error_to_psa_status(ret);
        }
        return PSA_SUCCESS;
#else
        return PSA_ERROR_NOT_SUPPORTED;
#endif
    }
    else if (PSA_ALG_AEAD_EQUAL(ctx->alg, PSA_ALG_CHACHA20_POLY1305)) {
#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
        if (first) {
            ret = wc_ChaCha20Poly1305_Init(&ctx->chacha, ctx->key,
                                           ctx->nonce, ctx->direction);
            if (ret != 0) {
                return wc_error_to_psa_status(ret);
            }
            if (aad_len > 0) {
                ret = wc_ChaCha20Poly1305_UpdateAad(&ctx->chacha, aad,
                                                    (word32)aad_len);
                if (ret != 0) {
                    return wc_error_to_psa_status(ret);
                }
            }
        }
        ret = wc_ChaCha20Poly1305_UpdateData(&ctx->chacha, in, out,
                                             (word32)n);
        if (ret != 0) {
            return wc_error_to_psa_status(ret);
        }
        return PSA_SUCCESS;
#else
        return PSA_ERROR_NOT_SUPPORTED;
#endif
    }
    else if (PSA_ALG_AEAD_EQUAL(ctx->alg, PSA_ALG_CCM)) {
#ifdef HAVE_AESCCM
        if (first) {
            ret = wolfpsa_aead_ccm_init(ctx);
            if (ret != PSA_SUCCESS) {
                return ret;
            }
        }
        return wolfpsa_aead_ccm_update(ctx, in, n, out);
#else
        return PSA_ERROR_NOT_SUPPORTED;
#endif
    }

    return PSA_ERROR_NOT_SUPPORTED;
}

/* Emit the tag from the streaming state (the payload was already emitted
 * from update()). For decrypt the caller-supplied tag is verified. */
static psa_status_t wolfpsa_aead_stream_final(wolfpsa_aead_ctx_t *ctx,
                                              uint8_t *tag, size_t tag_len)
{
    int ret;

    if (PSA_ALG_AEAD_EQUAL(ctx->alg, PSA_ALG_GCM)) {
#ifdef HAVE_AESGCM
        ret = (ctx->direction) ?
            wc_AesGcmEncryptFinal(&ctx->gcm, tag, (word32)tag_len) :
            wc_AesGcmDecryptFinal(&ctx->gcm, tag, (word32)tag_len);
        if (ret != 0) {
            if (ret == AES_GCM_AUTH_E || ret == MAC_CMP_FAILED_E) {
                return PSA_ERROR_INVALID_SIGNATURE;
            }
            return wc_error_to_psa_status(ret);
        }
        return PSA_SUCCESS;
#else
        return PSA_ERROR_NOT_SUPPORTED;
#endif
    }
    else if (PSA_ALG_AEAD_EQUAL(ctx->alg, PSA_ALG_CHACHA20_POLY1305)) {
#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
        uint8_t computed[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE];

        ret = wc_ChaCha20Poly1305_Final(&ctx->chacha, computed);
        if (ret != 0) {
            return wc_error_to_psa_status(ret);
        }
        if (ctx->direction) {
            XMEMCPY(tag, computed, tag_len);
        }
        else if (wc_ChaCha20Poly1305_CheckTag(computed, tag) != 0) {
            return PSA_ERROR_INVALID_SIGNATURE;
        }
        return PSA_SUCCESS;
#else
        return PSA_ERROR_NOT_SUPPORTED;
#endif
    }
    else if (PSA_ALG_AEAD_EQUAL(ctx->alg, PSA_ALG_CCM)) {
#ifdef HAVE_AESCCM
        if (ctx->direction) {
            return wolfpsa_aead_ccm_finish(ctx, tag, tag_len);
        }
        else {
            uint8_t computed[16];
            volatile int diff = 0;
            size_t i;
            psa_status_t status;

            status = wolfpsa_aead_ccm_finish(ctx, computed, tag_len);
            if (status != PSA_SUCCESS) {
                return status;
            }
            for (i = 0; i < tag_len; i++) {
                diff |= computed[i] ^ tag[i];
            }
            if (diff != 0) {
                return PSA_ERROR_INVALID_SIGNATURE;
            }
            return PSA_SUCCESS;
        }
#else
        return PSA_ERROR_NOT_SUPPORTED;
#endif
    }

    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_aead_update(psa_aead_operation_t *operation,
                             const uint8_t *input,
                             size_t input_length,
                             uint8_t *output,
                             size_t output_size,
                             size_t *output_length)
{
    wolfpsa_aead_ctx_t *ctx = wolfpsa_aead_get_ctx(operation);
    psa_status_t status;

    if (ctx == NULL) {
        return PSA_ERROR_BAD_STATE;
    }
    if (output_length == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    (void)output;
    (void)output_size;
    *output_length = 0;

    if (PSA_ALG_AEAD_EQUAL(ctx->alg, PSA_ALG_CCM) && !ctx->lengths_set) {
        return PSA_ERROR_BAD_STATE;
    }
    if (ctx->nonce_length == 0) {
        return PSA_ERROR_BAD_STATE;
    }
    if (ctx->lengths_set && ctx->aad_length != ctx->ad_expected) {
        status = PSA_ERROR_INVALID_ARGUMENT;
        psa_aead_abort(operation);
        return status;
    }
    if (ctx->lengths_set &&
        (input_length > SIZE_MAX - ctx->input_length ||
         ctx->input_length + input_length > ctx->plaintext_expected)) {
        status = PSA_ERROR_INVALID_ARGUMENT;
        psa_aead_abort(operation);
        return status;
    }
    if (input_length == 0) {
        return PSA_SUCCESS;
    }

    if (output == NULL) {
        if (ctx->streaming) {
            status = PSA_ERROR_BAD_STATE;
            psa_aead_abort(operation);
            return status;
        }
        /* One-shot path: buffer the payload; finish()/verify() emits it. */
        status = wolfpsa_aead_append(&ctx->input, &ctx->input_length, input,
                                     input_length);
        if (status != PSA_SUCCESS) {
            psa_aead_abort(operation);
        }
        return status;
    }

    /* Multipart path: emit the chunk now; finish()/verify() emits only the
     * tag. Buffering and streaming must not be mixed within one operation. */
    if (ctx->input_length > 0) {
        status = PSA_ERROR_BAD_STATE;
        psa_aead_abort(operation);
        return status;
    }
    if (output_size < input_length) {
        status = PSA_ERROR_BUFFER_TOO_SMALL;
        psa_aead_abort(operation);
        return status;
    }

    status = wolfpsa_aead_stream_update(ctx, input, input_length, output);
    if (status != PSA_SUCCESS) {
        psa_aead_abort(operation);
        return status;
    }
    ctx->streaming = 1;
    *output_length = input_length;
    return PSA_SUCCESS;
}

static psa_status_t wolfpsa_aead_encrypt_final(wolfpsa_aead_ctx_t *ctx,
                                               uint8_t *ciphertext,
                                               size_t ciphertext_size,
                                               size_t *ciphertext_length,
                                               uint8_t *tag,
                                               size_t tag_size,
                                               size_t *tag_length)
{
    int ret;
#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
    size_t chacha_ciphertext_size = 0;
#endif
    const uint8_t *input;
    const uint8_t *aad;

    if (ciphertext == NULL || ciphertext_length == NULL ||
        tag == NULL || tag_length == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (ctx->nonce_length == 0) {
        return PSA_ERROR_BAD_STATE;
    }

    if (ctx->streaming) {
        psa_status_t status;

        /* All payload was emitted from update(); emit only the tag. The
         * set_lengths values were already enforced per chunk in update(),
         * and the buffered input is empty by construction. */
        if (tag_size < ctx->tag_length) {
            return PSA_ERROR_BUFFER_TOO_SMALL;
        }
        status = wolfpsa_aead_stream_final(ctx, tag, ctx->tag_length);
        if (status != PSA_SUCCESS) {
            return status;
        }
        *ciphertext_length = 0;
        *tag_length = ctx->tag_length;
        return PSA_SUCCESS;
    }

    if (ctx->lengths_set &&
        (ctx->aad_length != ctx->ad_expected ||
         ctx->input_length != ctx->plaintext_expected)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
    if (PSA_ALG_AEAD_EQUAL(ctx->alg, PSA_ALG_CHACHA20_POLY1305)) {
        if (ctx->input_length > SIZE_MAX - ctx->tag_length) {
            return PSA_ERROR_BUFFER_TOO_SMALL;
        }
        chacha_ciphertext_size = ctx->input_length + ctx->tag_length;
    }
#endif

    if (ciphertext_size < ctx->input_length) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    if (tag_size < ctx->tag_length) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    if ((wolfpsa_check_word32_length(ctx->input_length) != PSA_SUCCESS) ||
        (wolfpsa_check_word32_length(ctx->aad_length) != PSA_SUCCESS)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    input = wolfpsa_aead_nonnull_data(ctx->input, ctx->input_length);
    aad = wolfpsa_aead_nonnull_data(ctx->aad, ctx->aad_length);

    if (PSA_ALG_AEAD_EQUAL(ctx->alg, PSA_ALG_GCM)) {
#ifdef HAVE_AESGCM
        Aes aes;
        ret = wc_AesInit(&aes, NULL, wolfPSA_GetDefaultDevID());
        if (ret == 0) {
            ret = wc_AesGcmSetKey(&aes, ctx->key, (word32)ctx->key_length);
        }
        if (ret == 0) {
            ret = wc_AesGcmEncrypt(&aes, ciphertext, input,
                                   (word32)ctx->input_length,
                                   ctx->nonce, (word32)ctx->nonce_length,
                                   tag, (word32)ctx->tag_length,
                                   aad, (word32)ctx->aad_length);
        }
        wc_AesFree(&aes);
        wc_ForceZero(&aes, sizeof(aes));
        if (ret != 0) {
            return wc_error_to_psa_status(ret);
        }
#else
        return PSA_ERROR_NOT_SUPPORTED;
#endif
    }
    else if (PSA_ALG_AEAD_EQUAL(ctx->alg, PSA_ALG_CCM)) {
#ifdef HAVE_AESCCM
        Aes aes;
        if (wc_AesCcmCheckTagSize((int)ctx->tag_length) != 0) {
            return PSA_ERROR_NOT_SUPPORTED;
        }
        ret = wc_AesInit(&aes, NULL, wolfPSA_GetDefaultDevID());
        if (ret == 0) {
            ret = wc_AesCcmSetKey(&aes, ctx->key, (word32)ctx->key_length);
        }
        if (ret == 0) {
            ret = wc_AesCcmEncrypt(&aes, ciphertext, input,
                                   (word32)ctx->input_length,
                                   ctx->nonce, (word32)ctx->nonce_length,
                                   tag, (word32)ctx->tag_length,
                                   aad, (word32)ctx->aad_length);
        }
        wc_AesFree(&aes);
        wc_ForceZero(&aes, sizeof(aes));
        if (ret != 0) {
            return wc_error_to_psa_status(ret);
        }
#else
        return PSA_ERROR_NOT_SUPPORTED;
#endif
    }
    else if (PSA_ALG_AEAD_EQUAL(ctx->alg, PSA_ALG_CHACHA20_POLY1305)) {
#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
        size_t out_len = 0;
        uint8_t *tmp = (uint8_t *)XMALLOC(chacha_ciphertext_size, NULL,
                                          DYNAMIC_TYPE_TMP_BUFFER);
        if (tmp == NULL) {
            return PSA_ERROR_INSUFFICIENT_MEMORY;
        }
        ret = psa_chacha20_poly1305_encrypt(ctx->key, ctx->key_length, ctx->alg,
                                            ctx->nonce, ctx->nonce_length,
                                            aad, ctx->aad_length,
                                            input, ctx->input_length,
                                            tmp, chacha_ciphertext_size,
                                            &out_len);
        if (ret != 0) {
            wc_ForceZero(tmp, chacha_ciphertext_size);
            XFREE(tmp, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            return (psa_status_t)ret;
        }
        if (out_len < ctx->input_length + ctx->tag_length) {
            wc_ForceZero(tmp, chacha_ciphertext_size);
            XFREE(tmp, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            return PSA_ERROR_GENERIC_ERROR;
        }
        XMEMCPY(ciphertext, tmp, ctx->input_length);
        XMEMCPY(tag, tmp + ctx->input_length, ctx->tag_length);
        wc_ForceZero(tmp, chacha_ciphertext_size);
        XFREE(tmp, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#else
        return PSA_ERROR_NOT_SUPPORTED;
#endif
    }
    else {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    *ciphertext_length = ctx->input_length;
    *tag_length = ctx->tag_length;
    return PSA_SUCCESS;
}

static psa_status_t wolfpsa_aead_decrypt_final(wolfpsa_aead_ctx_t *ctx,
                                               uint8_t *plaintext,
                                               size_t plaintext_size,
                                               size_t *plaintext_length,
                                               const uint8_t *tag,
                                               size_t tag_length)
{
    int ret;
    const uint8_t *input;
    const uint8_t *aad;

    if (plaintext == NULL || plaintext_length == NULL || tag == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (ctx->nonce_length == 0) {
        return PSA_ERROR_BAD_STATE;
    }

    if (ctx->streaming) {
        psa_status_t status;

        /* All payload was emitted from update(); verify only the tag. The
         * set_lengths values were already enforced per chunk in update(),
         * and the buffered input is empty by construction. */
        if (tag_length != ctx->tag_length &&
            (ctx->alg & PSA_ALG_AEAD_AT_LEAST_THIS_LENGTH_FLAG) == 0) {
            return PSA_ERROR_INVALID_SIGNATURE;
        }
        status = wolfpsa_aead_stream_final(ctx, (uint8_t *)tag,
                                           ctx->tag_length);
        if (status != PSA_SUCCESS) {
            return status;
        }
        *plaintext_length = 0;
        return PSA_SUCCESS;
    }

    if (ctx->lengths_set &&
        (ctx->aad_length != ctx->ad_expected ||
         ctx->input_length != ctx->plaintext_expected)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (plaintext_size < ctx->input_length) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    if (tag_length != ctx->tag_length &&
        (ctx->alg & PSA_ALG_AEAD_AT_LEAST_THIS_LENGTH_FLAG) == 0) {
        return PSA_ERROR_INVALID_SIGNATURE;
    }

    if (tag_length < ctx->tag_length &&
        (ctx->alg & PSA_ALG_AEAD_AT_LEAST_THIS_LENGTH_FLAG) != 0) {
        return PSA_ERROR_INVALID_SIGNATURE;
    }

    if ((wolfpsa_check_word32_length(ctx->input_length) != PSA_SUCCESS) ||
        (wolfpsa_check_word32_length(ctx->aad_length) != PSA_SUCCESS)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    input = wolfpsa_aead_nonnull_data(ctx->input, ctx->input_length);
    aad = wolfpsa_aead_nonnull_data(ctx->aad, ctx->aad_length);

    if (PSA_ALG_AEAD_EQUAL(ctx->alg, PSA_ALG_GCM)) {
#ifdef HAVE_AESGCM
        Aes aes;
        ret = wc_AesInit(&aes, NULL, wolfPSA_GetDefaultDevID());
        if (ret == 0) {
            ret = wc_AesGcmSetKey(&aes, ctx->key, (word32)ctx->key_length);
        }
        if (ret == 0) {
            ret = wc_AesGcmDecrypt(&aes, plaintext, input,
                                   (word32)ctx->input_length,
                                   ctx->nonce, (word32)ctx->nonce_length,
                                   tag, (word32)tag_length,
                                   aad, (word32)ctx->aad_length);
        }
        wc_AesFree(&aes);
        wc_ForceZero(&aes, sizeof(aes));
        if (ret == AES_GCM_AUTH_E || ret == MAC_CMP_FAILED_E) {
            return PSA_ERROR_INVALID_SIGNATURE;
        }
        if (ret != 0) {
            return wc_error_to_psa_status(ret);
        }
#else
        return PSA_ERROR_NOT_SUPPORTED;
#endif
    }
    else if (PSA_ALG_AEAD_EQUAL(ctx->alg, PSA_ALG_CCM)) {
#ifdef HAVE_AESCCM
        Aes aes;
        if (wc_AesCcmCheckTagSize((int)tag_length) != 0) {
            return PSA_ERROR_INVALID_SIGNATURE;
        }
        ret = wc_AesInit(&aes, NULL, wolfPSA_GetDefaultDevID());
        if (ret == 0) {
            ret = wc_AesCcmSetKey(&aes, ctx->key, (word32)ctx->key_length);
        }
        if (ret == 0) {
            ret = wc_AesCcmDecrypt(&aes, plaintext, input,
                                   (word32)ctx->input_length,
                                   ctx->nonce, (word32)ctx->nonce_length,
                                   tag, (word32)tag_length,
                                   aad, (word32)ctx->aad_length);
        }
        wc_AesFree(&aes);
        wc_ForceZero(&aes, sizeof(aes));
        if (ret == AES_CCM_AUTH_E || ret == MAC_CMP_FAILED_E) {
            return PSA_ERROR_INVALID_SIGNATURE;
        }
        if (ret != 0) {
            return wc_error_to_psa_status(ret);
        }
#else
        return PSA_ERROR_NOT_SUPPORTED;
#endif
    }
    else if (PSA_ALG_AEAD_EQUAL(ctx->alg, PSA_ALG_CHACHA20_POLY1305)) {
#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
        size_t out_len = 0;
        uint8_t *ciphertext = ctx->input;
        size_t ciphertext_len;
        uint8_t *tmp;
        if (ctx->input_length > SIZE_MAX - tag_length) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        ciphertext_len = ctx->input_length + tag_length;
        tmp = (uint8_t *)XMALLOC(ciphertext_len, NULL,
                                          DYNAMIC_TYPE_TMP_BUFFER);
        if (tmp == NULL) {
            return PSA_ERROR_INSUFFICIENT_MEMORY;
        }
        XMEMCPY(tmp, ciphertext, ctx->input_length);
        XMEMCPY(tmp + ctx->input_length, tag, tag_length);
        ret = psa_chacha20_poly1305_decrypt(ctx->key, ctx->key_length, ctx->alg,
                                            ctx->nonce, ctx->nonce_length,
                                            aad, ctx->aad_length,
                                            tmp, ciphertext_len,
                                            plaintext, plaintext_size, &out_len);
        wc_ForceZero(tmp, ciphertext_len);
        XFREE(tmp, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (ret != 0) {
            return PSA_ERROR_INVALID_SIGNATURE;
        }
        *plaintext_length = out_len;
        return PSA_SUCCESS;
#else
        return PSA_ERROR_NOT_SUPPORTED;
#endif
    }
    else {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    *plaintext_length = ctx->input_length;
    return PSA_SUCCESS;
}

psa_status_t psa_aead_finish(psa_aead_operation_t *operation,
                             uint8_t *ciphertext,
                             size_t ciphertext_size,
                             size_t *ciphertext_length,
                             uint8_t *tag,
                             size_t tag_size,
                             size_t *tag_length)
{
    wolfpsa_aead_ctx_t *ctx = wolfpsa_aead_get_ctx(operation);
    psa_status_t status;

    if (ctx == NULL) {
        return PSA_ERROR_BAD_STATE;
    }

    if (!ctx->direction) {
        return PSA_ERROR_BAD_STATE;
    }

    status = wolfpsa_aead_encrypt_final(ctx, ciphertext, ciphertext_size,
                                        ciphertext_length, tag, tag_size,
                                        tag_length);
    psa_aead_abort(operation);
    return status;
}

psa_status_t psa_aead_verify(psa_aead_operation_t *operation,
                             uint8_t *plaintext,
                             size_t plaintext_size,
                             size_t *plaintext_length,
                             const uint8_t *tag,
                             size_t tag_length)
{
    wolfpsa_aead_ctx_t *ctx = wolfpsa_aead_get_ctx(operation);
    psa_status_t status;

    if (ctx == NULL) {
        return PSA_ERROR_BAD_STATE;
    }

    if (ctx->direction) {
        return PSA_ERROR_BAD_STATE;
    }

    status = wolfpsa_aead_decrypt_final(ctx, plaintext, plaintext_size,
                                        plaintext_length, tag, tag_length);
    psa_aead_abort(operation);
    return status;
}

#ifdef HAVE_XCHACHA
/* One-shot encrypt for XChaCha20-Poly1305.
 * ciphertext = plaintext || tag (16-byte Poly1305 tag appended). */
static psa_status_t wolfpsa_xchacha_oneshot_encrypt(
    psa_key_id_t key,
    psa_algorithm_t alg,
    const uint8_t *nonce, size_t nonce_length,
    const uint8_t *additional_data, size_t additional_data_length,
    const uint8_t *plaintext, size_t plaintext_length,
    uint8_t *ciphertext, size_t ciphertext_size, size_t *ciphertext_length)
{
    psa_key_attributes_t attributes;
    uint8_t *key_data = NULL;
    size_t key_data_length = 0;
    psa_status_t status;
    psa_key_usage_t key_usage;
    psa_algorithm_t key_alg;
    int ret;
    /* Encrypt produces plaintext_length bytes of ciphertext plus 16-byte tag. */
    size_t out_len;

    /* Only the native 16-byte tag is supported. A shortened-tag or
     * at-least-this-length variant differs from the base algorithm and must be
     * rejected rather than silently emitting a full-length tag. */
    if (alg != PSA_ALG_XCHACHA20_POLY1305) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    if (nonce_length != XCHACHA20_POLY1305_AEAD_NONCE_SIZE) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (ciphertext_length == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Check for overflow before output-size check. */
    if (plaintext_length > SIZE_MAX - CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    out_len = plaintext_length + CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE;
    if (ciphertext_size < out_len) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    status = wolfpsa_get_key_data(key, &attributes, &key_data, &key_data_length);
    if (status != PSA_SUCCESS) {
        return status;
    }

    if (attributes.type != PSA_KEY_TYPE_XCHACHA20 ||
        key_data_length != CHACHA20_POLY1305_AEAD_KEYSIZE) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    key_usage = psa_get_key_usage_flags(&attributes);
    if ((key_usage & PSA_KEY_USAGE_ENCRYPT) == 0) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return PSA_ERROR_NOT_PERMITTED;
    }

    key_alg = psa_get_key_algorithm(&attributes);
    if (!PSA_ALG_AEAD_EQUAL(key_alg, PSA_ALG_XCHACHA20_POLY1305)) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return PSA_ERROR_NOT_PERMITTED;
    }
    if (!PSA_ALG_AEAD_EQUAL(key_alg, alg)) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return PSA_ERROR_NOT_PERMITTED;
    }

    ret = wc_XChaCha20Poly1305_Encrypt(
        ciphertext, ciphertext_size,
        plaintext, plaintext_length,
        additional_data, additional_data_length,
        nonce, nonce_length,
        key_data, key_data_length);

    wolfpsa_forcezero_free_key_data(key_data, key_data_length);

    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }

    *ciphertext_length = out_len;
    return PSA_SUCCESS;
}

/* One-shot decrypt for XChaCha20-Poly1305.
 * ciphertext = ciphertext_body || tag (16-byte Poly1305 tag appended). */
static psa_status_t wolfpsa_xchacha_oneshot_decrypt(
    psa_key_id_t key,
    psa_algorithm_t alg,
    const uint8_t *nonce, size_t nonce_length,
    const uint8_t *additional_data, size_t additional_data_length,
    const uint8_t *ciphertext, size_t ciphertext_length,
    uint8_t *plaintext, size_t plaintext_size, size_t *plaintext_length)
{
    psa_key_attributes_t attributes;
    uint8_t *key_data = NULL;
    size_t key_data_length = 0;
    psa_status_t status;
    psa_key_usage_t key_usage;
    psa_algorithm_t key_alg;
    int ret;
    size_t pt_len;

    /* Only the native 16-byte tag is supported. A shortened-tag or
     * at-least-this-length variant differs from the base algorithm and must be
     * rejected rather than mis-framing the trailing tag bytes. */
    if (alg != PSA_ALG_XCHACHA20_POLY1305) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    if (nonce_length != XCHACHA20_POLY1305_AEAD_NONCE_SIZE) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (plaintext_length == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (ciphertext_length < CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    pt_len = ciphertext_length - CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE;
    if (plaintext_size < pt_len) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    status = wolfpsa_get_key_data(key, &attributes, &key_data, &key_data_length);
    if (status != PSA_SUCCESS) {
        return status;
    }

    if (attributes.type != PSA_KEY_TYPE_XCHACHA20 ||
        key_data_length != CHACHA20_POLY1305_AEAD_KEYSIZE) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    key_usage = psa_get_key_usage_flags(&attributes);
    if ((key_usage & PSA_KEY_USAGE_DECRYPT) == 0) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return PSA_ERROR_NOT_PERMITTED;
    }

    key_alg = psa_get_key_algorithm(&attributes);
    if (!PSA_ALG_AEAD_EQUAL(key_alg, PSA_ALG_XCHACHA20_POLY1305)) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return PSA_ERROR_NOT_PERMITTED;
    }
    if (!PSA_ALG_AEAD_EQUAL(key_alg, alg)) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return PSA_ERROR_NOT_PERMITTED;
    }

    /* wc_XChaCha20Poly1305_Decrypt expects src = ciphertext || tag and
     * dst_space must accommodate pt_len output bytes. */
    ret = wc_XChaCha20Poly1305_Decrypt(
        plaintext, plaintext_size,
        ciphertext, ciphertext_length,
        additional_data, additional_data_length,
        nonce, nonce_length,
        key_data, key_data_length);

    wolfpsa_forcezero_free_key_data(key_data, key_data_length);

    if (ret == MAC_CMP_FAILED_E) {
        return PSA_ERROR_INVALID_SIGNATURE;
    }
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }

    *plaintext_length = pt_len;
    return PSA_SUCCESS;
}
#endif /* HAVE_XCHACHA */

#ifdef HAVE_ASCON
/* One-shot encrypt for Ascon-AEAD128.
 * ciphertext = encrypted_body || tag (16-byte tag appended). */
static psa_status_t wolfpsa_ascon_oneshot_encrypt(
    psa_key_id_t key,
    psa_algorithm_t alg,
    const uint8_t *nonce, size_t nonce_length,
    const uint8_t *additional_data, size_t additional_data_length,
    const uint8_t *plaintext, size_t plaintext_length,
    uint8_t *ciphertext, size_t ciphertext_size, size_t *ciphertext_length)
{
    psa_key_attributes_t attributes;
    uint8_t *key_data = NULL;
    size_t key_data_length = 0;
    psa_status_t status;
    psa_key_usage_t key_usage;
    psa_algorithm_t key_alg;
    wc_AsconAEAD128 ascon;
    int ret;
    size_t out_len;

    /* Only the native 16-byte tag is supported. A shortened-tag or
     * at-least-this-length variant differs from the base algorithm and must be
     * rejected rather than silently emitting a full-length tag. */
    if (alg != PSA_ALG_ASCON_AEAD128) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    if (nonce_length != ASCON_AEAD128_NONCE_SZ) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (ciphertext_length == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (plaintext_length > SIZE_MAX - ASCON_AEAD128_TAG_SZ) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    out_len = plaintext_length + ASCON_AEAD128_TAG_SZ;
    if (ciphertext_size < out_len) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    if ((wolfpsa_check_word32_length(plaintext_length) != PSA_SUCCESS) ||
        (wolfpsa_check_word32_length(additional_data_length) != PSA_SUCCESS)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    status = wolfpsa_get_key_data(key, &attributes, &key_data, &key_data_length);
    if (status != PSA_SUCCESS) {
        return status;
    }

    if (attributes.type != PSA_KEY_TYPE_ASCON ||
        key_data_length != ASCON_AEAD128_KEY_SZ) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    key_usage = psa_get_key_usage_flags(&attributes);
    if ((key_usage & PSA_KEY_USAGE_ENCRYPT) == 0) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return PSA_ERROR_NOT_PERMITTED;
    }

    key_alg = psa_get_key_algorithm(&attributes);
    if (!PSA_ALG_AEAD_EQUAL(key_alg, PSA_ALG_ASCON_AEAD128)) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return PSA_ERROR_NOT_PERMITTED;
    }
    if (!PSA_ALG_AEAD_EQUAL(key_alg, alg)) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return PSA_ERROR_NOT_PERMITTED;
    }

    ret = wc_AsconAEAD128_Init(&ascon);
    if (ret == 0) {
        ret = wc_AsconAEAD128_SetKey(&ascon, key_data);
    }
    if (ret == 0) {
        ret = wc_AsconAEAD128_SetNonce(&ascon, nonce);
    }
    if (ret == 0) {
        ret = wc_AsconAEAD128_SetAD(&ascon, additional_data,
                                    (word32)additional_data_length);
    }
    if (ret == 0) {
        ret = wc_AsconAEAD128_EncryptUpdate(&ascon, ciphertext,
                                            plaintext, (word32)plaintext_length);
    }
    if (ret == 0) {
        /* Tag is written to ciphertext + plaintext_length. */
        ret = wc_AsconAEAD128_EncryptFinal(&ascon,
                                           ciphertext + plaintext_length);
    }

    wc_AsconAEAD128_Clear(&ascon);
    wc_ForceZero(&ascon, sizeof(ascon));
    wolfpsa_forcezero_free_key_data(key_data, key_data_length);

    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }

    *ciphertext_length = out_len;
    return PSA_SUCCESS;
}

/* One-shot decrypt for Ascon-AEAD128.
 * ciphertext = encrypted_body || tag (16-byte tag appended). */
static psa_status_t wolfpsa_ascon_oneshot_decrypt(
    psa_key_id_t key,
    psa_algorithm_t alg,
    const uint8_t *nonce, size_t nonce_length,
    const uint8_t *additional_data, size_t additional_data_length,
    const uint8_t *ciphertext, size_t ciphertext_length,
    uint8_t *plaintext, size_t plaintext_size, size_t *plaintext_length)
{
    psa_key_attributes_t attributes;
    uint8_t *key_data = NULL;
    size_t key_data_length = 0;
    psa_status_t status;
    psa_key_usage_t key_usage;
    psa_algorithm_t key_alg;
    wc_AsconAEAD128 ascon;
    int ret;
    size_t ct_len; /* ciphertext body length (without tag) */

    /* Only the native 16-byte tag is supported. A shortened-tag or
     * at-least-this-length variant differs from the base algorithm and must be
     * rejected rather than mis-framing the trailing tag bytes. */
    if (alg != PSA_ALG_ASCON_AEAD128) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    if (nonce_length != ASCON_AEAD128_NONCE_SZ) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (plaintext_length == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (ciphertext_length < ASCON_AEAD128_TAG_SZ) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    ct_len = ciphertext_length - ASCON_AEAD128_TAG_SZ;
    if (plaintext_size < ct_len) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    if ((wolfpsa_check_word32_length(ct_len) != PSA_SUCCESS) ||
        (wolfpsa_check_word32_length(additional_data_length) != PSA_SUCCESS)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    status = wolfpsa_get_key_data(key, &attributes, &key_data, &key_data_length);
    if (status != PSA_SUCCESS) {
        return status;
    }

    if (attributes.type != PSA_KEY_TYPE_ASCON ||
        key_data_length != ASCON_AEAD128_KEY_SZ) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    key_usage = psa_get_key_usage_flags(&attributes);
    if ((key_usage & PSA_KEY_USAGE_DECRYPT) == 0) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return PSA_ERROR_NOT_PERMITTED;
    }

    key_alg = psa_get_key_algorithm(&attributes);
    if (!PSA_ALG_AEAD_EQUAL(key_alg, PSA_ALG_ASCON_AEAD128)) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return PSA_ERROR_NOT_PERMITTED;
    }
    if (!PSA_ALG_AEAD_EQUAL(key_alg, alg)) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return PSA_ERROR_NOT_PERMITTED;
    }

    ret = wc_AsconAEAD128_Init(&ascon);
    if (ret == 0) {
        ret = wc_AsconAEAD128_SetKey(&ascon, key_data);
    }
    if (ret == 0) {
        ret = wc_AsconAEAD128_SetNonce(&ascon, nonce);
    }
    if (ret == 0) {
        ret = wc_AsconAEAD128_SetAD(&ascon, additional_data,
                                    (word32)additional_data_length);
    }
    if (ret == 0) {
        ret = wc_AsconAEAD128_DecryptUpdate(&ascon, plaintext,
                                            ciphertext, (word32)ct_len);
    }
    if (ret == 0) {
        /* Tag is at ciphertext + ct_len. */
        ret = wc_AsconAEAD128_DecryptFinal(&ascon, ciphertext + ct_len);
    }

    wc_AsconAEAD128_Clear(&ascon);
    wc_ForceZero(&ascon, sizeof(ascon));
    wolfpsa_forcezero_free_key_data(key_data, key_data_length);

    if (ret == MAC_CMP_FAILED_E || ret == ASCON_AUTH_E) {
        return PSA_ERROR_INVALID_SIGNATURE;
    }
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }

    *plaintext_length = ct_len;
    return PSA_SUCCESS;
}
#endif /* HAVE_ASCON */

psa_status_t psa_aead_encrypt(psa_key_id_t key,
                              psa_algorithm_t alg,
                              const uint8_t *nonce,
                              size_t nonce_length,
                              const uint8_t *additional_data,
                              size_t additional_data_length,
                              const uint8_t *plaintext,
                              size_t plaintext_length,
                              uint8_t *ciphertext,
                              size_t ciphertext_size,
                              size_t *ciphertext_length)
{
    psa_aead_operation_t operation = PSA_AEAD_OPERATION_INIT;
    psa_status_t status;
    uint8_t tag[PSA_AEAD_TAG_MAX_SIZE];
    size_t tag_length = 0;
    size_t out_len = 0;

    /* One-shot-only algorithms: bypass the multipart state machine. */
#ifdef HAVE_XCHACHA
    if (PSA_ALG_AEAD_EQUAL(alg, PSA_ALG_XCHACHA20_POLY1305)) {
        return wolfpsa_xchacha_oneshot_encrypt(key, alg, nonce, nonce_length,
            additional_data, additional_data_length, plaintext, plaintext_length,
            ciphertext, ciphertext_size, ciphertext_length);
    }
#endif /* HAVE_XCHACHA */
#ifdef HAVE_ASCON
    if (PSA_ALG_AEAD_EQUAL(alg, PSA_ALG_ASCON_AEAD128)) {
        return wolfpsa_ascon_oneshot_encrypt(key, alg, nonce, nonce_length,
            additional_data, additional_data_length, plaintext, plaintext_length,
            ciphertext, ciphertext_size, ciphertext_length);
    }
#endif /* HAVE_ASCON */

    status = psa_aead_encrypt_setup(&operation, key, alg);
    if (status != PSA_SUCCESS) {
        return status;
    }

    if (PSA_ALG_AEAD_EQUAL(alg, PSA_ALG_CCM)) {
        status = psa_aead_set_lengths(&operation, additional_data_length,
                                      plaintext_length);
        if (status != PSA_SUCCESS) {
            psa_aead_abort(&operation);
            return status;
        }
    }

    status = psa_aead_set_nonce(&operation, nonce, nonce_length);
    if (status != PSA_SUCCESS) {
        psa_aead_abort(&operation);
        return status;
    }

    status = psa_aead_update_ad(&operation, additional_data, additional_data_length);
    if (status != PSA_SUCCESS) {
        psa_aead_abort(&operation);
        return status;
    }

    status = psa_aead_update(&operation, plaintext, plaintext_length,
                             NULL, 0, &out_len);
    if (status != PSA_SUCCESS) {
        psa_aead_abort(&operation);
        return status;
    }

    {
        size_t needed_tag_len = wolfpsa_aead_tag_length(alg);
        if (needed_tag_len > ciphertext_size ||
            ciphertext_size - needed_tag_len < plaintext_length) {
            psa_aead_abort(&operation);
            return PSA_ERROR_BUFFER_TOO_SMALL;
        }
    }

    status = psa_aead_finish(&operation, ciphertext, ciphertext_size,
                             &out_len, tag, sizeof(tag), &tag_length);
    if (status != PSA_SUCCESS) {
        return status;
    }

    if (ciphertext_size < out_len + tag_length) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    XMEMCPY(ciphertext + out_len, tag, tag_length);
    *ciphertext_length = out_len + tag_length;
    return PSA_SUCCESS;
}

psa_status_t psa_aead_decrypt(psa_key_id_t key,
                              psa_algorithm_t alg,
                              const uint8_t *nonce,
                              size_t nonce_length,
                              const uint8_t *additional_data,
                              size_t additional_data_length,
                              const uint8_t *ciphertext,
                              size_t ciphertext_length,
                              uint8_t *plaintext,
                              size_t plaintext_size,
                              size_t *plaintext_length)
{
    psa_aead_operation_t operation = PSA_AEAD_OPERATION_INIT;
    psa_status_t status;
    size_t tag_length;
    size_t ct_len;

    /* One-shot-only algorithms: bypass the multipart state machine. */
#ifdef HAVE_XCHACHA
    if (PSA_ALG_AEAD_EQUAL(alg, PSA_ALG_XCHACHA20_POLY1305)) {
        return wolfpsa_xchacha_oneshot_decrypt(key, alg, nonce, nonce_length,
            additional_data, additional_data_length, ciphertext, ciphertext_length,
            plaintext, plaintext_size, plaintext_length);
    }
#endif /* HAVE_XCHACHA */
#ifdef HAVE_ASCON
    if (PSA_ALG_AEAD_EQUAL(alg, PSA_ALG_ASCON_AEAD128)) {
        return wolfpsa_ascon_oneshot_decrypt(key, alg, nonce, nonce_length,
            additional_data, additional_data_length, ciphertext, ciphertext_length,
            plaintext, plaintext_size, plaintext_length);
    }
#endif /* HAVE_ASCON */

    status = psa_aead_decrypt_setup(&operation, key, alg);
    if (status != PSA_SUCCESS) {
        return status;
    }

    tag_length = wolfpsa_aead_tag_length(alg);
    if (tag_length == 0 || ciphertext_length < tag_length) {
        psa_aead_abort(&operation);
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    ct_len = ciphertext_length - tag_length;

    if (PSA_ALG_AEAD_EQUAL(alg, PSA_ALG_CCM)) {
        status = psa_aead_set_lengths(&operation, additional_data_length,
                                      ct_len);
        if (status != PSA_SUCCESS) {
            psa_aead_abort(&operation);
            return status;
        }
    }

    status = psa_aead_set_nonce(&operation, nonce, nonce_length);
    if (status != PSA_SUCCESS) {
        psa_aead_abort(&operation);
        return status;
    }

    status = psa_aead_update_ad(&operation, additional_data, additional_data_length);
    if (status != PSA_SUCCESS) {
        psa_aead_abort(&operation);
        return status;
    }

    status = psa_aead_update(&operation, ciphertext, ct_len,
                             NULL, 0, plaintext_length);
    if (status != PSA_SUCCESS) {
        psa_aead_abort(&operation);
        return status;
    }

    status = psa_aead_verify(&operation, plaintext, plaintext_size,
                             plaintext_length,
                             ciphertext + ct_len, tag_length);
    return status;
}

psa_status_t psa_aead_abort(psa_aead_operation_t *operation)
{
    wolfpsa_aead_ctx_t *ctx = wolfpsa_aead_get_ctx(operation);

    if (operation == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (ctx != NULL) {
        if (ctx->aad != NULL) {
            wc_ForceZero(ctx->aad, ctx->aad_length);
            XFREE(ctx->aad, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        }
        if (ctx->input != NULL) {
            wc_ForceZero(ctx->input, ctx->input_length);
            XFREE(ctx->input, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        }
        if (ctx->key != NULL) {
            wc_ForceZero(ctx->key, ctx->key_length);
            XFREE(ctx->key, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        }
        wc_ForceZero(ctx, sizeof(*ctx));
        XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        operation->opaque = (uintptr_t)NULL;
    }

    return PSA_SUCCESS;
}

#endif /* WOLFSSL_PSA_ENGINE */
