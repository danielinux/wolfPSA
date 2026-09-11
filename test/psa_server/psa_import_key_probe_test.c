/* psa_import_key_probe_test.c
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
 *
 * Standalone test for the psa_import_key() persistent-store existence probe.
 * It provides a mock wolfPSA_Store_* backend (the POSIX store cannot return an
 * I/O error on a read probe, only 0 or NOT_AVAILABLE) so the probe-failure
 * path can be exercised deterministically. Build it against a wolfPSA archive
 * that excludes the store backend objects so this file is the only provider
 * of the wolfPSA_Store_* symbols.
 */

/* MEMORY_E comes from wolfCrypt, whose headers need a configuration before
 * <settings.h>: same prologue as the sibling tests that reach into it. */
#include "psa_api_test_user_settings.h"

#ifndef WOLFSSL_USER_SETTINGS
#define WOLFSSL_USER_SETTINGS
#endif

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include <wolfpsa/psa/crypto.h>
#include <psa_store.h>

#include <stdio.h>
#include <string.h>

/* ---- mock store backend: the only wolfPSA_Store_* in the link ---- */

static int g_probe_ret = 0;
static uint8_t g_data[1024];
static size_t g_len = 0;
static int g_exists = 0;

static void mock_reset(void)
{
    g_probe_ret = 0;
    memset(g_data, 0, sizeof(g_data));
    g_len = 0;
    g_exists = 0;
}

int wolfPSA_Store_Open(int type, unsigned long id1, unsigned long id2, int read,
    void** store)
{
    (void)type;
    (void)id1;
    (void)id2;
    if (store == NULL) {
        return WOLFPSA_STORE_IO_ERROR;
    }
    *store = NULL;
    if (read) {
        /* The existence probe: return the value under test. */
        return g_probe_ret;
    }
    *store = (void*)1;
    return WOLFPSA_STORE_OK;
}

int wolfPSA_Store_OpenSz(int type, unsigned long id1, unsigned long id2,
    int read, int variableSz, void** store)
{
    (void)variableSz;
    return wolfPSA_Store_Open(type, id1, id2, read, store);
}

int wolfPSA_Store_Read(void* store, unsigned char* buffer, int len)
{
    (void)store;
    if (!g_exists || (size_t)len < g_len) {
        return -1;
    }
    memcpy(buffer, g_data, g_len);
    return (int)g_len;
}

int wolfPSA_Store_Write(void* store, unsigned char* buffer, int len)
{
    (void)store;
    if (len < 0 || (size_t)len > sizeof(g_data)) {
        return -1;
    }
    memcpy(g_data, buffer, (size_t)len);
    g_len = (size_t)len;
    g_exists = 1;
    return len;
}

void wolfPSA_Store_Close(void* store)
{
    (void)store;
}

int wolfPSA_Store_Remove(int type, unsigned long id1, unsigned long id2)
{
    (void)type;
    (void)id1;
    (void)id2;
    g_exists = 0;
    g_len = 0;
    return WOLFPSA_STORE_OK;
}

/* ---- test helpers ---- */

static void setup_aes_attr(psa_key_attributes_t* attr, psa_key_id_t id)
{
    *attr = psa_key_attributes_init();
    psa_set_key_type(attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(attr, 128);
    psa_set_key_usage_flags(attr, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(attr, PSA_ALG_GCM);
    psa_set_key_lifetime(attr, PSA_KEY_LIFETIME_PERSISTENT);
    psa_set_key_id(attr, id);
}

/* Probe reports the key exists (ret == 0): import fails with
 * ALREADY_EXISTS and the stored record is untouched. */
static int test_probe_exists(void)
{
    psa_key_attributes_t attr;
    uint8_t key[16];
    uint8_t stored[16];
    psa_key_id_t key_id = 0;
    psa_status_t st;
    int ok = 1;

    mock_reset();
    memset(stored, 0x11, sizeof(stored));
    memcpy(g_data, stored, sizeof(stored));
    g_len = sizeof(stored);
    g_exists = 1;
    g_probe_ret = 0;
    setup_aes_attr(&attr, 0x1000);
    memset(key, 0xAA, sizeof(key));

    st = psa_import_key(&attr, key, sizeof(key), &key_id);
    if (st != PSA_ERROR_ALREADY_EXISTS) {
        printf("FAIL probe_exists: expected ALREADY_EXISTS, got %d\n", (int)st);
        ok = 0;
    }
    if (g_len != sizeof(stored) || memcmp(g_data, stored, sizeof(stored)) != 0) {
        printf("FAIL probe_exists: stored record was modified\n");
        ok = 0;
    }
    return ok;
}

/* Probe reports the key is absent (ret == -4): import succeeds and creates
 * the record. */
static int test_probe_absent(void)
{
    psa_key_attributes_t attr;
    uint8_t key[16];
    psa_key_id_t key_id = 0;
    psa_status_t st;
    int ok = 1;

    mock_reset();
    g_exists = 0;
    g_probe_ret = WOLFPSA_STORE_NOT_AVAILABLE;
    setup_aes_attr(&attr, 0x1000);
    memset(key, 0xBB, sizeof(key));

    st = psa_import_key(&attr, key, sizeof(key), &key_id);
    if (st != PSA_SUCCESS) {
        printf("FAIL probe_absent: expected SUCCESS, got %d\n", (int)st);
        ok = 0;
    }
    if (!g_exists) {
        printf("FAIL probe_absent: key was not created\n");
        ok = 0;
    }
    return ok;
}

/* Probe fails with an I/O error (ret == -5, not -4): import must not proceed
 * to the write path (which would overwrite the existing record); it must
 * return STORAGE_FAILURE and leave the stored record intact. */
static int test_probe_io_error(void)
{
    psa_key_attributes_t attr;
    uint8_t key[16];
    uint8_t stored[16];
    psa_key_id_t key_id = 0;
    psa_status_t st;
    int ok = 1;

    mock_reset();
    memset(stored, 0x22, sizeof(stored));
    memcpy(g_data, stored, sizeof(stored));
    g_len = sizeof(stored);
    g_exists = 1;
    g_probe_ret = WOLFPSA_STORE_IO_ERROR;
    setup_aes_attr(&attr, 0x1000);
    memset(key, 0xCC, sizeof(key));

    st = psa_import_key(&attr, key, sizeof(key), &key_id);
    if (st != PSA_ERROR_STORAGE_FAILURE) {
        printf("FAIL probe_io_error: expected STORAGE_FAILURE, got %d\n",
               (int)st);
        ok = 0;
    }
    if (g_len != sizeof(stored) || memcmp(g_data, stored, sizeof(stored)) != 0) {
        printf("FAIL probe_io_error: existing record was overwritten\n");
        ok = 0;
    }
    return ok;
}

/* The probe fails to allocate its store context (MEMORY_E): import must
 * report memory exhaustion, not a storage failure, and must leave the
 * existing record intact. */
static int test_probe_memory_error(void)
{
    psa_key_attributes_t attr;
    uint8_t key[16];
    uint8_t stored[16];
    psa_key_id_t key_id = 0;
    psa_status_t st;
    int ok = 1;

    mock_reset();
    memset(stored, 0x33, sizeof(stored));
    memcpy(g_data, stored, sizeof(stored));
    g_len = sizeof(stored);
    g_exists = 1;
    g_probe_ret = MEMORY_E;
    setup_aes_attr(&attr, 0x1000);
    memset(key, 0xDD, sizeof(key));

    st = psa_import_key(&attr, key, sizeof(key), &key_id);
    if (st != PSA_ERROR_INSUFFICIENT_MEMORY) {
        printf("FAIL probe_memory_error: expected INSUFFICIENT_MEMORY, "
               "got %d\n", (int)st);
        ok = 0;
    }
    if (g_len != sizeof(stored) || memcmp(g_data, stored, sizeof(stored)) != 0) {
        printf("FAIL probe_memory_error: existing record was overwritten\n");
        ok = 0;
    }
    return ok;
}

int main(void)
{
    int ok = 1;
    psa_status_t st;

    st = psa_crypto_init();
    if (st != PSA_SUCCESS) {
        printf("FAIL psa_crypto_init: %d\n", (int)st);
        return 1;
    }

    if (!test_probe_exists()) {
        ok = 0;
    }
    if (!test_probe_absent()) {
        ok = 0;
    }
    if (!test_probe_io_error()) {
        ok = 0;
    }
    if (!test_probe_memory_error()) {
        ok = 0;
    }

    if (ok) {
        printf("psa_import_key_probe_test: all tests passed\n");
        return 0;
    }
    printf("psa_import_key_probe_test: FAILED\n");
    return 1;
}
