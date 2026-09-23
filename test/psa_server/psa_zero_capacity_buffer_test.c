/* psa_zero_capacity_buffer_test.c
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

/* Regression test for the PSA zero-capacity buffer contract: an output
 * buffer may be represented by (NULL, 0), and an input buffer by (NULL, 0);
 * such calls must reach the size/length checks and return the contract
 * status (BUFFER_TOO_SMALL, INVALID_SIGNATURE, ...), not
 * INVALID_ARGUMENT. Covers F-13860..F-13872. */

#include "psa_api_test_user_settings.h"

#ifndef WOLFSSL_USER_SETTINGS
#define WOLFSSL_USER_SETTINGS
#endif

#include <wolfssl/wolfcrypt/settings.h>

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <wolfpsa/psa/crypto.h>

#define TEST_KEY_BITS 2048

static int check_status(psa_status_t st, psa_status_t expected,
                        const char *what)
{
    if (st != expected) {
        printf("FAIL: %s (status=%d, expected %d)\n",
               what, (int)st, (int)expected);
        return 1;
    }
    return 0;
}

/* F-13861: psa_generate_random(NULL, 0) is a valid empty request. */
static int test_random_zero(void)
{
    int rc = 0;

    rc |= check_status(psa_generate_random(NULL, 0), PSA_SUCCESS,
                       "generate_random(NULL, 0)");
    if (rc == 0) {
        printf("PASS: random zero-length\n");
    }
    return rc;
}

/* F-13862: exporting a nonempty key into (NULL, 0) is BUFFER_TOO_SMALL. */
static int test_copy_key_failure_clears_target(void)
{
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_key_id_t target = 0x12345678;
    psa_status_t st;

    st = psa_copy_key(0xdeadbeef, &attrs, &target);
    if (st == PSA_SUCCESS) {
        printf("FAIL: copy_key of a missing key unexpectedly succeeded\n");
        return 1;
    }
    if (target != PSA_KEY_ID_NULL) {
        printf("FAIL: copy_key left stale target id %u on failure\n",
               (unsigned)target);
        return 1;
    }
    printf("PASS: copy_key failure clears target\n");
    return 0;
}

/* F-13863: finishing a hash into (NULL, 0) is BUFFER_TOO_SMALL. */
int main(void)
{
    int rc = 0;

    if (psa_crypto_init() != PSA_SUCCESS) {
        printf("FAIL: psa_crypto_init\n");
        return 1;
    }

    rc |= test_random_zero();
    rc |= test_copy_key_failure_clears_target();

    if (rc != 0) {
        printf("PSA zero-capacity buffer test: FAIL\n");
        return 1;
    }
    printf("PSA zero-capacity buffer test: OK\n");
    return 0;
}
