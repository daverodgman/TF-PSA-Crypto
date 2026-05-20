/**
 * \file aesce_common.h
 *
 * \brief This file contains AESCE definitions and functions common to
 * both the AESCE and GCM modules.
 *
 * Copyright The Mbed TLS Contributors
 * SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef TF_PSA_CRYPTO_MBEDTLS_PRIVATE_AESCE_COMMON_H
#define TF_PSA_CRYPTO_MBEDTLS_PRIVATE_AESCE_COMMON_H

#if defined(MBEDTLS_AESCE_C) \
    && defined(MBEDTLS_ARCH_IS_ARMV8_A) && defined(MBEDTLS_HAVE_NEON_INTRINSICS) \
    && (defined(MBEDTLS_COMPILER_IS_GCC) || defined(__clang__) || defined(MSC_VER))

/* MBEDTLS_AESCE_HAVE_CODE is defined if we have a suitable target platform, and a
 * potentially suitable compiler (compiler version & flags are not checked when defining
 * this). */
#define MBEDTLS_AESCE_HAVE_CODE
#endif

#endif /* TF_PSA_CRYPTO_MBEDTLS_PRIVATE_AESCE_COMMON_H */
