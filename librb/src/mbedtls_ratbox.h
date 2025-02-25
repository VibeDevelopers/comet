/*
 *  librb: a library used by ircd-ratbox and other things
 *  mbedtls_ratbox.h: embedded data for ARM MbedTLS backend
 *
 *  Copyright (C) 2016 Aaron Jones <aaronmdjones@gmail.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301
 *  USA
 *
 *  $Id$
 */

#ifndef RB_MBEDTLS_EMBEDDED_DATA_H
#define RB_MBEDTLS_EMBEDDED_DATA_H

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/certs.h"
#include "mbedtls/x509.h"
#include "mbedtls/ssl.h"
#include "mbedtls/ssl_ciphersuites.h"
#include "mbedtls/net.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"
#include "mbedtls/dhm.h"
#include "mbedtls/version.h"

/*
 * Personalization string for CTR-DRBG initialization
 */
static const char rb_mbedtls_personal_str[] = "comet/librb personalization string";

/*
 * Default list of supported ciphersuites
 * The user can override this with the ssl_cipher_list option in ircd.conf
 *
 * The format for this option is the same as the macro names below, but
 * with underscores replaced with hyphens, and without the initial MBEDTLS_
 *
 * For example;
 * ssl_cipher_list = "TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384"
 *
 * Multiple ciphersuites can be separated by colons (:)
 *
 * ************************************************************************
 *
 * The ordering of the following list should be intuitive. Within the list;
 *
 * * All AEAD forward-secret ciphersuites are located first [1]
 * * All SHA2 forward-secret ciphersuites are located second
 * * All remaining forward-secret ciphersuites are located third
 * * All non-forward-secret ciphersuites are located last, in the same order
 *
 *   [1] Because in practice, they are the only secure ciphersuites available;
 *       the ETM extension for CBC ciphersuites has not seen wide adoption.
 *
 * In practice, all clients SHOULD support an AEAD forward-secret cipher,
 * which the server will then negotiate as they are preferred.
 *
 * This choice can be revisited in future; please consult me first.  -- amdj
 */
static const int rb_mbedtls_ciphersuites[] = {

	// AEAD forward-secret ciphersuites

#ifdef	MBEDTLS_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
	MBEDTLS_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	MBEDTLS_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	MBEDTLS_TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
#endif

	MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	MBEDTLS_TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384,
	MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	MBEDTLS_TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384,
	MBEDTLS_TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
	MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384,
	MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CCM,
	MBEDTLS_TLS_DHE_RSA_WITH_AES_256_CCM,

	MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	MBEDTLS_TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256,
	MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	MBEDTLS_TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256,
	MBEDTLS_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
	MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256,
	MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
	MBEDTLS_TLS_DHE_RSA_WITH_AES_128_CCM,

	// SHA2 forward-secret ciphersuites

	MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
	MBEDTLS_TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384,
	MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
	MBEDTLS_TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384,
	MBEDTLS_TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
	MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256,

	MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
	MBEDTLS_TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256,
	MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
	MBEDTLS_TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,
	MBEDTLS_TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
	MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,

	// Remaining forward-secret ciphersuites

	MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	MBEDTLS_TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
	MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA,

	MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	MBEDTLS_TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
	MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA,

	// Non-forward-secret ciphersuites

	MBEDTLS_TLS_RSA_WITH_AES_256_GCM_SHA384,
	MBEDTLS_TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384,
	MBEDTLS_TLS_RSA_WITH_AES_256_CCM,

	MBEDTLS_TLS_RSA_WITH_AES_128_GCM_SHA256,
	MBEDTLS_TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256,
	MBEDTLS_TLS_RSA_WITH_AES_128_CCM,

	MBEDTLS_TLS_RSA_WITH_AES_256_CBC_SHA256,
	MBEDTLS_TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256,

	MBEDTLS_TLS_RSA_WITH_AES_128_CBC_SHA256,
	MBEDTLS_TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256,

	MBEDTLS_TLS_RSA_WITH_AES_256_CBC_SHA,
	MBEDTLS_TLS_RSA_WITH_CAMELLIA_256_CBC_SHA,

	MBEDTLS_TLS_RSA_WITH_AES_128_CBC_SHA,
	MBEDTLS_TLS_RSA_WITH_CAMELLIA_128_CBC_SHA,

	// The end of list sentinel
	0
};

/*
 * YES, this is a hardcoded CA certificate.
 *
 * BEFORE YOU THROW YOUR ARMS UP IN A PANIC ABOUT A BACKDOOR, READ THIS TEXT!
 *
 * ARM mbedTLS requires a CA certificate to be set in its configuration before it will
 * request a client certificate from peers. Since we want to do that, and not all
 * installations will have a CA certificate to hand, we have this.
 *
 * Its key was securely destroyed after being generated, but even if it wasn't, that
 * doesn't matter; the IRCd will accept ALL certificates, whether signed by this CA
 * certificate or not!
 *
 * After all, it only cares about certificates in as far as to generate a fingerprint
 * for them.
 *
 * Yes, this is a massive hack, but there is no alternative.
 */

static const unsigned char rb_mbedtls_dummy_ca_certificate[825] = {
	0x30, 0x82, 0x03, 0x35, 0x30, 0x82, 0x02, 0x1D, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x09, 0x00,
	0x86, 0xC5, 0x1F, 0x62, 0xBE, 0xFC, 0x0B, 0xA8, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86,
	0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00, 0x30, 0x31, 0x31, 0x2F, 0x30, 0x2D, 0x06, 0x03, 0x55,
	0x04, 0x03, 0x0C, 0x26, 0x43, 0x68, 0x61, 0x72, 0x79, 0x62, 0x64, 0x69, 0x73, 0x20, 0x6D, 0x62,
	0x65, 0x64, 0x54, 0x4C, 0x53, 0x20, 0x44, 0x75, 0x6D, 0x6D, 0x79, 0x20, 0x43, 0x41, 0x20, 0x43,
	0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x30, 0x1E, 0x17, 0x0D, 0x31, 0x36,
	0x30, 0x35, 0x30, 0x34, 0x30, 0x38, 0x35, 0x32, 0x35, 0x33, 0x5A, 0x17, 0x0D, 0x34, 0x33, 0x30,
	0x39, 0x32, 0x30, 0x30, 0x38, 0x35, 0x32, 0x35, 0x33, 0x5A, 0x30, 0x31, 0x31, 0x2F, 0x30, 0x2D,
	0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x26, 0x43, 0x68, 0x61, 0x72, 0x79, 0x62, 0x64, 0x69, 0x73,
	0x20, 0x6D, 0x62, 0x65, 0x64, 0x54, 0x4C, 0x53, 0x20, 0x44, 0x75, 0x6D, 0x6D, 0x79, 0x20, 0x43,
	0x41, 0x20, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x30, 0x82, 0x01,
	0x22, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00,
	0x03, 0x82, 0x01, 0x0F, 0x00, 0x30, 0x82, 0x01, 0x0A, 0x02, 0x82, 0x01, 0x01, 0x00, 0xCA, 0x4B,
	0xA6, 0xA1, 0x82, 0x5B, 0x06, 0xC6, 0x82, 0x76, 0x8E, 0xB2, 0x22, 0x37, 0x83, 0x91, 0x4B, 0xD0,
	0xAE, 0x2F, 0xEE, 0x8E, 0x60, 0x04, 0xBA, 0x77, 0x8C, 0xD0, 0xCF, 0x5E, 0xA4, 0xFD, 0x80, 0xA1,
	0x2E, 0xDC, 0x1F, 0xD9, 0x72, 0x2C, 0x28, 0x03, 0x27, 0x48, 0x23, 0x6E, 0x41, 0x49, 0x62, 0x09,
	0x2D, 0xCF, 0x87, 0xA1, 0x45, 0x9D, 0x2B, 0x43, 0x6F, 0xBB, 0xDB, 0x23, 0xD8, 0xD9, 0x6D, 0x36,
	0x4E, 0xA3, 0x85, 0x40, 0x4D, 0x72, 0xEC, 0x7B, 0xEF, 0x2B, 0x13, 0xE4, 0x6F, 0xDA, 0x23, 0x4F,
	0x1C, 0xE7, 0xEA, 0xD9, 0x17, 0x2B, 0xD6, 0x67, 0x79, 0x42, 0xC3, 0x81, 0x9A, 0x77, 0x64, 0xC7,
	0xC5, 0x44, 0xE1, 0xA4, 0xA3, 0x50, 0x8C, 0x1F, 0xCA, 0xD3, 0x6F, 0xC7, 0xFF, 0x2C, 0xBA, 0x7B,
	0x21, 0x0C, 0xF3, 0xA9, 0x6A, 0x89, 0x74, 0x33, 0x60, 0xA1, 0xF8, 0x9F, 0xAA, 0x39, 0xA9, 0x45,
	0x7E, 0x3D, 0x41, 0x67, 0x04, 0xF5, 0x9F, 0x47, 0x62, 0xAC, 0x65, 0xE0, 0x8D, 0x46, 0x9E, 0xD9,
	0xE5, 0x77, 0xD5, 0x8C, 0x47, 0xA2, 0xFB, 0x7D, 0x94, 0x27, 0xC9, 0xB9, 0x3F, 0x4D, 0xF4, 0xFD,
	0x19, 0x3C, 0xF6, 0x24, 0xAE, 0x70, 0xD7, 0x23, 0xE4, 0x64, 0x0A, 0xFC, 0x63, 0x89, 0x8A, 0xFE,
	0xD0, 0x8E, 0x48, 0x1A, 0xD8, 0xC3, 0xA9, 0xEC, 0x9D, 0x0F, 0xC7, 0xC5, 0x22, 0xBC, 0x45, 0x4A,
	0x2F, 0x4D, 0xF5, 0x0E, 0x4F, 0xFF, 0xAC, 0xE0, 0x55, 0xF4, 0x86, 0x04, 0x1B, 0x60, 0xDF, 0x4C,
	0x25, 0xB9, 0xEC, 0x10, 0x0C, 0x54, 0x16, 0xDF, 0x42, 0xF0, 0x07, 0x00, 0x28, 0x81, 0x7C, 0x95,
	0xAA, 0xC1, 0x01, 0xA3, 0xB8, 0xDF, 0x68, 0xCB, 0x55, 0xA7, 0x80, 0xCC, 0xE5, 0x3D, 0xE1, 0x68,
	0x10, 0x27, 0x56, 0x94, 0x67, 0xEC, 0x82, 0x66, 0x3D, 0x96, 0x76, 0xC3, 0xEE, 0x23, 0x02, 0x03,
	0x01, 0x00, 0x01, 0xA3, 0x50, 0x30, 0x4E, 0x30, 0x1D, 0x06, 0x03, 0x55, 0x1D, 0x0E, 0x04, 0x16,
	0x04, 0x14, 0xFF, 0xC8, 0xBA, 0x56, 0x74, 0xB1, 0x03, 0xA9, 0x79, 0x55, 0xFA, 0x58, 0x86, 0x13,
	0xDE, 0xC0, 0xFA, 0xF2, 0x94, 0x62, 0x30, 0x1F, 0x06, 0x03, 0x55, 0x1D, 0x23, 0x04, 0x18, 0x30,
	0x16, 0x80, 0x14, 0xFF, 0xC8, 0xBA, 0x56, 0x74, 0xB1, 0x03, 0xA9, 0x79, 0x55, 0xFA, 0x58, 0x86,
	0x13, 0xDE, 0xC0, 0xFA, 0xF2, 0x94, 0x62, 0x30, 0x0C, 0x06, 0x03, 0x55, 0x1D, 0x13, 0x04, 0x05,
	0x30, 0x03, 0x01, 0x01, 0xFF, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01,
	0x01, 0x0B, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x3D, 0x35, 0x69, 0x87, 0xEB, 0x41, 0xA9,
	0x2A, 0x51, 0xF3, 0x28, 0x71, 0xB4, 0x06, 0x7F, 0x15, 0x5A, 0x6D, 0x88, 0x5B, 0xC8, 0x4C, 0xE1,
	0x6C, 0xC7, 0xCB, 0x93, 0x63, 0x69, 0xFB, 0xA6, 0x6D, 0xC7, 0x44, 0x6B, 0xD6, 0x39, 0x46, 0x34,
	0xFC, 0x45, 0x23, 0xD2, 0x29, 0x1B, 0xCC, 0x1C, 0x13, 0xD7, 0x63, 0x10, 0x81, 0xF5, 0x82, 0x45,
	0xEC, 0xDC, 0x20, 0x5F, 0xBB, 0xC3, 0xE6, 0x4A, 0x07, 0xA7, 0xBD, 0x9E, 0xFC, 0x5D, 0xFE, 0xC5,
	0x43, 0x3A, 0xC6, 0xA4, 0x6C, 0x5B, 0xF9, 0x63, 0x8F, 0xF9, 0xEB, 0xC2, 0xF4, 0xA7, 0xE4, 0x1B,
	0x23, 0xFA, 0xE1, 0x5A, 0x79, 0xC5, 0x1D, 0x1D, 0xFC, 0xAA, 0x81, 0xF7, 0x21, 0x52, 0xC9, 0x46,
	0x17, 0x1B, 0x24, 0x4B, 0x14, 0x5C, 0xF9, 0xB5, 0x86, 0x04, 0x80, 0x51, 0x95, 0xCF, 0x4E, 0x47,
	0x32, 0x8A, 0x1E, 0x52, 0x2E, 0xBF, 0x08, 0x8E, 0x9E, 0xE3, 0x88, 0x45, 0xC3, 0x75, 0xD7, 0xAE,
	0xC3, 0x7E, 0x7E, 0xE9, 0xC9, 0x5B, 0xD8, 0x58, 0x3B, 0x25, 0x53, 0x0C, 0x00, 0x21, 0x1A, 0x71,
	0x12, 0x23, 0xA0, 0x35, 0x6E, 0xC9, 0x7D, 0x83, 0x5C, 0x19, 0xE4, 0x05, 0x84, 0x46, 0x4E, 0x50,
	0xE2, 0x9E, 0x70, 0x2E, 0x74, 0x05, 0xEA, 0x31, 0x04, 0x55, 0xA7, 0xF4, 0x67, 0x95, 0xDC, 0x86,
	0x1F, 0x9D, 0xA0, 0x5D, 0x7F, 0x29, 0x48, 0x84, 0xEF, 0x13, 0xB8, 0xB3, 0xBF, 0x65, 0xD4, 0x52,
	0x98, 0x06, 0xE6, 0x8A, 0xB1, 0x36, 0xEA, 0x39, 0xB3, 0x04, 0x2B, 0x6E, 0x64, 0x6E, 0xF3, 0x20,
	0x74, 0xB6, 0x6E, 0x21, 0x3B, 0x99, 0xFE, 0x6E, 0x70, 0x48, 0x78, 0xEA, 0x31, 0x95, 0xB3, 0xB0,
	0x0E, 0x48, 0x83, 0x35, 0xA9, 0x74, 0xBF, 0x45, 0x07, 0xC8, 0x5A, 0x12, 0xA2, 0x4D, 0x16, 0xDB,
	0xB3, 0x1F, 0x72, 0xDE, 0x2A, 0x28, 0xFE, 0x7C, 0x2D
};

#endif /* RB_MBEDTLS_EMBEDDED_DATA_H */
