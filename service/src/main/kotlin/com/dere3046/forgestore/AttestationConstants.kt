/*
 * This file is part of ForgeStore
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program;
 * if not, see <https://www.gnu.org/licenses/>.
 *
 * Copyright (C) 2026 TheGeniusClub
 */

package com.dere3046.forgestore

object AttestationConstants {
    val ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17"
    val ATTESTATION_OID_OBJ = org.bouncycastle.asn1.ASN1ObjectIdentifier(ATTESTATION_OID)

    const val KEY_DESCRIPTION_ATTESTATION_VERSION_INDEX = 0
    const val KEY_DESCRIPTION_ATTESTATION_SECURITY_LEVEL_INDEX = 1
    const val KEY_DESCRIPTION_KEYMINT_VERSION_INDEX = 2
    const val KEY_DESCRIPTION_KEYMINT_SECURITY_LEVEL_INDEX = 3
    const val KEY_DESCRIPTION_ATTESTATION_CHALLENGE_INDEX = 4
    const val KEY_DESCRIPTION_UNIQUE_ID_INDEX = 5
    const val KEY_DESCRIPTION_SOFTWARE_ENFORCED_INDEX = 6
    const val KEY_DESCRIPTION_TEE_ENFORCED_INDEX = 7

    const val ROOT_OF_TRUST_VERIFIED_BOOT_KEY_INDEX = 0
    const val ROOT_OF_TRUST_DEVICE_LOCKED_INDEX = 1
    const val ROOT_OF_TRUST_VERIFIED_BOOT_STATE_INDEX = 2
    const val ROOT_OF_TRUST_VERIFIED_BOOT_HASH_INDEX = 3

    const val TAG_PURPOSE = 1
    const val TAG_ALGORITHM = 2
    const val TAG_KEY_SIZE = 3
    const val TAG_BLOCK_MODE = 4
    const val TAG_DIGEST = 5
    const val TAG_PADDING = 6
    const val TAG_CALLER_NONCE = 7
    const val TAG_MIN_MAC_LENGTH = 8
    const val TAG_EC_CURVE = 10
    const val TAG_RSA_PUBLIC_EXPONENT = 200
    const val TAG_RSA_OAEP_MGF_DIGEST = 203
    const val TAG_USER_ID = 501
    const val TAG_USER_SECURE_ID = 502
    const val TAG_NO_AUTH_REQUIRED = 503
    const val TAG_USER_AUTH_TYPE = 504
    const val TAG_AUTH_TIMEOUT = 505
    const val TAG_APPLICATION_ID = 601
    const val TAG_CREATION_DATETIME = 701
    const val TAG_ORIGIN = 702
    const val TAG_ROOT_OF_TRUST = 704
    const val TAG_OS_VERSION = 705
    const val TAG_OS_PATCHLEVEL = 706
    const val TAG_UNIQUE_ID = 707
    const val TAG_ATTESTATION_CHALLENGE = 708
    const val TAG_ATTESTATION_APPLICATION_ID = 709
    const val TAG_ATTESTATION_ID_BRAND = 710
    const val TAG_ATTESTATION_ID_DEVICE = 711
    const val TAG_ATTESTATION_ID_PRODUCT = 712
    const val TAG_ATTESTATION_ID_SERIAL = 713
    const val TAG_ATTESTATION_ID_IMEI = 714
    const val TAG_ATTESTATION_ID_MEID = 715
    const val TAG_ATTESTATION_ID_MANUFACTURER = 716
    const val TAG_ATTESTATION_ID_MODEL = 717
    const val TAG_VENDOR_PATCHLEVEL = 718
    const val TAG_BOOT_PATCHLEVEL = 719
    const val TAG_DEVICE_UNIQUE_ATTESTATION = 720
    const val TAG_ATTESTATION_ID_SECOND_IMEI = 723
    const val TAG_MODULE_HASH = 724
    const val TAG_CERTIFICATE_SERIAL = 1006
    const val TAG_CERTIFICATE_SUBJECT = 1007
    const val TAG_CERTIFICATE_NOT_BEFORE = 1008
    const val TAG_CERTIFICATE_NOT_AFTER = 1009

    const val CHALLENGE_LENGTH_LIMIT = 128
}
