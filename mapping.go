/*
 * Copyright (C) 2015-2018 Virgil Security Inc.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   (1) Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 *   (2) Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 *
 *   (3) Neither the name of the copyright holder nor the names of its
 *   contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

package virgil_crypto_go

import (
	"gopkg.in/virgil.v5/crypto-native"
	"gopkg.in/virgil.v5/crypto-native/keytypes"
)

var KeyTypeMap = map[cryptonative.KeyType]interface{}{
	keytypes.Default:         VirgilKeyPairType_FAST_EC_ED25519,
	keytypes.RSA_2048:        VirgilKeyPairType_RSA_2048,
	keytypes.RSA_3072:        VirgilKeyPairType_RSA_3072,
	keytypes.RSA_4096:        VirgilKeyPairType_RSA_4096,
	keytypes.RSA_8192:        VirgilKeyPairType_RSA_8192,
	keytypes.EC_SECP256R1:    VirgilKeyPairType_EC_SECP256R1,
	keytypes.EC_SECP384R1:    VirgilKeyPairType_EC_SECP384R1,
	keytypes.EC_SECP521R1:    VirgilKeyPairType_EC_SECP521R1,
	keytypes.EC_BP256R1:      VirgilKeyPairType_EC_BP256R1,
	keytypes.EC_BP384R1:      VirgilKeyPairType_EC_BP384R1,
	keytypes.EC_BP512R1:      VirgilKeyPairType_EC_BP512R1,
	keytypes.EC_SECP256K1:    VirgilKeyPairType_EC_SECP256K1,
	keytypes.EC_CURVE25519:   VirgilKeyPairType_EC_CURVE25519,
	keytypes.FAST_EC_X25519:  VirgilKeyPairType_FAST_EC_X25519,
	keytypes.FAST_EC_ED25519: VirgilKeyPairType_FAST_EC_ED25519,
}
