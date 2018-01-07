package virgil_crypto_go

import (
	"gopkg.in/virgil.v6/crypto-native"
	"gopkg.in/virgil.v6/crypto-native/keytypes"
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
