package virgil_crypto_go

// KeyType denotes algorithm used for key generation. See keytypes package
type KeyType int

const (
	Default = iota
	RSA_2048
	RSA_3072
	RSA_4096
	RSA_8192
	EC_SECP256R1
	EC_SECP384R1
	EC_SECP521R1
	EC_BP256R1
	EC_BP384R1
	EC_BP512R1
	EC_SECP256K1
	EC_CURVE25519
	FAST_EC_X25519
	FAST_EC_ED25519
)

var KeyTypeMap = map[KeyType]interface{}{
	Default:         VirgilKeyPairType_FAST_EC_ED25519,
	RSA_2048:        VirgilKeyPairType_RSA_2048,
	RSA_3072:        VirgilKeyPairType_RSA_3072,
	RSA_4096:        VirgilKeyPairType_RSA_4096,
	RSA_8192:        VirgilKeyPairType_RSA_8192,
	EC_SECP256R1:    VirgilKeyPairType_EC_SECP256R1,
	EC_SECP384R1:    VirgilKeyPairType_EC_SECP384R1,
	EC_SECP521R1:    VirgilKeyPairType_EC_SECP521R1,
	EC_BP256R1:      VirgilKeyPairType_EC_BP256R1,
	EC_BP384R1:      VirgilKeyPairType_EC_BP384R1,
	EC_BP512R1:      VirgilKeyPairType_EC_BP512R1,
	EC_SECP256K1:    VirgilKeyPairType_EC_SECP256K1,
	EC_CURVE25519:   VirgilKeyPairType_EC_CURVE25519,
	FAST_EC_X25519:  VirgilKeyPairType_FAST_EC_X25519,
	FAST_EC_ED25519: VirgilKeyPairType_FAST_EC_ED25519,
}
