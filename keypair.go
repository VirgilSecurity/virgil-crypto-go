package virgil_crypto_go

import (
	"encoding/base64"
	"encoding/pem"
	"gopkg.in/virgil.v6/crypto-native"
)

type nativeKeypair struct {
	publicKey  *nativePublicKey
	privateKey *nativePrivateKey
}

func (e *nativeKeypair) HasPublic() bool {
	return e.publicKey != nil && !e.publicKey.Empty()
}
func (e *nativeKeypair) HasPrivate() bool {
	return e.privateKey != nil && !e.privateKey.Empty()
}
func (e *nativeKeypair) PublicKey() cryptonative.PublicKey {
	return e.publicKey
}
func (e *nativeKeypair) PrivateKey() cryptonative.PrivateKey {
	return e.privateKey
}

func unwrapKey(key []byte) []byte {

	block, _ := pem.Decode(key)
	if block != nil {
		return block.Bytes
	} else {
		buf := make([]byte, base64.StdEncoding.DecodedLen(len(key)))

		read, err := base64.StdEncoding.Decode(buf, key)

		if err == nil {
			return buf[:read]
		}

		return key //already DER
	}
}
