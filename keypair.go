package virgil_crypto_go

import (
	"encoding/base64"
	"encoding/pem"
	"gopkg.in/virgil.v6/crypto-native"
)

type externalKeypair struct {
	publicKey  *externalPublicKey
	privateKey *externalPrivateKey
}

func (e *externalKeypair) HasPublic() bool {
	return e.publicKey != nil && !e.publicKey.Empty()
}
func (e *externalKeypair) HasPrivate() bool {
	return e.privateKey != nil && !e.privateKey.Empty()
}
func (e *externalKeypair) PublicKey() cryptonative.PublicKey {
	return e.publicKey
}
func (e *externalKeypair) PrivateKey() cryptonative.PrivateKey {
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
