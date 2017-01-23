package virgil_crypto_go

import (
	"gopkg.in/virgil.v4/virgilcrypto"
	"encoding/base64"
	"encoding/pem"
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
func (e *nativeKeypair) PublicKey() virgilcrypto.PublicKey {
	return e.publicKey
}
func (e *nativeKeypair) PrivateKey() virgilcrypto.PrivateKey {
	return e.privateKey
}

func unwrapKey(key []byte) ([]byte) {

	block, _ := pem.Decode(key)
	if block != nil {
		return block.Bytes
	} else{
		buf := make([]byte, base64.StdEncoding.DecodedLen(len(key)))

		read, err := base64.StdEncoding.Decode(buf, key)

		if err == nil {
			return buf[:read]
		}

		return key //already DER
	}
}