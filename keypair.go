package virgil_crypto_go

import "gopkg.in/virgilsecurity/virgil-sdk-go.v4/virgilcrypto"

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