package virgil_crypto_go

type VirgilAccessTokenSigner struct {
	Crypto *ExternalCrypto
}

func NewVirgilAccessTokenSigner() *VirgilAccessTokenSigner {
	return &VirgilAccessTokenSigner{Crypto: &ExternalCrypto{}}
}

func (t *VirgilAccessTokenSigner) GenerateTokenSignature(data []byte, privateKey interface {
	IsPrivate() bool
}) ([]byte, error) {
	return t.Crypto.Sign(data, privateKey.(*externalPrivateKey))

}
func (t *VirgilAccessTokenSigner) VerifyTokenSignature(data []byte, signature []byte, publicKey interface {
	IsPublic() bool
}) error {
	return t.Crypto.VerifySignature(data, signature, publicKey.(*externalPublicKey))

}
func (t *VirgilAccessTokenSigner) GetAlgorithm() string {
	return "VEDS512"
}
