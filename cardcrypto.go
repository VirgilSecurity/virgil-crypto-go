package virgil_crypto_go

import "crypto/sha512"

type CardCrypto struct {
	Crypto *ExternalCrypto
}

func NewCardCrypto() *CardCrypto {
	return &CardCrypto{Crypto: &ExternalCrypto{}}
}

func (c *CardCrypto) GenerateSignature(data []byte, key interface {
	IsPrivate() bool
	Identifier() []byte
}) ([]byte, error) {
	return c.Crypto.Sign(data, key.(*externalPrivateKey))
}

func (c *CardCrypto) VerifySignature(data []byte, signature []byte, key interface {
	IsPublic() bool
	Identifier() []byte
}) error {
	return c.Crypto.VerifySignature(data, signature, key.(*externalPublicKey))
}

func (c *CardCrypto) ExportPublicKey(key interface {
	IsPublic() bool
	Identifier() []byte
}) ([]byte, error) {
	return c.Crypto.ExportPublicKey(key.(*externalPublicKey))
}

func (c *CardCrypto) ImportPublicKey(data []byte) (interface {
	IsPublic() bool
	Identifier() []byte
}, error) {
	return c.Crypto.ImportPublicKey(data)
}

func (c *CardCrypto) GenerateSHA512(data []byte) []byte {
	hash := sha512.Sum512(data)
	return hash[:]
}
