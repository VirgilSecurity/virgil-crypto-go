package virgil_crypto_go

import "gopkg.in/virgil.v5/errors"

type VirgilPrivateKeyExporter struct {
	Crypto   *ExternalCrypto
	Password string
}

func NewPrivateKeyExporter(password string) *VirgilPrivateKeyExporter {
	return &VirgilPrivateKeyExporter{
		Crypto:   NewVirgilCrypto(),
		Password: password,
	}
}

func (v *VirgilPrivateKeyExporter) ExportPrivateKey(key interface {
	IsPrivate() bool
	Identifier() []byte
}) ([]byte, error) {

	if v.Crypto == nil {
		return nil, errors.New("Crypto is not set")
	}
	kkey, ok := key.(*externalPrivateKey)
	if !ok {
		return nil, errors.New("this key type is not supported")
	}

	return v.Crypto.ExportPrivateKey(kkey, v.Password)
}

func (v *VirgilPrivateKeyExporter) ImportPrivateKey(data []byte) (interface {
	IsPrivate() bool
	Identifier() []byte
}, error) {

	if v.Crypto == nil {
		return nil, errors.New("Crypto is not set")
	}

	return v.Crypto.ImportPrivateKey(data, v.Password)
}
