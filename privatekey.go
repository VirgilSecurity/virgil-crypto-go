package virgil_crypto_go

import "gopkg.in/virgil.v6/crypto-native"

type externalPrivateKey struct {
	receiverID []byte
	key        []byte
}

func (k *externalPrivateKey) contents() []byte {
	return k.key
}

func (k *externalPrivateKey) ReceiverID() []byte {
	return k.receiverID
}

func (k *externalPrivateKey) Encode(password []byte) ([]byte, error) {
	if len(password) == 0 {

		vkey := ToVirgilByteArray(k.key)
		defer DeleteVirgilByteArray(vkey)
		venc := VirgilKeyPairPrivateKeyToDER(vkey)
		defer DeleteVirgilByteArray(venc)

		return ToSlice(venc), nil
	} else {
		vkey := ToVirgilByteArray(k.key)
		defer DeleteVirgilByteArray(vkey)
		vpass := ToVirgilByteArray([]byte(password))
		defer DeleteVirgilByteArray(vpass)
		return ToSlice(VirgilKeyPairEncryptPrivateKey(vkey, vpass)), nil
	}
}

func (k *externalPrivateKey) Empty() bool {
	return k == nil || len(k.key) == 0
}

func (k *externalPrivateKey) ExtractPublicKey() (cryptonative.PublicKey, error) {
	vkey := ToVirgilByteArray(k.key)
	defer DeleteVirgilByteArray(vkey)
	vempty := ToVirgilByteArray(make([]byte, 0))
	defer DeleteVirgilByteArray(vempty)
	pub := VirgilKeyPairExtractPublicKey(vkey, vempty)
	defer DeleteVirgilByteArray(pub)
	vder := VirgilKeyPairPublicKeyToDER(pub)
	defer DeleteVirgilByteArray(vder)

	derPub := ToSlice(vder)
	return &externalPublicKey{
		key:        derPub,
		receiverID: k.receiverID,
	}, nil
}
