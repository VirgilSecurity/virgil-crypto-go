package virgil_crypto_go

import "gopkg.in/virgil.v4/virgilcrypto"

type nativePrivateKey struct {
	receiverID []byte
	key        []byte
}


func (k *nativePrivateKey) Contents() []byte {
	return k.key
}

func (k *nativePrivateKey) ReceiverID() []byte {
	return k.receiverID
}

func (k *nativePrivateKey) Encode(password []byte) (res []byte, err error) {
	if(len(password) == 0){
		return ToSlice(VirgilKeyPairPrivateKeyToDER(ToVirgilByteArray(k.key))), nil
	} else {
		return ToSlice(VirgilKeyPairEncryptPrivateKey(ToVirgilByteArray(k.key), ToVirgilByteArray([]byte(password)))), nil
	}
}

func (k *nativePrivateKey) Empty() bool {
	return k == nil || len(k.key) == 0
}

func (k *nativePrivateKey) ExtractPublicKey() (virgilcrypto.PublicKey, error) {
	pub := VirgilKeyPairExtractPublicKey(ToVirgilByteArray(k.key), ToVirgilByteArray(make([]byte,0)))
	derPub := ToSlice(VirgilKeyPairPublicKeyToDER(pub))
	return &nativePublicKey{
		key:derPub,
		receiverID:k.receiverID,
	}, nil
}
