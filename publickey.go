package virgil_crypto_go

type nativePublicKey struct {
	receiverID []byte
	key        []byte
}

func (k *nativePublicKey) Contents() []byte {
	return k.key
}

func (k *nativePublicKey) ReceiverID() []byte {
	return k.receiverID
}

func (k *nativePublicKey) Encode() ([]byte, error) {
	vkey := ToVirgilByteArray(k.key)
	defer DeleteVirgilByteArray(vkey)
	vder := VirgilKeyPairPublicKeyToDER(vkey)
	defer DeleteVirgilByteArray(vder)
	derPub := ToSlice(vder)
	return derPub, nil
}

func (k *nativePublicKey) Empty() bool {
	return k == nil || len(k.key) == 0
}