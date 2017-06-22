package virgil_crypto_go

type nativePublicKey struct {
	receiverID []byte
	key        []byte
}

func (k *nativePublicKey) contents() []byte {
	return k.key
}

func (k *nativePublicKey) ReceiverID() []byte {
	return k.receiverID
}

func (k *nativePublicKey) Encode() ([]byte, error) {

	derPub := make([]byte, len(k.key))
	copy(derPub,k.key)
	/*vkey := ToVirgilByteArray(k.key)
	defer DeleteVirgilByteArray(vkey)
	vder := VirgilKeyPairPublicKeyToDER(vkey)
	defer DeleteVirgilByteArray(vder)
	derPub := ToSlice(vder)*/
	return derPub, nil
}

func (k *nativePublicKey) Empty() bool {
	return k == nil || len(k.key) == 0
}