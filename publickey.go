package virgil_crypto_go

type externalPublicKey struct {
	receiverID []byte
	key        []byte
}

func (k *externalPublicKey) contents() []byte {
	return k.key
}

func (k *externalPublicKey) ReceiverID() []byte {
	return k.receiverID
}

func (k *externalPublicKey) Encode() ([]byte, error) {

	derPub := make([]byte, len(k.key))
	copy(derPub, k.key)
	/*vkey := ToVirgilByteArray(k.key)
	defer DeleteVirgilByteArray(vkey)
	vder := VirgilKeyPairPublicKeyToDER(vkey)
	defer DeleteVirgilByteArray(vder)
	derPub := ToSlice(vder)*/
	return derPub, nil
}

func (k *externalPublicKey) Empty() bool {
	return k == nil || len(k.key) == 0
}
