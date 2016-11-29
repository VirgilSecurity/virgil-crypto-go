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
	derPub := ToSlice(VirgilKeyPairPublicKeyToDER(ToVirgilByteArray(k.key)))
	return derPub, nil
}

func (k *nativePublicKey) Empty() bool {
	return k == nil || len(k.key) == 0
}