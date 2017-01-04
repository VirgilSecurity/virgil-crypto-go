package virgil_crypto_go

import (
	"gopkg.in/virgilsecurity/virgil-sdk-go.v4/virgilcrypto"
	"io"
	"crypto/sha256"
	"encoding/base64"
	"github.com/pkg/errors"
	"fmt"
)

type NativeCrypto struct {

}

var unsupportedError = errors.New("unsupported")

const signatureKey = "VIRGIL-DATA-SIGNATURE"

func (c *NativeCrypto) GenerateKeypair() (_ virgilcrypto.Keypair, err error) {

	defer func() {
		if r := recover(); r != nil {
			var ok bool
			err, ok = r.(error)
			if !ok {
				err = fmt.Errorf("pkg: %v", r)
			}
		}
	}()

	kp := VirgilKeyPairGenerate(VirgilKeyPairType_FAST_EC_ED25519)
	rawPub := ToSlice(VirgilKeyPairPublicKeyToDER(kp.PublicKey()))
	receiverId := c.CalculateFingerprint(rawPub)

	pub := &nativePublicKey{
		key:rawPub,
		receiverID:receiverId,
	}

	rawPriv := ToSlice(VirgilKeyPairPrivateKeyToDER(kp.PrivateKey()))

	priv := &nativePrivateKey{
		key:rawPriv,
		receiverID:receiverId,
	}

	return &nativeKeypair{
		publicKey:pub,
		privateKey:priv,
	}, nil
}

func (c *NativeCrypto) ImportPrivateKey(data []byte, password string) (_ virgilcrypto.PrivateKey, err error) {
	defer func() {
		if r := recover(); r != nil {
			var ok bool
			err, ok = r.(error)
			if !ok {
				err = fmt.Errorf("pkg: %v", r)
			}
		}
	}()
	var rawPriv []byte

	if(password == ""){
		rawPriv = data
	} else {
		rawPriv = ToSlice(VirgilKeyPairPrivateKeyToDER( VirgilKeyPairDecryptPrivateKey(ToVirgilByteArray(data), ToVirgilByteArray([]byte(password)))))
	}

	rawPub := ToSlice(VirgilKeyPairExtractPublicKey(ToVirgilByteArray(rawPriv), ToVirgilByteArray(make([]byte, 0))))

	receiverId := c.CalculateFingerprint(rawPub)

	return &nativePrivateKey{
		key:rawPriv,
		receiverID:receiverId,
	}, nil
}

func (c *NativeCrypto) ImportPublicKey(data []byte) (_ virgilcrypto.PublicKey, err error) {
	defer func() {
		if r := recover(); r != nil {
			var ok bool
			err, ok = r.(error)
			if !ok {
				err = fmt.Errorf("pkg: %v", r)
			}
		}
	}()
	rawPub := ToSlice(VirgilKeyPairPublicKeyToDER(ToVirgilByteArray(data)))
	receiverId := c.CalculateFingerprint(rawPub)

	return &nativePublicKey{
		key:rawPub,
		receiverID:receiverId,
	}, nil

}

func (c *NativeCrypto) ExportPrivateKey(key virgilcrypto.PrivateKey, password string) (_ []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			var ok bool
			err, ok = r.(error)
			if !ok {
				err = fmt.Errorf("pkg: %v", r)
			}
		}
	}()
	return key.Encode([]byte(password))
}

func (c *NativeCrypto) ExportPublicKey(key virgilcrypto.PublicKey) (_ []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			var ok bool
			err, ok = r.(error)
			if !ok {
				err = fmt.Errorf("pkg: %v", r)
			}
		}
	}()
	return key.Encode()
}

func (c *NativeCrypto) Encrypt(data []byte, recipients ...virgilcrypto.PublicKey) (_ []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			var ok bool
			err, ok = r.(error)
			if !ok {
				err = fmt.Errorf("pkg: %v", r)
			}
		}
	}()

	ci := NewVirgilCipher()
	for _,r := range recipients{
		ci.AddKeyRecipient(ToVirgilByteArray(r.ReceiverID()), ToVirgilByteArray(r.Contents()))
	}
	ct := ToSlice(ci.Encrypt(ToVirgilByteArray(data), true))
	return ct, nil
}

func (c *NativeCrypto) EncryptStream(in io.Reader, out io.Writer, recipients ...virgilcrypto.PublicKey) ( error) {

  	return unsupportedError

}

func (c *NativeCrypto) Decrypt(data []byte, key virgilcrypto.PrivateKey) (_ []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			var ok bool
			err, ok = r.(error)
			if !ok {
				err = fmt.Errorf("pkg: %v", r)
			}
		}
	}()

	ci := NewVirgilCipher()
	k := key.(*nativePrivateKey)
	plainText := ToSlice(ci.DecryptWithKey(ToVirgilByteArray(data), ToVirgilByteArray(key.ReceiverID()), ToVirgilByteArray(k.Contents())))
	return plainText, nil
}

func (c *NativeCrypto) DecryptStream(in io.Reader, out io.Writer, key virgilcrypto.PrivateKey) error {
	return unsupportedError
}

func (c *NativeCrypto) Sign(data []byte, signer virgilcrypto.PrivateKey) (_ []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			var ok bool
			err, ok = r.(error)
			if !ok {
				err = fmt.Errorf("pkg: %v", r)
			}
		}
	}()

	s := NewVirgilSigner()
	k := signer.(*nativePrivateKey)
	signature := ToSlice(s.Sign(ToVirgilByteArray(data), ToVirgilByteArray(k.key)))
	return signature, nil
}

func (c *NativeCrypto) Verify(data []byte, signature []byte, key virgilcrypto.PublicKey) (_ bool, err error) {
	defer func() {
		if r := recover(); r != nil {
			var ok bool
			err, ok = r.(error)
			if !ok {
				err = fmt.Errorf("pkg: %v", r)
			}
		}
	}()
	s := NewVirgilSigner()
	valid := s.Verify(ToVirgilByteArray(data), ToVirgilByteArray(signature), ToVirgilByteArray(key.Contents()))
	return valid, nil
}

func (c *NativeCrypto) SignStream(in io.Reader, signer virgilcrypto.PrivateKey) ([]byte, error) {
	return nil, unsupportedError
}

func (c *NativeCrypto) VerifyStream(in io.Reader, signature []byte, key virgilcrypto.PublicKey) (bool, error) {
	return false, unsupportedError
}
func (c *NativeCrypto) CalculateFingerprint(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

func (c *NativeCrypto) SignThenEncrypt(data []byte, signerKey virgilcrypto.PrivateKey, recipients ...virgilcrypto.PublicKey) (_ []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			var ok bool
			err, ok = r.(error)
			if !ok {
				err = fmt.Errorf("pkg: %v", r)
			}
		}
	}()
	ci := NewVirgilCipher()
	params := ci.CustomParams().(VirgilCustomParams)

	signature, err := c.Sign(data, signerKey)
	if(err != nil){
		return nil, err
	}

	params.SetString(ToVirgilByteArray([]byte(signatureKey)), ToVirgilByteArray(signature))

	for _,r := range recipients{
		ci.AddKeyRecipient(ToVirgilByteArray(r.ReceiverID()), ToVirgilByteArray(r.Contents()))
	}
	ct := ToSlice(ci.Encrypt(ToVirgilByteArray(data), true))
	return ct, nil
}

func (c *NativeCrypto) DecryptThenVerify(data []byte, decryptionKey virgilcrypto.PrivateKey, verifierKey virgilcrypto.PublicKey) (_ []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			var ok bool
			err, ok = r.(error)
			if !ok {
				err = fmt.Errorf("pkg: %v", r)
			}
		}
	}()
	ci := NewVirgilCipher()
	pt := ToSlice(ci.DecryptWithKey(ToVirgilByteArray(data), ToVirgilByteArray(decryptionKey.ReceiverID()), ToVirgilByteArray(decryptionKey.(*nativePrivateKey).key)))
	sig := ToSlice(ci.CustomParams().(VirgilCustomParams).GetString(ToVirgilByteArray([]byte(signatureKey))))

	valid, err := c.Verify(pt, sig, verifierKey)
	if(!valid){
		return nil, err
	}
	return pt, nil
}

//ToSlice converts VirgilByteArray to a go slice
func ToSlice(b VirgilByteArray) []byte{
	str := VirgilBase64Encode(b)
	ret, _ := base64.StdEncoding.DecodeString(str)
	return ret
}

//ToVirgilByteArray converts go slice to a VirgilByteArray
func ToVirgilByteArray(data []byte) VirgilByteArray{
	str := base64.StdEncoding.EncodeToString(data)
	return VirgilBase64Decode(str)
}
