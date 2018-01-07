package virgil_crypto_go

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"github.com/pkg/errors"
	"gopkg.in/virgil.v6/crypto-api"
	"gopkg.in/virgil.v6/crypto-native"
	"io"
)

type ExternalCrypto struct {
	keyType cryptonative.KeyType
}

const (
	signatureKey = "VIRGIL-DATA-SIGNATURE"
	signerId     = "VIRGIL-DATA-SIGNER-ID"
)

func (c *ExternalCrypto) SetKeyType(keyType cryptonative.KeyType) error {
	if _, ok := KeyTypeMap[keyType]; !ok {
		return errors.New("key type not supported")
	} else {
		c.keyType = keyType
		return nil
	}
}

func (c *ExternalCrypto) GenerateKeypair() (_ cryptonative.Keypair, err error) {

	defer func() {
		if r := recover(); r != nil {
			var ok bool
			err, ok = r.(error)
			if !ok {
				err = fmt.Errorf("pkg: %v", r)
			}
		}
	}()

	keyType, ok := KeyTypeMap[c.keyType]
	if !ok {
		return nil, errors.New("This key type is not supported")
	}

	kp := VirgilKeyPairGenerate(keyType)
	defer DeleteVirgilKeyPair(kp)

	der := VirgilKeyPairPublicKeyToDER(kp.PublicKey())
	defer DeleteVirgilByteArray(der)

	rawPub := ToSlice(der)
	receiverId := c.CalculateFingerprint(rawPub)

	pub := &externalPublicKey{
		key:        rawPub,
		receiverID: receiverId,
	}

	der1 := VirgilKeyPairPrivateKeyToDER(kp.PrivateKey())
	defer DeleteVirgilByteArray(der1)
	rawPriv := ToSlice(der1)

	priv := &externalPrivateKey{
		key:        rawPriv,
		receiverID: receiverId,
	}

	return &externalKeypair{
		publicKey:  pub,
		privateKey: priv,
	}, nil
}

func (c *ExternalCrypto) ImportPrivateKey(data []byte, password string) (_ cryptoapi.PrivateKey, err error) {
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

	unwrappedKey := unwrapKey(data)
	if password == "" {
		rawPriv = unwrappedKey
	} else {

		vdata := ToVirgilByteArray(unwrappedKey)
		defer DeleteVirgilByteArray(vdata)
		vpassword := ToVirgilByteArray([]byte(password))
		defer DeleteVirgilByteArray(vpassword)
		dec := VirgilKeyPairDecryptPrivateKey(vdata, vpassword)
		defer DeleteVirgilByteArray(dec)
		der := VirgilKeyPairPrivateKeyToDER(dec)
		defer DeleteVirgilByteArray(der)

		rawPriv = ToSlice(der)
	}

	vpriv := ToVirgilByteArray(rawPriv)
	defer DeleteVirgilByteArray(vpriv)
	vempty := ToVirgilByteArray(make([]byte, 0))
	defer DeleteVirgilByteArray(vempty)
	vpub := VirgilKeyPairExtractPublicKey(vpriv, vempty)
	defer DeleteVirgilByteArray(vpub)

	rawPub := ToSlice(vpub)

	receiverId := c.CalculateFingerprint(rawPub)

	return &externalPrivateKey{
		key:        rawPriv,
		receiverID: receiverId,
	}, nil
}

func (c *ExternalCrypto) ImportPublicKey(data []byte) (_ cryptoapi.PublicKey, err error) {
	rawPub := unwrapKey(data)
	receiverId := c.CalculateFingerprint(rawPub)

	return &externalPublicKey{
		key:        rawPub,
		receiverID: receiverId,
	}, nil

}

func (c *ExternalCrypto) ExportPrivateKey(key cryptoapi.PrivateKey, password string) (_ []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			var ok bool
			err, ok = r.(error)
			if !ok {
				err = fmt.Errorf("pkg: %v", r)
			}
		}
	}()

	k, ok := key.(*externalPrivateKey)
	if !ok {
		return nil, errors.New("wrong private key type")
	}
	return k.Encode([]byte(password))
}

func (c *ExternalCrypto) ExportPublicKey(key cryptoapi.PublicKey) (_ []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			var ok bool
			err, ok = r.(error)
			if !ok {
				err = fmt.Errorf("pkg: %v", r)
			}
		}
	}()
	k, ok := key.(*externalPublicKey)
	if !ok {
		return nil, errors.New("wrong private key type")
	}
	return k.Encode()
}

func (c *ExternalCrypto) Encrypt(data []byte, recipients ...cryptoapi.PublicKey) (_ []byte, err error) {
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
	defer DeleteVirgilCipher(ci)

	for _, r := range recipients {
		rec := r.(*externalPublicKey)

		vrec := ToVirgilByteArray(rec.ReceiverID())
		defer DeleteVirgilByteArray(vrec)
		vcon := ToVirgilByteArray(rec.contents())
		defer DeleteVirgilByteArray(vcon)
		ci.AddKeyRecipient(vrec, vcon)
	}
	vdata := ToVirgilByteArray(data)
	defer DeleteVirgilByteArray(vdata)

	venc := ci.Encrypt(vdata, true)
	defer DeleteVirgilByteArray(venc)

	ct := ToSlice(venc)

	return ct, nil
}

func (c *ExternalCrypto) EncryptStream(in io.Reader, out io.Writer, recipients ...cryptoapi.PublicKey) (err error) {
	defer func() {
		if r := recover(); r != nil {
			var ok bool
			err, ok = r.(error)
			if !ok {
				err = fmt.Errorf("pkg: %v", r)
			}
		}
	}()

	s := NewDirectorVirgilDataSource(NewDataSource(in))
	defer DeleteDirectorVirgilDataSource(s)

	d := NewDirectorVirgilDataSink(NewDataSink(out))
	defer DeleteDirectorVirgilDataSink(d)

	ci := NewVirgilStreamCipher()
	defer DeleteVirgilStreamCipher(ci)

	for _, r := range recipients {
		rec := r.(*externalPublicKey)
		vrec := ToVirgilByteArray(rec.ReceiverID())
		defer DeleteVirgilByteArray(vrec)

		vcon := ToVirgilByteArray(rec.contents())
		defer DeleteVirgilByteArray(vcon)
		ci.AddKeyRecipient(vrec, vcon)

	}

	ci.Encrypt(s, d)

	return

}

func (c *ExternalCrypto) Decrypt(data []byte, key cryptoapi.PrivateKey) (_ []byte, err error) {
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
	defer DeleteVirgilCipher(ci)

	k, ok := key.(*externalPrivateKey)
	if !ok {
		return
	}

	vdata := ToVirgilByteArray(data)
	defer DeleteVirgilByteArray(vdata)
	vrec := ToVirgilByteArray(k.ReceiverID())
	defer DeleteVirgilByteArray(vrec)
	vcontents := ToVirgilByteArray(k.contents())
	defer DeleteVirgilByteArray(vcontents)

	vplain := ci.DecryptWithKey(vdata, vrec, vcontents)
	defer DeleteVirgilByteArray(vplain)
	plainText := ToSlice(vplain)
	return plainText, nil
}

func (c *ExternalCrypto) DecryptStream(in io.Reader, out io.Writer, key cryptoapi.PrivateKey) (err error) {
	defer func() {
		if r := recover(); r != nil {
			var ok bool
			err, ok = r.(error)
			if !ok {
				err = fmt.Errorf("pkg: %v", r)
			}
		}
	}()

	d := NewDirectorVirgilDataSink(NewDataSink(out))
	defer DeleteDirectorVirgilDataSink(d)
	s := NewDirectorVirgilDataSource(NewDataSource(in))
	defer DeleteDirectorVirgilDataSource(s)

	ci := NewVirgilStreamCipher()
	defer DeleteVirgilStreamCipher(ci)

	k, ok := key.(*externalPrivateKey)
	if !ok {
		return errors.New(" key is not native key")
	}

	vcontents := ToVirgilByteArray(k.contents())
	defer DeleteVirgilByteArray(vcontents)

	vrec := ToVirgilByteArray(k.receiverID)
	defer DeleteVirgilByteArray(vrec)

	ci.DecryptWithKey(s, d, vrec, vcontents)

	return
}

func (c *ExternalCrypto) Sign(data []byte, signer cryptoapi.PrivateKey) (_ []byte, err error) {
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
	defer DeleteVirgilSigner(s)
	k, ok := signer.(*externalPrivateKey)
	if !ok {
		return nil, errors.New("wrong private key type")
	}

	vdata := ToVirgilByteArray(data)
	defer DeleteVirgilByteArray(vdata)
	vkey := ToVirgilByteArray(k.key)
	defer DeleteVirgilByteArray(vkey)
	vsign := s.Sign(vdata, vkey)
	defer DeleteVirgilByteArray(vsign)

	signature := ToSlice(vsign)
	return signature, nil
}

func (c *ExternalCrypto) SignHash(hash []byte, signer cryptoapi.PrivateKey) (_ []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			var ok bool
			err, ok = r.(error)
			if !ok {
				err = fmt.Errorf("pkg: %v", r)
			}
		}
	}()

	s := NewVirgilSignerBase(VirgilHashAlgorithm_SHA256)
	defer DeleteVirgilSignerBase(s)
	k, ok := signer.(*externalPrivateKey)
	if !ok {
		return nil, errors.New("wrong private key type")
	}

	vdata := ToVirgilByteArray(hash)
	defer DeleteVirgilByteArray(vdata)
	vkey := ToVirgilByteArray(k.key)
	defer DeleteVirgilByteArray(vkey)
	vsign := s.SignHash(vdata, vkey)
	defer DeleteVirgilByteArray(vsign)

	signature := ToSlice(vsign)
	return signature, nil
}

func (c *ExternalCrypto) VerifySignature(data []byte, signature []byte, key cryptoapi.PublicKey) (err error) {
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
	defer DeleteVirgilSigner(s)

	vdata := ToVirgilByteArray(data)
	defer DeleteVirgilByteArray(vdata)
	vsignature := ToVirgilByteArray(signature)
	defer DeleteVirgilByteArray(vsignature)
	vcontents := ToVirgilByteArray(key.(*externalPublicKey).contents())
	defer DeleteVirgilByteArray(vcontents)

	valid := s.Verify(vdata, vsignature, vcontents)

	if !valid {
		return cryptonative.CryptoError("invalid signature")
	}

	return nil
}

func (c *ExternalCrypto) VerifyHash(hash []byte, signature []byte, key cryptoapi.PublicKey) (_ bool, err error) {
	defer func() {
		if r := recover(); r != nil {
			var ok bool
			err, ok = r.(error)
			if !ok {
				err = fmt.Errorf("pkg: %v", r)
			}
		}
	}()
	s := NewVirgilSignerBase(VirgilHashAlgorithm_SHA256)
	defer DeleteVirgilSignerBase(s)

	vdata := ToVirgilByteArray(hash)
	defer DeleteVirgilByteArray(vdata)
	vsignature := ToVirgilByteArray(signature)
	defer DeleteVirgilByteArray(vsignature)
	vcontents := ToVirgilByteArray(key.(*externalPublicKey).contents())
	defer DeleteVirgilByteArray(vcontents)

	valid := s.VerifyHash(vdata, vsignature, vcontents)
	return valid, nil
}

func (c *ExternalCrypto) SignStream(in io.Reader, signerKey cryptoapi.PrivateKey) (_ []byte, err error) {

	defer func() {
		if r := recover(); r != nil {
			var ok bool
			err, ok = r.(error)
			if !ok {
				err = fmt.Errorf("pkg: %v", r)
			}
		}
	}()

	signer := NewVirgilStreamSigner()
	defer DeleteVirgilStreamSigner(signer)

	s := NewDirectorVirgilDataSource(NewDataSource(in))
	defer DeleteDirectorVirgilDataSource(s)

	vcontents := ToVirgilByteArray(signerKey.(*externalPrivateKey).contents())
	defer DeleteVirgilByteArray(vcontents)

	vsign := signer.Sign(s, vcontents)
	defer DeleteVirgilByteArray(vsign)

	return ToSlice(vsign), nil
}

func (c *ExternalCrypto) VerifyStream(in io.Reader, signature []byte, key cryptoapi.PublicKey) (res bool, err error) {

	defer func() {
		if r := recover(); r != nil {
			var ok bool
			err, ok = r.(error)
			if !ok {
				err = fmt.Errorf("pkg: %v", r)
			}
		}
	}()

	signer := NewVirgilStreamSigner()
	defer DeleteVirgilStreamSigner(signer)

	s := NewDirectorVirgilDataSource(NewDataSource(in))
	defer DeleteDirectorVirgilDataSource(s)

	vsign := ToVirgilByteArray(signature)
	defer DeleteVirgilByteArray(vsign)

	vcontents := ToVirgilByteArray(key.(*externalPublicKey).contents())
	defer DeleteVirgilByteArray(vcontents)

	res = signer.Verify(s, vsign, vcontents)

	return res, nil
}
func (c *ExternalCrypto) CalculateFingerprint(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

func (c *ExternalCrypto) SignThenEncrypt(data []byte, signerKey cryptoapi.PrivateKey, recipients ...cryptoapi.PublicKey) (_ []byte, err error) {
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
	defer DeleteVirgilCipher(ci)
	params := ci.CustomParams().(VirgilCustomParams)

	k, ok := signerKey.(*externalPrivateKey)
	if !ok {
		return nil, errors.New("wrong private key type")
	}

	signature, err := c.Sign(data, k)
	if err != nil {
		return nil, err
	}
	vsigKey := ToVirgilByteArray([]byte(signatureKey))
	defer DeleteVirgilByteArray(vsigKey)

	vsig := ToVirgilByteArray(signature)
	defer DeleteVirgilByteArray(vsig)
	params.SetString(vsigKey, vsig)

	vsignerKey := ToVirgilByteArray([]byte(signerId))
	defer DeleteVirgilByteArray(vsignerKey)
	vsigner := ToVirgilByteArray(k.ReceiverID())
	defer DeleteVirgilByteArray(vsigner)
	params.SetString(vsignerKey, vsigner)

	for _, r := range recipients {

		rKey, ok := r.(*externalPublicKey)
		if !ok {
			return nil, errors.New("wrong public key type")
		}

		vrec := ToVirgilByteArray(rKey.ReceiverID())
		defer DeleteVirgilByteArray(vrec)
		vconts := ToVirgilByteArray(r.(*externalPublicKey).contents())
		defer DeleteVirgilByteArray(vconts)
		ci.AddKeyRecipient(vrec, vconts)
	}

	vdata := ToVirgilByteArray(data)
	defer DeleteVirgilByteArray(vdata)
	venc := ci.Encrypt(vdata, true)
	defer DeleteVirgilByteArray(venc)
	ct := ToSlice(venc)

	return ct, nil
}

func (c *ExternalCrypto) DecryptThenVerify(data []byte, decryptionKey cryptoapi.PrivateKey, verifierKeys ...cryptoapi.PublicKey) (_ []byte, err error) {
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
	defer DeleteVirgilCipher(ci)

	k, ok := decryptionKey.(*externalPrivateKey)
	if !ok {
		return nil, errors.New("wrong private key type")
	}

	vdata := ToVirgilByteArray(data)
	defer DeleteVirgilByteArray(vdata)
	vrec := ToVirgilByteArray(k.ReceiverID())
	defer DeleteVirgilByteArray(vrec)
	vkey := ToVirgilByteArray(k.key)
	defer DeleteVirgilByteArray(vkey)
	vpt := ci.DecryptWithKey(vdata, vrec, vkey)
	defer DeleteVirgilByteArray(vpt)

	plaintext := ToSlice(vpt)

	vsigKey := ToVirgilByteArray([]byte(signatureKey))
	defer DeleteVirgilByteArray(vsigKey)
	sigString := ci.CustomParams().(VirgilCustomParams).GetString(vsigKey)
	defer DeleteVirgilByteArray(sigString)

	sig := ToSlice(sigString)

	if len(verifierKeys) == 1 {
		err := c.VerifySignature(plaintext, sig, verifierKeys[0])
		if err != nil {
			return nil, err
		}

	} else {
		vsignerIdKey := ToVirgilByteArray([]byte(signerId))
		defer DeleteVirgilByteArray(vsignerIdKey)
		signerIdString := ci.CustomParams().(VirgilCustomParams).GetString(vsignerIdKey)
		defer DeleteVirgilByteArray(signerIdString)

		signerIdValue := ToSlice(signerIdString)

		for _, v := range verifierKeys {
			vk, ok := v.(*externalPublicKey)
			if !ok {
				return nil, errors.New("wrong public key type")
			}

			if subtle.ConstantTimeCompare(vk.ReceiverID(), signerIdValue) == 1 {
				err := c.VerifySignature(plaintext, sig, v)
				if err != nil {
					return nil, err
				}
				return plaintext, nil
			}
		}
		return nil, cryptonative.CryptoError("Could not verify signature with provided keys")

	}

	return plaintext, nil
}

func (c *ExternalCrypto) ExtractPublicKey(key cryptoapi.PrivateKey) (_ cryptoapi.PublicKey, err error) {
	defer func() {
		if r := recover(); r != nil {
			var ok bool
			err, ok = r.(error)
			if !ok {
				err = fmt.Errorf("pkg: %v", r)
			}
		}
	}()

	k, ok := key.(*externalPrivateKey)
	if !ok {
		return nil, errors.New("the key is not native private key")
	}
	return k.ExtractPublicKey()

}

//ToSlice converts VirgilByteArray to a go slice
func ToSlice(b VirgilByteArray) []byte {
	l := int(b.Size())
	res := make([]byte, l)
	for i := 0; i < l; i++ {
		res[i] = b.Get(i)
	}
	return res
}

//ToVirgilByteArray converts go slice to a VirgilByteArray
func ToVirgilByteArray(data []byte) VirgilByteArray {
	l := len(data)
	b := NewVirgilByteArray(uint(len(data)))
	for i := 0; i < l; i++ {
		b.Set(i, data[i])
	}
	return b
}
