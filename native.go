package virgil_crypto_go

import (
	"io"
	"crypto/sha256"
	"github.com/pkg/errors"
	"fmt"
	"gopkg.in/virgil.v4/virgilcrypto"
)

type NativeCrypto struct {

}

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
	defer  DeleteVirgilKeyPair(kp)

	der := VirgilKeyPairPublicKeyToDER(kp.PublicKey())
	defer DeleteVirgilByteArray(der)

	rawPub := ToSlice(der)
	receiverId := c.CalculateFingerprint(rawPub)

	pub := &nativePublicKey{
		key:rawPub,
		receiverID:receiverId,
	}


	der1 := VirgilKeyPairPrivateKeyToDER(kp.PrivateKey())
	defer DeleteVirgilByteArray(der1)
	rawPriv := ToSlice(der1)

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

	unwrappedKey := unwrapKey(data)
	if(password == ""){
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

	vdata := ToVirgilByteArray(unwrapKey(data))
	defer DeleteVirgilByteArray(vdata)
	vder := VirgilKeyPairPublicKeyToDER(vdata)
	defer DeleteVirgilByteArray(vder)
	rawPub := ToSlice(vder)
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
	defer DeleteVirgilCipher(ci)

	for _,r := range recipients{
		vrec :=ToVirgilByteArray(r.ReceiverID())
		defer DeleteVirgilByteArray(vrec)
		vcon := ToVirgilByteArray(r.Contents())
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

func (c *NativeCrypto) EncryptStream(in io.Reader, out io.Writer, recipients ...virgilcrypto.PublicKey) ( err error) {
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

	for _,r := range recipients{
		vrec := ToVirgilByteArray(r.ReceiverID())
		defer DeleteVirgilByteArray(vrec)

		vcon := ToVirgilByteArray(r.Contents())
		defer DeleteVirgilByteArray(vcon)
		ci.AddKeyRecipient(vrec, vcon)

	}


	ci.Encrypt(s, d)

  	return

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
	defer DeleteVirgilCipher(ci)

	k, ok := key.(*nativePrivateKey)
	if !ok{
		return
	}

	vdata := ToVirgilByteArray(data)
	defer DeleteVirgilByteArray(vdata)
	vrec := ToVirgilByteArray(key.ReceiverID())
	defer DeleteVirgilByteArray(vrec)
	vcontents := ToVirgilByteArray(k.Contents())
	defer DeleteVirgilByteArray(vcontents)

	vplain := ci.DecryptWithKey(vdata, vrec, vcontents)
	defer  DeleteVirgilByteArray(vplain)
	plainText := ToSlice(vplain)
	return plainText, nil
}

func (c *NativeCrypto) DecryptStream(in io.Reader, out io.Writer, key virgilcrypto.PrivateKey) (err error) {
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

	k, ok := key.(*nativePrivateKey)
	if !ok{
		return errors.New(" key is not native key")
	}

	vcontents := ToVirgilByteArray(k.Contents())
	defer DeleteVirgilByteArray(vcontents)

	vrec := ToVirgilByteArray(k.receiverID)
	defer DeleteVirgilByteArray(vrec)

	ci.DecryptWithKey(s, d, vrec, vcontents)

	return
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
	defer DeleteVirgilSigner(s)
	k, ok := signer.(*nativePrivateKey)
	if !ok{
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
	defer DeleteVirgilSigner(s)

	vdata := ToVirgilByteArray(data)
	defer DeleteVirgilByteArray(vdata)
	vsignature := ToVirgilByteArray(signature)
	defer DeleteVirgilByteArray(vsignature)
	vcontents := ToVirgilByteArray(key.Contents())
	defer DeleteVirgilByteArray(vcontents)

	valid := s.Verify(vdata, vsignature, vcontents)
	return valid, nil
}

func (c *NativeCrypto) SignStream(in io.Reader, signerKey virgilcrypto.PrivateKey) (_ []byte, err error) {

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

	vcontents := ToVirgilByteArray(signerKey.Contents())
	defer DeleteVirgilByteArray(vcontents)

	vsign := signer.Sign(s, vcontents)
	defer DeleteVirgilByteArray(vsign)

	return ToSlice(vsign), nil
}

func (c *NativeCrypto) VerifyStream(in io.Reader, signature []byte, key virgilcrypto.PublicKey) (res bool, err error) {

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


	vcontents := ToVirgilByteArray(key.Contents())
	defer DeleteVirgilByteArray(vcontents)

	res = signer.Verify(s, vsign, vcontents)

	return res, nil
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
	defer DeleteVirgilCipher(ci)
	params := ci.CustomParams().(VirgilCustomParams)

	signature, err := c.Sign(data, signerKey)
	if(err != nil){
		return nil, err
	}
	vsigKey := ToVirgilByteArray([]byte(signatureKey))
	defer DeleteVirgilByteArray(vsigKey)

	vsig := ToVirgilByteArray(signature)
	defer DeleteVirgilByteArray(vsig)
	params.SetString(vsigKey, vsig)

	for _,r := range recipients{
		vrec := ToVirgilByteArray(r.ReceiverID())
		defer DeleteVirgilByteArray(vrec)
		vconts := ToVirgilByteArray(r.Contents())
		defer DeleteVirgilByteArray(vconts)
		ci.AddKeyRecipient(vrec, vconts)
	}

	vdata := ToVirgilByteArray(data)
	defer DeleteVirgilByteArray(vdata)
	venc :=ci.Encrypt(vdata, true)
	defer DeleteVirgilByteArray(venc)
	ct := ToSlice(venc)

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
	defer DeleteVirgilCipher(ci)

	vdata := ToVirgilByteArray(data)
	defer DeleteVirgilByteArray(vdata)
	vrec := ToVirgilByteArray(decryptionKey.ReceiverID())
	defer DeleteVirgilByteArray(vrec)
	vkey := ToVirgilByteArray(decryptionKey.(*nativePrivateKey).key)
	defer DeleteVirgilByteArray(vkey)
	vpt := ci.DecryptWithKey(vdata, vrec, vkey)
	defer DeleteVirgilByteArray(vpt)

	pt := ToSlice(vpt)
	vsigKey := ToVirgilByteArray([]byte(signatureKey))
	defer DeleteVirgilByteArray(vsigKey)
	sig := ToSlice(ci.CustomParams().(VirgilCustomParams).GetString(vsigKey))

	valid, err := c.Verify(pt, sig, verifierKey)
	if(!valid){
		return nil, err
	}
	return pt, nil
}

func (c *NativeCrypto) ExtractPublicKey(key virgilcrypto.PrivateKey) (_ virgilcrypto.PublicKey, err error){
	defer func() {
		if r := recover(); r != nil {
			var ok bool
			err, ok = r.(error)
			if !ok {
				err = fmt.Errorf("pkg: %v", r)
			}
		}
	}()

	k, ok := key.(*nativePrivateKey)
	if !ok{
		return nil, errors.New("the key is not native private key")
	}
	return k.ExtractPublicKey()

}

//ToSlice converts VirgilByteArray to a go slice
func ToSlice(b VirgilByteArray) []byte{
	l := int(b.Size())
	res := make([]byte, l)
	for i:= 0; i < l; i++{
		res[i] = b.Get(i)
	}
	return res
}

//ToVirgilByteArray converts go slice to a VirgilByteArray
func ToVirgilByteArray(data []byte) VirgilByteArray{
	l := len(data)
	b := NewVirgilByteArray(uint(len(data)))
	for i:= 0; i < l; i++{
		b.Set(i, data[i])
	}
	return b
}
