package virgil_crypto_go

import (
	"testing"
	"bytes"
	"crypto/rand"
)

func TestSignEncrypt(t *testing.T) {
	crypto := &NativeCrypto{}

	//make random data
	data := make([]byte, 257)
	rand.Read(data)

	keypair, err := crypto.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	signerKeypair, err := crypto.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	cipherText, err := crypto.SignThenEncrypt(data, signerKeypair.PrivateKey(), keypair.PublicKey())
	if err != nil {
		t.Fatal(err)
	}

	if plaintext, err := crypto.DecryptThenVerify(cipherText, keypair.PrivateKey(), keypair.PublicKey(), signerKeypair.PublicKey()); err != nil || !bytes.Equal(plaintext, data) {
		t.Fatal(err)
	}

}

func BenchmarkSignThenEncrypt(b *testing.B){

	crypto := &NativeCrypto{}

	//make random data
	data := make([]byte, 257)
	rand.Read(data)

	keypair, err := crypto.GenerateKeypair()
	if err != nil {
		b.Fatal(err)
	}

	signerKeypair, err := crypto.GenerateKeypair()
	if err != nil {
		b.Fatal(err)
	}


	for i := 0; i< b.N; i++{
		cipherText, err := crypto.SignThenEncrypt(data, signerKeypair.PrivateKey(), keypair.PublicKey())
		if err != nil {
			b.Fatal(err)
		}
		if plaintext, err := crypto.DecryptThenVerify(cipherText, keypair.PrivateKey(), signerKeypair.PublicKey()); err != nil || !bytes.Equal(plaintext, data) {
			b.Fatal(err)
		}
	}

}


func TestStreamCipher(t *testing.T) {
	crypto := &NativeCrypto{}
	keypair, err := crypto.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	plainBuf := make([]byte, 102301)
	rand.Read(plainBuf)
	plain := bytes.NewBuffer(plainBuf)
	cipheredStream := &bytes.Buffer{}
	err = crypto.EncryptStream(plain, cipheredStream, keypair.PublicKey())
	if err != nil {
		t.Fatal(err)
	}

	//decrypt with key

	cipheredInputStream := bytes.NewBuffer(cipheredStream.Bytes())
	plainOutBuffer := &bytes.Buffer{}
	err = crypto.DecryptStream(cipheredInputStream, plainOutBuffer, keypair.PrivateKey())
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(plainBuf, plainOutBuffer.Bytes()) {
		t.Fatal("plain & decrypted buffers do not match")
	}

	//decrypt with wrong id must fail

	cipheredInputStream = bytes.NewBuffer(cipheredStream.Bytes())
	plainOutBuffer = &bytes.Buffer{}

	keypair, err = crypto.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	err = crypto.DecryptStream(cipheredInputStream, plainOutBuffer, keypair.PrivateKey())
	if err == nil {
		t.Fatal("decrypt must fail but didn't")
	}

	//decrypt with wrong key must fail
	keypair1, err := crypto.GenerateKeypair()

	if err != nil {
		t.Fatal(err)
	}
	cipheredInputStream = bytes.NewBuffer(cipheredStream.Bytes())
	plainOutBuffer = &bytes.Buffer{}
	err = crypto.DecryptStream(cipheredInputStream, plainOutBuffer, keypair1.PrivateKey())
	if err == nil {
		t.Fatal("decrypt must fail but didn't")
	}

}


func TestStreamSigner(t *testing.T) {
	crypto := &NativeCrypto{}
	keypair, err := crypto.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	plainBuf := make([]byte, 1023)
	rand.Read(plainBuf)
	plain := bytes.NewBuffer(plainBuf)
	sign, err := crypto.SignStream(plain, keypair.PrivateKey())
	if err != nil {
		t.Fatal(err)
	}

	//verify signature

	plain = bytes.NewBuffer(plainBuf)

	res, err := crypto.VerifyStream(plain,sign, keypair.PublicKey())
	if err != nil {
		t.Fatal(err)
	}

	if !res {
		t.Fatal("verify result is ok but err is nil")
	}

	//verify with wrong signature must fail

	plain = bytes.NewBuffer(plainBuf)


	sign[len(sign)-1] = ^sign[len(sign)-1]//invert last byte

	res, err = crypto.VerifyStream(plain, sign, keypair.PublicKey())
	if res {
		t.Fatal("verify must fail but didn't")
	}

	sign[len(sign)-1] = ^sign[len(sign)-1] //restore last byte
	//verify with wrong key must fail
	keypair, err = crypto.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	res, err = crypto.VerifyStream(plain, sign, keypair.PublicKey())
	if res {
		t.Fatal("verify must fail but didn't")
	}

}

func TestNativeCrypto_ExportImportPrivateKey(t *testing.T) {
	crypto := &NativeCrypto{}
	keypair, err := crypto.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	pubb, err := crypto.ExportPublicKey(keypair.PublicKey())
	if err != nil {
		t.Fatal(err)
	}

	privb, err := crypto.ExportPrivateKey(keypair.PrivateKey(), "abc")
	if err != nil {
		t.Fatal(err)
	}

	pub, err := crypto.ImportPublicKey(pubb)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := crypto.ImportPrivateKey(privb, "abc")
	if err != nil {
		t.Fatal(err)
	}

	data := make([]byte, 257)
	rand.Read(data)

	cipherText, err := crypto.SignThenEncrypt(data, keypair.PrivateKey(), keypair.PublicKey())
	if err != nil {
		t.Fatal(err)
	}

	if plaintext, err := crypto.DecryptThenVerify(cipherText, priv, pub, pub); err != nil || !bytes.Equal(plaintext, data) {
		t.Fatal(err)
	}

}