package virgil_crypto_go

import (
	"testing"

	"crypto/rand"

	"github.com/stretchr/testify/assert"
	"gopkg.in/virgil.v5/cryptoimpl"
)

func TestCrossTestCrypto(t *testing.T) {

	c1 := &cryptoimpl.VirgilCrypto{}
	c2 := &ExternalCrypto{}

	kp1, err := c1.GenerateKeypair()
	assert.NoError(t, err)

	kp2, err := c2.GenerateKeypair()
	assert.NoError(t, err)

	data := make([]byte, 257)
	rand.Read(data)

	kp2p, err := c2.ExportPublicKey(kp2.PublicKey())
	assert.NoError(t, err)

	kp2pub, err := c1.ImportPublicKey(kp2p)
	assert.NoError(t, err)

	ciphertext, err := c1.SignThenEncrypt(data, kp1.PrivateKey(), kp2pub)
	assert.NoError(t, err)

	kp1p, err := c1.ExportPublicKey(kp1.PublicKey())
	assert.NoError(t, err)

	kp1pub, err := c2.ImportPublicKey(kp1p)
	assert.NoError(t, err)

	decrypted, err := c2.DecryptThenVerify(ciphertext, kp2.PrivateKey(), kp1pub)
	assert.NoError(t, err)
	assert.Equal(t, decrypted, data)

}
