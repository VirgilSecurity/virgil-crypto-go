# virgil-crypto-go
Crypto implementation which uses wrapper for c++ crypto library

##Usage

* Place generated virgil_crypto_go.go and all dependencies in this folder
* In your code import github.com/VirgilSecurity/virgil-crypto-go
```go
import (
	"gopkg.in/virgilsecurity/virgil-sdk-go.v4"
	"gopkg.in/virgilsecurity/virgil-sdk-go.v4/virgilcrypto"
 
	crypto "gopkg.in/virgilsecurity/virgil-crypto-go"

)
```
* Replace the default crypto in virgil SDK like this:
```go
  virgilcrypto.DefaultCrypto = &crypto.NativeCrypto{}
```
