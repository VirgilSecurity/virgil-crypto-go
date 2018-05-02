TEMPDIR := $(shell mktemp -d)
BRANCH ?=develop

all:
	git clone --branch=$(BRANCH) https://github.com/VirgilSecurity/virgil-crypto.git $(TEMPDIR)
	cd $(TEMPDIR); \
	cmake -H. -B_build -DCMAKE_INSTALL_PREFIX=_install -DLANG=go -DINSTALL_CORE_LIBS=ON -DVIRGIL_CRYPTO_FEATURE_PYTHIA=ON; \
	cmake --build _build --target install 
	cp -r $(TEMPDIR)/_install/* .
	rm -rf $(TEMPDIR)d
	mv ./lib/virgil_crypto_go.a ./lib/libvirgil_crypto_go.a

