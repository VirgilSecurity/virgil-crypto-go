TEMPDIR := $(shell mktemp -d)
BRANCH ?=v2.3.0

all:
	git clone --branch=$(BRANCH) https://github.com/VirgilSecurity/virgil-crypto.git $(TEMPDIR)
	cd $(TEMPDIR); \
	cmake -H. -B_build -DCMAKE_INSTALL_PREFIX=_install -DLANG=go -DINSTALL_CORE_LIBS=ON; \
	cmake --build _build --target install 
	cp -r $(TEMPDIR)/_install/* .
	rm -rf $(TEMPDIR)d

