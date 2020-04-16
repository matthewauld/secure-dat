
.PHONY: all

CXXFLAGS := $(CXX11FLAGS)$(OS_CXXFLAGS) -pthread -Wall -g -O2 -DSSL_LIB_INIT -I${ZROOT}/deps/root/include -I${ZROOT}/root/include
LDFLAGS := -L${ZROOT}/deps/root/lib -L${ZROOT}/root/lib
LIBS := -lcrypto -lrelic -lrelic_ec -lopenabe

all: encrypt decrypt

encrypt: encrypt.o
	g++ -o encrypt $(CXXFLAGS) $(LDFLAGS) encrypt.cc $(LIBS)

decrypt: decrypt.o
	g++ -o decrypt $(CXXFLAGS) $(LDFLAGS) decrypt.cc $(LIBS)
clean:
	rm encrypt.o encrypt decrypt.o decrypt
