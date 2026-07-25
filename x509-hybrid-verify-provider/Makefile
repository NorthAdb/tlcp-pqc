# x509-hybrid-verify-provider — PQC 证书链解析与混合验签

TONGSUO   ?= /home/wang/Desktop/Tongsuo
PQMAGIC   ?= /home/wang/Desktop/pqmagic/install

CC        = gcc
CFLAGS    = -fPIC -Wall -Wextra -O2 -g \
            -I$(TONGSUO)/include \
            -I$(TONGSUO) \
            -I$(PQMAGIC)/include \
            -Iinclude
LDFLAGS_SO = -shared -Wl,-soname,cert_verify.so
LIBS      = -L$(TONGSUO) -lcrypto

OBJDIR    = obj
OBJS_SO   = $(OBJDIR)/cert_verify.o $(OBJDIR)/cert_verify_prov.o \
            $(OBJDIR)/cert_verify_openssl.o

.PHONY: all clean test

all: cert_verify.so verify_certs_1

$(OBJDIR):
	mkdir -p $(OBJDIR) obj_tools

$(OBJDIR)/cert_verify.o: src/cert_verify.c include/cert_verify.h | $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJDIR)/cert_verify_prov.o: src/cert_verify_prov.c | $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJDIR)/cert_verify_openssl.o: src/cert_verify_openssl.c include/cert_verify.h | $(OBJDIR)
	$(CC) $(CFLAGS) -c src/cert_verify_openssl.c -o $@

cert_verify.so: $(OBJS_SO)
	$(CC) $(LDFLAGS_SO) -o $@ $(OBJS_SO) $(LIBS)

obj_tools/verify_certs_1.o: tools/verify_certs_1.c include/cert_verify.h | $(OBJDIR)
	$(CC) $(CFLAGS) -c tools/verify_certs_1.c -o $@

verify_certs_1: obj_tools/verify_certs_1.o $(OBJDIR)/cert_verify.o
	$(CC) -o $@ $^ $(LIBS)

PQMAGIC_MOD ?= $(PQMAGIC)/../pqmagic-algorithms-provider/build

test: verify_certs_1
	LD_LIBRARY_PATH=$(TONGSUO):$(PQMAGIC)/lib:$$LD_LIBRARY_PATH \
	OPENSSL_MODULES=$(PQMAGIC_MOD) \
	./verify_certs_1 /home/wang/Desktop/certs/3

test-openssl: cert_verify.so
	./scripts/openssl_verify.sh -CAfile /home/wang/Desktop/certs/3/root.crt \
		-untrusted /home/wang/Desktop/certs/3/yunying.crt \
		/home/wang/Desktop/certs/3/user_sig.crt

clean:
	rm -rf $(OBJDIR) obj_tools cert_verify.so verify_certs_1
