# Makefile for ML-DSA-44-SM2 Provider

CC = gcc
CFLAGS = -fPIC -Wall -Wextra -O2 -g
INCLUDES = -I/home/wang/Desktop/Tongsuo/include \
           -I/home/wang/Desktop/x509-hybrid-spki-provider/include
LIBS = -L/home/wang/Desktop/Tongsuo -L/usr/local/lib/lib64 \
       -lcrypto -lssl
LDFLAGS = -shared -Wl,-soname,libml_dsa_sm2_provider.so

SRCDIR = src
INCDIR = include
OBJDIR = obj

SOURCES = $(SRCDIR)/ml_dsa_sm2_ameth.c \
          $(SRCDIR)/ml_kem512_sm2_ameth.c \
          $(SRCDIR)/ml_dsa_sm2_provider.c
OBJECTS = $(SOURCES:$(SRCDIR)/%.c=$(OBJDIR)/%.o)

TARGET = libml_dsa_sm2_provider.so

.PHONY: all clean install

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(OBJDIR):
	mkdir -p $(OBJDIR)

clean:
	rm -rf $(OBJDIR) $(TARGET)

install: $(TARGET)
	cp $(TARGET) /usr/local/lib/
	ldconfig
