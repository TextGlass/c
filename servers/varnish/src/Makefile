#VARNISH_PREFIX=/usr
VARNISH_PREFIX=/opt/varnish/varnish-4.1.0
TEXTGLASS_PREFIX=../../../src

CC=gcc
CFLAGS=-O3 -Wall -g -fPIC
TGFLAGS=$(CFLAGS) -D_TEXTGLASS_SKIP_ASSERT -I$(TEXTGLASS_PREFIX) -I$(TEXTGLASS_PREFIX)/data -I$(TEXTGLASS_PREFIX)/jsmn
VCFLAGS=$(TGFLAGS) -I$(VARNISH_PREFIX)/include/varnish
LDFLAGS=-shared
LIBFLAGS=
LIBTEXTGLASS=$(TEXTGLASS_PREFIX)/libtextglass.a
VMODPY=$(VARNISH_PREFIX)/share/varnish/vmodtool.py
PYTHON=python
RM=rm -f

.PHONY: clean all

all:			libvmod_textglass.so

libvmod_textglass.so:	vcc_if.o vmod_textglass.o $(LIBTEXTGLASS)
			$(CC) $(LDFLAGS) -o libvmod_textglass.so vcc_if.o vmod_textglass.o $(LIBTEXTGLASS) $(LIBFLAGS)

vcc_if.o:		vcc_if.c vcc_if.h
			$(CC) $(VCFLAGS) -c vcc_if.c -o vcc_if.o

vmod_textglass.o:	vmod_textglass.c
			$(CC) $(VCFLAGS) -c vmod_textglass.c -o vmod_textglass.o

vcc_if.%:		vmod_textglass.vcc
			$(PYTHON) $(VMODPY) vmod_textglass.vcc

$(LIBTEXTGLASS):
			$(MAKE) -C $(TEXTGLASS_PREFIX) libtextglass.a
clean:
			$(RM) *.o vcc_if.c vcc_if.h *.so *.rst
