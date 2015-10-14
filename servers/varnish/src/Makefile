CC=gcc
CFLAGS=-O3 -Wall -g -fPIC -D_TEXTGLASS_SKIP_ASSERT
LDFLAGS=
LIBFLAGS=
PYTHON=python
RM=rm -f

TG_PREFIX=../../../src
LIBTEXTGLASS=$(TG_PREFIX)/libtextglass.a
CFLAGS+=-I$(TG_PREFIX) -I$(TG_PREFIX)/data -I$(TG_PREFIX)/jsmn

#VPREFIX=/usr
VPREFIX=/opt/varnish/varnish-4.1.0
VCFLAGS=$(CFLAGS) -I$(VPREFIX)/include/varnish
VMODPY=$(VPREFIX)/share/varnish/vmodtool.py

.PHONY: clean all

all:			libvmod_textglass.so

libvmod_textglass.so:	vcc_if.o vmod_textglass.o $(LIBTEXTGLASS)
			$(CC) $(LDFLAGS) -shared -o libvmod_textglass.so vcc_if.o vmod_textglass.o $(LIBTEXTGLASS) $(LIBFLAGS)

vcc_if.o:		vcc_if.c vcc_if.h
			$(CC) $(VCFLAGS) -c vcc_if.c -o vcc_if.o

vmod_textglass.o:	vmod_textglass.c
			$(CC) $(VCFLAGS) -c vmod_textglass.c -o vmod_textglass.o

vcc_if.%:		vmod_textglass.vcc
			$(PYTHON) $(VMODPY) vmod_textglass.vcc

clean:
			$(RM) *.o vcc_if.c vcc_if.h *.so *.rst
