CC=gcc
CFLAGS=-O3 -Wall -g -fPIC -I. -Idata -Ijsmn
LDFLAGS=
LIBFLAGS=-lpthread
RM=rm -f

INCLUDES=textglass.h data/tree.h data/queue.h data/list.h data/hashtable.h jsmn/jsmn.h
OBJS=domain.o pattern.o classify.o json_file.o util.o data/hashtable.o data/list.o jsmn/jsmn.o

.PHONY: clean lib

all:			textglass_client lib
lib:			libtextglass.so libtextglass.a

textglass_client:	libtextglass.a main.o
			$(CC) $(LDFLAGS) -o $@ main.o libtextglass.a $(LIBFLAGS)

libtextglass.so:	$(OBJS)
			$(CC) $(LDFLAGS) -shared -o $@ $(OBJS)

libtextglass.a:		$(OBJS)
			ar cr $@ $(OBJS)

%.o:			%.c $(INCLUDES)
			$(CC) $(CFLAGS) -c $< -o $@

clean:
			$(RM) *.o data/*.o jsmn/*.o *.so *.a textglass_client
