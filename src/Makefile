CC=gcc
CFLAGS=-O3 -Wall -fPIC
LDFLAGS=
LIBFLAGS=-lpthread
RM=rm -f

INCLUDES=tree.h queue.h tg_list.h tg_hashtable.h
OBJS=tg_hashtable.o tg_list.o

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
			$(RM) *.o *.so *.a textglass_client
