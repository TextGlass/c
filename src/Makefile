CC=gcc
CFLAGS=-O3 -Wall -g -fPIC
LDFLAGS=-shared
LIBFLAGS=
RM=rm -f

INCLUDES= \
	textglass.h \
	data/tree.h \
	data/queue.h \
	data/list.h \
	data/hashtable.h \
	jsmn/jsmn.h

SOURCE= \
	domain.c \
	pattern.c \
	classify.c \
	attribute.c \
	transformer.c \
	jsonfile.c \
	memalloc.c \
	util.c \
	data/hashtable.c \
	data/list.c \
	jsmn/jsmn.c

OBJS=$(SOURCE:.c=.o)

.PHONY: clean lib all

all:			textglass_client lib
lib:			libtextglass.so libtextglass.a

textglass_client:	libtextglass.a main.o
			$(CC) -o $@ main.o libtextglass.a $(LIBFLAGS)

libtextglass.so:	$(OBJS)
			$(CC) $(LDFLAGS) -o $@ $(OBJS)

libtextglass.a:		$(OBJS)
			ar cr $@ $(OBJS)

%.o:			%.c $(INCLUDES)
			$(CC) $(CFLAGS) -c $< -o $@

clean:
			$(RM) *.o data/*.o jsmn/*.o *.so *.a textglass_client
