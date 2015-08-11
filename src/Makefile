#compile flags 
CC=gcc
CFLAGS=-O3 -Wall
LDFLAGS=
LIBFLAGS=
RM=rm -f

#targets
all:			textglass_client

textglass_client:	main.o
			$(CC) $(LDFLAGS) -o $@ main.o $(LIBFLAGS)

%.o:			%.c
			$(CC) $(CFLAGS) -c $< -o $@

clean:
			$(RM) *.o dclass_client
