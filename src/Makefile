LIBS = $(shell pkg-config --libs openssl)
SRC = main.c ask.c
OBJ = ${SRC:.c=.o}
CFLAGS = -pedantic -Wall -Os -march=native -O3 -pipe -fno-plt -fexceptions \
         -Wp,-D_FORTIFY_SOURCE=3 -Wformat -Werror=format-security \
         -fstack-clash-protection -fcf-protection -flto
LDFLAGS = -O3 -march=native -Wl,--sort-common,--as-needed,-z,relro,-z,now,-z,pack-relative-relocs -L/usr/lib

CC = clang
LINKER = clang -fuse-ld=lld 

all: build ask

build: main.o
	$(LINKER) main.o -o vsrfdi ${LDFLAGS} ${LIBS}

ask: ask.o
	$(LINKER) ask.o -o ask ${LDFLAGS}

main.o:
	$(CC) -c main.c -o main.o ${CFLAGS}

ask.o:
	$(CC) -c ask.c -o ask.o $(CFLAGS)

clean:
	rm -f ${OBJ} vsrfdi ask