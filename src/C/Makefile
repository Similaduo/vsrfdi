LIBS = $(shell pkg-config --libs openssl)
SRC = main.c
OBJ = ${SRC:.c=.o}
CFLAGS = -pedantic -Wall -Os -march=native -O3 -pipe -fno-plt -fexceptions \
         -Wp,-D_FORTIFY_SOURCE=3 -Wformat -Werror=format-security \
         -fstack-clash-protection -fcf-protection -flto
LDFLAGS = -O3 -march=native -Wl,--sort-common,--as-needed,-z,relro,-z,now,-z,pack-relative-relocs -L/usr/lib

CC = clang
LINKER = clang -fuse-ld=lld 

all: build

build: main.o
	$(LINKER) main.o -o vsrfdi ${LDFLAGS} ${LIBS}

main.o:
	$(CC) -c main.c -o main.o ${CFLAGS}

clean:
	rm -f ${OBJ} vsrfdi