LIBS = -lgpgme
SRC = main.c
OBJ = ${SRC:.c=.o}
CFLAGS = -pedantic -Wall -Os -march=native -O3 -pipe -fno-plt -fexceptions \
         -Wp,-D_FORTIFY_SOURCE=3 -Wformat -Werror=format-security \
         -fstack-clash-protection -fcf-protection
LDFLAGS = -Wl,-O1 -Wl,--sort-common -Wl,--as-needed -Wl,-z,relro -Wl,-z,now \
          -Wl,-z,pack-relative-relocs

all: build

build: ${OBJ}
	gcc ${LIBS} ${OBJ} -o vsrfdi ${CFLAGS} ${LDFLAGS}

main.o: ${SRC}
	gcc -c main.c -o main.o ${CFLAGS}

clean:
	rm -f ${OBJ} vsrfdi
	