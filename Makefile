
TARGET= ed25519
FLTO=-flto=8
CFLAGS=-Wall -Wextra -O3 -fwrapv $(FLTO) $(DEFS)
CC=gcc
AR=gcc-ar

LOBJECTS := $(patsubst %.c,%.o,$(wildcard src/*.c))

$(TARGET): test.c ed25519.a
	$(CC) $(TARGET_ARCH) $(CFLAGS) $(LDFLAGS) -o $@ test.c ed25519.a $(LIBS)

ed25519.a: ed25519.a($(LOBJECTS))
	touch $@

ed25519.a($(LOBJECTS)):  $(wildcard src/*.h)

$(TARGET): license.h

license.h: license.txt
	echo '#define LICENSE \' > license.h.tmp
	sed 's/.*/"&\\n" \\/' < license.txt >> license.h.tmp
	echo >> license.h.tmp
	mv license.h.tmp license.h

clean:
	-rm -f ${TARGET} license.h ed25519.a

test:	$(TARGET)
	set -x					;\
	S=$$(./$(TARGET) -r)			&&\
	P=$$(./$(TARGET) -k $$S)		&&\
	V=$$(./$(TARGET) -hs $$S Makefile)	&&\
	./$(TARGET) -hvp $$V $$P Makefile	&&\
	V=$$(./$(TARGET) -s$$S Makefile)	&&\
	./$(TARGET) -v$$V -p$$P Makefile	&&\
	./$(TARGET) -t

