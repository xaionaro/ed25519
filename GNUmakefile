
CC= gcc
CFLAGS= -Wall -Wextra -O3 -fwrapv -fPIC
LDFLAGS=
ifeq ($(CC),gcc)
LDFLAGS+= -flto=8 -Wl,--gc-sections
CFLAGS+= -fdata-sections -ffunction-sections
endif

TARGETS=\
	ed25519\
	ed25519.a\
	ed25519.so

LIB_SRCS=$(wildcard src/*.c)
LIB_OBJS=$(patsubst %.c,%.o,$(LIB_SRCS))

all: ed25519

clean:
	-rm -f $(TARGETS) $(LIB_OBJS)

test: $(TARGETS)
	bash ed25519_tests

ed25519: $(LIB_OBJS)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) $(TARGET_ARCH) -o ed25519 main.c $(LIB_OBJS)

ed25519.so: $(LIB_OBJS)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) $(TARGET_ARCH) -fPIC -shared -o ed25519.so $(LIB_OBJS)

ed25519.a: $(LIB_OBJS)
	ar rcs ed25519.a $(LIB_OBJS)

%.o: %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) $(TARGET_ARCH) -fPIC -c -o $@ $^
