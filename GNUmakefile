
CC= gcc
CFLAGS= -Wall -Wextra -O3 -fwrapv $(FLTO)
ifeq ($(CC),gcc)
FLTO ?= -flto=8
endif

TARGET=ed25519

all: $(TARGET)

clean:
	-rm -f $(TARGET)

test: $(TARGET)
	bash ed25519_tests

$(TARGET): src/*.c

%: %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) $(TARGET_ARCH) -o $@ $^
