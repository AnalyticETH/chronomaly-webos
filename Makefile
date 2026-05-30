# Default target architecture (can override with: make ARCH=arm64)
ARCH ?= x86_64

ifeq ($(ARCH),arm64)
    CC = aarch64-linux-gnu-gcc
    TARGET = exploit-arm64
else ifeq ($(ARCH),arm)
    CC = arm-linux-gnueabihf-gcc
    TARGET = exploit-arm
else
    CC = gcc
    TARGET = exploit
endif

CFLAGS = -static -O2 -Wall
LDFLAGS = -lrt -lpthread

all:
	$(CC) $(CFLAGS) -o $(TARGET) getroot.c $(LDFLAGS)
	@echo "Built $(TARGET) for $(ARCH)"

arm64:
	$(MAKE) ARCH=arm64

arm:
	$(MAKE) ARCH=arm

webos: arm64
	@echo "WebOS build complete: exploit-arm64"
	@echo "Deploy to TV with: ./deploy-webos.sh"

clean:
	rm -f exploit exploit-arm64 exploit-arm