CC     = gcc
CFLAGS = -O2 -Wall -Wextra -fPIE -pie
TARGET = dntry

all: $(TARGET) demo bebop

$(TARGET): dntry.c
	$(CC) $(CFLAGS) -o $@ $<

https: dntry.c
	$(CC) $(CFLAGS) -DUSE_HTTPS -o $(TARGET) $< -lssl -lcrypto

demo: demo.c
	$(CC) -O2 -static -o $@ $<

bebop: bebop.c
	$(CC) -static -nostdlib -mno-sse -o $@ $<

clean:
	rm -f $(TARGET) demo bebop
