CC      = gcc
CFLAGS  = -O2 -Wall -Wextra -static
TARGET  = dntry

all: $(TARGET) demo

$(TARGET): fileless_loader.c
	$(CC) $(CFLAGS) -o $@ $<

https: fileless_loader.c
	$(CC) -O2 -Wall -Wextra -DUSE_HTTPS -s -o $(TARGET) $< -lssl -lcrypto

demo: demo.c
	$(CC) -O2 -static -o $@ $<

clean:
	rm -f $(TARGET) demo
