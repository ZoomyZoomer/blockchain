CC = gcc
CFLAGS = -g -lcrypto  # Ensure -lcrypto is here to link OpenSSL
LDFLAGS = -lcrypto  # Additional linking flags if necessary

# Your source files and targets
TARGETS = log checklog logserver

all: $(TARGETS)

log: log.c
	$(CC) $(CFLAGS) -o log log.c -lcrypto

checklog: checklog.c
	$(CC) $(CFLAGS) -o checklog checklog.c -lcrypto

logserver: logserver.c
	$(CC) $(CFLAGS) -o logserver logserver.c -lcrypto

clean:
	rm -f $(TARGETS)
