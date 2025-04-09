ifeq ($(OS),Windows_NT)
    CC = gcc
    CFLAGS = -Wall -Wextra -O2
    LIBS = -lws2_32 -lbcrypt
    RM = del /Q /F
    EXT = .exe
else
    CC = gcc
    CFLAGS = -Wall -Wextra -O2
    LIBS = -lpthread
    RM = rm -f
    EXT =
endif

COMMON_SRC = monocypher.c siete.c crypto_utils.c platform.c
SERVER_SRC = server.c $(COMMON_SRC)
CLIENT_SRC = client.c $(COMMON_SRC)

HEADERS = monocypher.h siete.h crypto_utils.h constants.h platform.h errors.h

SERVER = server$(EXT)
CLIENT = client$(EXT)

all: $(SERVER) $(CLIENT)

$(SERVER): $(SERVER_SRC) $(HEADERS)
	$(CC) $(CFLAGS) -o $@ $(SERVER_SRC) $(LIBS)

$(CLIENT): $(CLIENT_SRC) $(HEADERS)
	$(CC) $(CFLAGS) -o $@ $(CLIENT_SRC) $(LIBS)

clean:
	$(RM) $(SERVER) $(CLIENT)

help:
	@echo "Available targets:"
	@echo "  all      - Build both server and client (default)"
	@echo "  server   - Build only server"
	@echo "  client   - Build only client"
	@echo "  clean    - Remove compiled files"
	@echo "  help     - Show this help message"

.PHONY: all clean help