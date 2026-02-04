# Nell Agent Makefile
# Cross-compile for Windows using MinGW-w64

# Compiler
CC = x86_64-w64-mingw32-gcc
CC32 = i686-w64-mingw32-gcc

# Flags
CFLAGS = -Wall -O2
LDFLAGS = -lwinhttp -liphlpapi -lnetapi32 -lws2_32

# Debug flags
DEBUG_CFLAGS = -Wall -g -DDEBUG_BUILD

# Sources
SRCS = nell.c Package.c Parser.c Transport.c Utils.c Checkin.c Command.c
OBJS = $(SRCS:.c=.o)

# Output
TARGET = nell.exe
TARGET32 = nell32.exe

# Default: 64-bit release
all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $(SRCS) $(LDFLAGS)
	@echo "[+] Built $(TARGET) (x64)"

# 32-bit build
x86: $(SRCS)
	$(CC32) $(CFLAGS) -o $(TARGET32) $(SRCS) $(LDFLAGS)
	@echo "[+] Built $(TARGET32) (x86)"

# Debug build (with console)
debug: $(SRCS)
	$(CC) $(DEBUG_CFLAGS) -o nell_debug.exe $(SRCS) $(LDFLAGS) -mconsole
	@echo "[+] Built nell_debug.exe (debug)"

# Clean
clean:
	rm -f $(TARGET) $(TARGET32) nell_debug.exe *.o

# Install mingw-w64 if needed
install-deps:
	@echo "Install with: sudo apt install mingw-w64"

.PHONY: all x86 debug clean install-deps
