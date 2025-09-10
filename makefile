# VPN Tunnel Remote Desktop Makefile
# Cross-platform build system for Windows and Linux

# Compiler settings
CXX ?= g++
CXXFLAGS = -std=c++17 -O2 -Wall

# Detect operating system (allow override with TARGET_OS)
ifeq ($(TARGET_OS),)
    ifeq ($(OS),Windows_NT)
        TARGET_OS := Windows
    else
        TARGET_OS := Linux
    endif
endif

ifeq ($(TARGET_OS),Windows)
    CLIENT_EXE = client.exe
    SERVER_EXE = server.exe
    CLIENT_LIBS = -lws2_32 -ld3d11 -ldxgi -lntdll -lgdi32 -luser32 -liphlpapi -static
    SERVER_LIBS = -lws2_32 -lgdi32 -luser32 -lcomctl32 -static
    DEFINES = -DWIN32_LEAN_AND_MEAN
    ifneq ($(OS),Windows_NT)
        CXX := x86_64-w64-mingw32-g++
    endif
else
    CLIENT_EXE = client
    SERVER_EXE = server
    CLIENT_LIBS = -pthread
    SERVER_LIBS = -pthread -lX11
    DEFINES =
endif

# Source files
CLIENT_SRC = client.cpp
SERVER_SRC = server.cpp

# Build targets
.PHONY: all clean client server info
.RECIPEPREFIX := >

all: info client server

info:
> @echo "=============================================="
> @echo "VPN Tunnel Remote Desktop Build System"
> @echo "=============================================="
> @echo "Target OS: $(TARGET_OS)"
> @echo "Compiler: $(CXX)"
> @echo "Flags: $(CXXFLAGS) $(DEFINES)"
> @echo ""

client: $(CLIENT_SRC)
> @echo "Building client for $(TARGET_OS)..."
> $(CXX) $(CXXFLAGS) $(DEFINES) $(CLIENT_SRC) -o $(CLIENT_EXE) $(CLIENT_LIBS)
> @echo "✓ Client built successfully: $(CLIENT_EXE)"

server: $(SERVER_SRC)
> @echo "Building server for $(TARGET_OS)..."
> $(CXX) $(CXXFLAGS) $(DEFINES) $(SERVER_SRC) -o $(SERVER_EXE) $(SERVER_LIBS)
> @echo "✓ Server built successfully: $(SERVER_EXE)"

clean:
> @echo "Cleaning build artifacts..."
ifeq ($(TARGET_OS),Windows)
> -del /Q *.exe 2>nul
else
> -rm -f $(CLIENT_EXE) $(SERVER_EXE)
endif
> @echo "✓ Clean complete"

# Development targets
rebuild: clean all

test-build: all
> @echo "=============================================="
> @echo "Build Test Complete"
> @echo "=============================================="
> @echo "Client: $(CLIENT_EXE)"
> @echo "Server: $(SERVER_EXE)"
> @echo ""
> @echo "Usage:"
> @echo "  1. Start server: ./$(SERVER_EXE)"
> @echo "  2. Connect client: ./$(CLIENT_EXE) <server_ip> [port]"
> @echo ""

# Help target
help:
> @echo "Available targets:"
> @echo "  all      - Build both client and server"
> @echo "  client   - Build client only"
> @echo "  server   - Build server only"
> @echo "  clean    - Remove build artifacts"
> @echo "  rebuild  - Clean and build all"
> @echo "  test-build - Build and show usage info"
> @echo "  help     - Show this help message"
