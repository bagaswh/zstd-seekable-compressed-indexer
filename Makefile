CC = clang
COMMON_CFLAGS = -Wall -Wextra -pedantic -Werror -std=c17 -march=native
DEBUG_CFLAGS = $(COMMON_CFLAGS) -O3 -Wall -Wextra -g -DDEBUG
ASAN_CFLAGS = $(COMMON_CFLAGS) -O3 -fsanitize=address -fsanitize=undefined -fno-omit-frame-pointer -fno-optimize-sibling-calls -fno-common

BUILD_DIR = build
TARGET = $(BUILD_DIR)/program
SOURCES = main.c

ZSTD_DIR = external/zstd
ZSTD_LIB_DIR = $(ZSTD_DIR)/lib
ZSTD_LIB = $(ZSTD_LIB_DIR)/libzstd.a
ZSTD_SEEKABLE_DIR = $(ZSTD_DIR)/contrib/seekable_format
ZSTD_SEEKABLE_SRCS = \
  $(ZSTD_SEEKABLE_DIR)/zstdseek_compress.c \
  $(ZSTD_SEEKABLE_DIR)/zstdseek_decompress.c
ZSTD_SEEKABLE_OBJS = $(ZSTD_SEEKABLE_SRCS:.c=.o)

INCLUDES = -I$(ZSTD_LIB_DIR) -I$(ZSTD_LIB_DIR)/common -I$(ZSTD_SEEKABLE_DIR)

all: $(TARGET)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(ZSTD_LIB):
	@echo "Building libzstd.a..."
	$(MAKE) -C $(ZSTD_LIB_DIR) libzstd.a

$(ZSTD_SEEKABLE_DIR)/%.o: $(ZSTD_SEEKABLE_DIR)/%.c
	@echo "Compiling $<..."
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(TARGET): $(BUILD_DIR) $(ZSTD_LIB) $(ZSTD_SEEKABLE_OBJS) $(SOURCES)
	@echo "Building CLI binary..."
	$(CC) $(CFLAGS) $(INCLUDES) $(SOURCES) $(ZSTD_SEEKABLE_OBJS) $(ZSTD_LIB) $(SOURCE_FILES) $(LDFLAGS) -o $(TARGET)

debug: CFLAGS = $(DEBUG_CFLAGS)
debug: all

asan: CFLAGS = $(ASAN_CFLAGS)
asan: LDFLAGS = $(ASAN_LDFLAGS)
asan: TARGET = $(BUILD_DIR)/cli-asan
asan: clean-objs $(TARGET)
	@echo "Built with AddressSanitizer: $(TARGET)"

clean-objs:
	@echo "Cleaning object files..."
	find $(ZSTD_SEEKABLE_DIR) -name '*.o' -delete

clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)
	find $(ZSTD_SEEKABLE_DIR) -name '*.o' -delete

clean-all: clean
	@echo "Cleaning zstd static library..."
	$(MAKE) -C $(ZSTD_LIB_DIR) clean

init-submodules:
	git submodule update --init --recursive

run: all
	$(TARGET)

run-asan: asan
	$(BUILD_DIR)/cli-asan

.PHONY: all debug asan clean clean-objs clean-all init-submodules run run-asan

build-genfile:
	clang -O2 -march=native -std=c17 -I. genfile.c -o genfile