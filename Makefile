CC              = clang
BUILD_DIR       = build
OBJ_DIR         = $(BUILD_DIR)/objs
SOURCES         = main.c $(CUTILS_DIR)/slice.c

# Libs
CUTILS_DIR      = external/cutils
XXHASH_DIR      = external/xxHash

INCLUDES        = -I$(ZSTD_LIB_DIR) -I$(ZSTD_SEEKABLE_DIR) -I$(CUTILS_DIR) -I$(XXHASH_DIR)

ARGS ?=

# Output preprocessed sources
ifdef PREPROCESS
	PREPROCESS_FLAG = -E
	OUTPUT_EXT = .i
	SKIP_LINKING = 1
endif

# Output assembly
ifdef ASM
	ASM_FLAG = -S
	OUTPUT_EXT = .s
	SKIP_LINKING = 1
endif

# Individual source file targets for preprocessing/assembly
PREPROCESS_TARGETS = $(patsubst %.c,$(BUILD_DIR)/%.i,$(notdir $(SOURCES)))
ASM_TARGETS = $(patsubst %.c,$(BUILD_DIR)/%.s,$(notdir $(SOURCES)))

# Default output extension
OUTPUT_EXT ?= 

# Common compiler/linker flags
COMMON_CFLAGS   = $(PREPROCESS_FLAG) $(ASM_FLAG) -std=c17 -march=native -mavx -msse
COMMON_LDFLAGS  = 

# Optional preprocessor defines
ifdef TRACE
    TRACE_FLAG = -DTRACE=$(TRACE)
endif

# Build types
RELEASE_CFLAGS  = $(COMMON_CFLAGS) -O2 -DNDEBUG $(TRACE_FLAG)
RELEASE_LDFLAGS = $(COMMON_LDFLAGS)
DEBUG_CFLAGS    = $(COMMON_CFLAGS) -pg -O0 -g3 -ggdb3 -DDEBUG $(TRACE_FLAG)
DEBUG_LDFLAGS   = $(COMMON_LDFLAGS)
ASAN_CFLAGS = $(DEBUG_CFLAGS) -fsanitize=address,undefined -fno-omit-frame-pointer -fno-optimize-sibling-calls -fno-common -O1 -g3 -ggdb3
ASAN_LDFLAGS = -fsanitize=address,undefined -g3

# Targets
TARGET_RELEASE  = $(BUILD_DIR)/program-release$(OUTPUT_EXT)
TARGET_DEBUG    = $(BUILD_DIR)/program-debug$(OUTPUT_EXT)
TARGET_ASAN     = $(BUILD_DIR)/program-asan$(OUTPUT_EXT)

# Zstd dependencies
ZSTD_DIR            = external/zstd
ZSTD_LIB_DIR        = $(ZSTD_DIR)/lib
ZSTD_LIB            = $(ZSTD_LIB_DIR)/libzstd.a
ZSTD_SEEKABLE_DIR   = $(ZSTD_DIR)/contrib/seekable_format
ZSTD_SEEKABLE_SRCS  = $(ZSTD_SEEKABLE_DIR)/zstdseek_compress.c \
                      $(ZSTD_SEEKABLE_DIR)/zstdseek_decompress.c
ZSTD_SEEKABLE_OBJS  = $(patsubst $(ZSTD_SEEKABLE_DIR)/%.c,$(OBJ_DIR)/%.o,$(ZSTD_SEEKABLE_SRCS))
ZSTD_INCLUDES       = -I$(ZSTD_LIB_DIR)/common

# XXHash dependencies
XXHASH_LIB          = $(XXHASH_DIR)/libxxhash.a

# Valgrind configuration
VALGRIND_OPTS = --leak-check=full --show-leak-kinds=all --track-origins=yes --verbose --error-exitcode=1

.PHONY: all release debug asan clean clean-all init-submodules run run-debug run-asan run-valgrind build-genfile preprocess preprocess-debug

all: release

release: $(if $(SKIP_LINKING),$(PREPROCESS_TARGETS)$(ASM_TARGETS),$(TARGET_RELEASE))

$(TARGET_RELEASE): CFLAGS = $(RELEASE_CFLAGS)
$(TARGET_RELEASE): LDFLAGS = $(RELEASE_LDFLAGS)
$(TARGET_RELEASE): $(BUILD_DIR) $(ZSTD_LIB) $(XXHASH_LIB) $(ZSTD_SEEKABLE_OBJS) $(SOURCES)
	@echo "Building Release binary..."
	$(CC) $(CFLAGS) $(INCLUDES) $(SOURCES) $(ZSTD_SEEKABLE_OBJS) $(ZSTD_LIB) $(XXHASH_LIB) $(LDFLAGS) -o $(TARGET_RELEASE)

# Individual file preprocessing/assembly rules
$(BUILD_DIR)/%.i: %.c | $(BUILD_DIR)
	@echo "Preprocessing $< -> $@"
	$(CC) $(RELEASE_CFLAGS) $(INCLUDES) -E $< -o $@

$(BUILD_DIR)/%.i: $(CUTILS_DIR)/%.c | $(BUILD_DIR)
	@echo "Preprocessing $< -> $@"
	$(CC) $(RELEASE_CFLAGS) $(INCLUDES) -E $< -o $@

$(BUILD_DIR)/%.s: %.c | $(BUILD_DIR)
	@echo "Generating assembly $< -> $@"
	$(CC) $(RELEASE_CFLAGS) $(INCLUDES) -S $< -o $@

$(BUILD_DIR)/%.s: $(CUTILS_DIR)/%.c | $(BUILD_DIR)
	@echo "Generating assembly $< -> $@"
	$(CC) $(RELEASE_CFLAGS) $(INCLUDES) -S $< -o $@

debug: $(if $(SKIP_LINKING),$(PREPROCESS_TARGETS)$(ASM_TARGETS),$(TARGET_DEBUG))

$(TARGET_DEBUG): CFLAGS = $(DEBUG_CFLAGS)
$(TARGET_DEBUG): LDFLAGS = $(DEBUG_LDFLAGS)
$(TARGET_DEBUG): $(BUILD_DIR) $(ZSTD_LIB) $(XXHASH_LIB) $(ZSTD_SEEKABLE_OBJS) $(SOURCES)
	@echo "Building Debug binary..."
	$(CC) $(CFLAGS) $(INCLUDES) $(SOURCES) $(ZSTD_SEEKABLE_OBJS) $(ZSTD_LIB) $(XXHASH_LIB) $(LDFLAGS) -o $(TARGET_DEBUG)

# Debug versions of preprocessing/assembly rules
$(BUILD_DIR)/%-debug.i: %.c | $(BUILD_DIR)
	@echo "Preprocessing (debug) $< -> $@"
	$(CC) $(DEBUG_CFLAGS) $(INCLUDES) -E $< -o $@

$(BUILD_DIR)/%-debug.i: $(CUTILS_DIR)/%.c | $(BUILD_DIR)
	@echo "Preprocessing (debug) $< -> $@"
	$(CC) $(DEBUG_CFLAGS) $(INCLUDES) -E $< -o $@

$(BUILD_DIR)/%-debug.s: %.c | $(BUILD_DIR)
	@echo "Generating assembly (debug) $< -> $@"
	$(CC) $(DEBUG_CFLAGS) $(INCLUDES) -S $< -o $@

$(BUILD_DIR)/%-debug.s: $(CUTILS_DIR)/%.c | $(BUILD_DIR)
	@echo "Generating assembly (debug) $< -> $@"
	$(CC) $(DEBUG_CFLAGS) $(INCLUDES) -S $< -o $@

asan: clean-objs $(if $(SKIP_LINKING),$(PREPROCESS_TARGETS)$(ASM_TARGETS),$(TARGET_ASAN))

$(TARGET_ASAN): CFLAGS = $(ASAN_CFLAGS)
$(TARGET_ASAN): LDFLAGS = $(ASAN_LDFLAGS)
$(TARGET_ASAN): $(BUILD_DIR) $(ZSTD_LIB) $(XXHASH_LIB) $(ZSTD_SEEKABLE_OBJS) $(SOURCES)
	@echo "Building AddressSanitizer binary..."
	$(CC) $(CFLAGS) $(INCLUDES) $(SOURCES) $(ZSTD_SEEKABLE_OBJS) $(ZSTD_LIB) $(XXHASH_LIB) $(LDFLAGS) -o $(TARGET_ASAN)

# Convenience targets for preprocessing
preprocess:
	$(MAKE) release PREPROCESS=1

preprocess-debug:
	$(MAKE) debug PREPROCESS=1

# Convenience targets for assembly output
asm:
	$(MAKE) release ASM=1

asm-debug:
	$(MAKE) debug ASM=1

# Individual file targets
preprocess-main: $(BUILD_DIR)/main.i
preprocess-slice: $(BUILD_DIR)/slice.i
asm-main: $(BUILD_DIR)/main.s
asm-slice: $(BUILD_DIR)/slice.s

$(BUILD_DIR) $(OBJ_DIR):
	@mkdir -p $@

$(ZSTD_LIB):
	@echo "Building libzstd.a..."
	$(MAKE) -C $(ZSTD_LIB_DIR) libzstd.a

$(XXHASH_LIB):
	@echo "Building libxxhash.a..."
	$(MAKE) -C $(XXHASH_DIR) libxxhash.a

# Compile Zstd seekable objects into build/objs
$(OBJ_DIR)/%.o: $(ZSTD_SEEKABLE_DIR)/%.c | $(OBJ_DIR)
	@echo "Compiling $< -> $@"
	$(CC) $(CFLAGS) $(INCLUDES) $(ZSTD_INCLUDES) -c $< -o $@

clean-objs:
	@echo "Cleaning object files..."
	rm -rf $(OBJ_DIR)

clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)

clean-all: clean
	@echo "Cleaning zstd static library..."
	$(MAKE) -C $(ZSTD_LIB_DIR) clean
	@echo "Cleaning xxhash static library..."
	$(MAKE) -C $(XXHASH_DIR) clean

init-submodules:
	git submodule update --init --recursive

run: release
	$(TARGET_RELEASE)

run-debug: debug
	$(TARGET_DEBUG)

run-asan-debug: asan
	ASAN_OPTIONS=symbolize=1:abort_on_error=1:halt_on_error=1:print_stacktrace=1 ASAN_SYMBOLIZER_PATH=$$(which llvm-symbolizer) $(TARGET_ASAN) $(ARGS)

run-valgrind: debug
	@echo "Running under Valgrind..."
	valgrind $(VALGRIND_OPTS) $(TARGET_DEBUG)

build-genfile:
	@echo "Building genfile utility..."
	$(CC) -O2 -march=native -std=c17 -I. genfile.c -o genfile