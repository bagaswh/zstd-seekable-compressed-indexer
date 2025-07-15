#define _GNU_SOURCE

#include <argp.h>
#include <errno.h>
#include <error.h>
#include <immintrin.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "slice.h"
#include "xxhash.h"
#include "zstd.h"
#include "zstd_seekable.h"

typedef uint8_t u8;
typedef int8_t i8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int64_t i64;

int compress_main(int argc, char **argv);
int info_main(int argc, char **argv);
int write_pairs_main(int argc, char **argv);
int build_index_main(int argc, char **argv);
int decompress_frame_main(int argc, char **argv);

struct subcommand {
	const char *name;
	int (*func)(int argc, char **argv);
	const char *description;
};

static struct subcommand subcommands[] = {
    {"compress", compress_main, "Compress files"},
    {"build-index", build_index_main, "Build index from streaming pairs"},
    {"info", info_main, "Show file information"},
    {NULL, NULL, NULL}};

void print_usage(const char *program_name) {
	printf("Usage: %s <subcommand> [options]\n\n", program_name);
	printf("Available subcommands:\n");
	for (int i = 0; subcommands[i].name; i++) {
		printf("  %-12s %s\n", subcommands[i].name, subcommands[i].description);
	}
	printf("\nUse '%s <subcommand> --help' for subcommand-specific options.\n", program_name);
}

#define ERR_OK 0
#define ERR_ALLOC 1
#define ERR_ZSTD_INIT 2
#define ERR_ZSTD_COMPRESS 3

/* Utils */

#define min(a, b) ((a) < (b) ? (a) : (b))
#define max(a, b) ((a) > (b) ? (a) : (b))

typedef enum {
	ERROR_fsize = 1,
	ERROR_fopen = 2,
	ERROR_fclose = 3,
	ERROR_fread = 4,
	ERROR_fwrite = 5,
	ERROR_loadFile = 6,
	ERROR_saveFile = 7,
	ERROR_malloc = 8,
	ERROR_largeFile = 9,
	ERROR_fflush = 10,
	ERROR_mmap = 11,
} COMMON_ErrorCode;

#define CHECK(cond, ...)                        \
	do {                                        \
		if (!(cond)) {                          \
			fprintf(stderr,                     \
			        "%s:%d CHECK(%s) failed: ", \
			        __FILE__,                   \
			        __LINE__,                   \
			        #cond);                     \
			fprintf(stderr, "" __VA_ARGS__);    \
			fprintf(stderr, "\n");              \
			exit(1);                            \
		}                                       \
	} while (0)

#define CHECK_ZSTD(fn)                                           \
	do {                                                         \
		size_t const err = (fn);                                 \
		CHECK(!ZSTD_isError(err), "%s", ZSTD_getErrorName(err)); \
	} while (0)

u8 *mmap_or_die(FILE *file, size_t size) {
	u8 *const data = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fileno(file), 0);
	if (data == MAP_FAILED) {
		perror("mmap");
		exit(ERROR_mmap);
	}
	return data;
}

FILE *fopen_orDie(const char *filename, const char *instruction) {
	FILE *const inFile = fopen(filename, instruction);
	if (inFile) return inFile;
	/* error */
	perror(filename);
	exit(ERROR_fopen);
}

static size_t fclose_orDie(FILE *file) {
	if (!fclose(file)) return 0;
	/* error */
	perror("fclose");
	exit(6);
}

size_t fread_orDie(void *buffer, size_t sizeToRead, FILE *file) {
	size_t const readSize = fread(buffer, 1, sizeToRead, file);
	if (readSize == sizeToRead)
		return readSize; /* good */
	if (feof(file))
		return readSize; /* good, reached end of file */
	/* error */
	perror("fread");
	exit(ERROR_fread);
}

size_t fwrite_orDie(const void *buffer, size_t sizeToWrite, FILE *file) {
	size_t const writtenSize = fwrite(buffer, 1, sizeToWrite, file);
	if (writtenSize == sizeToWrite) return sizeToWrite; /* good */
	/* error */
	perror("fwrite");
	exit(ERROR_fwrite);
}

int fflush_orDie(FILE *file) {
	int const ret = fflush(file);
	if (ret == 0) return 0;
	/* error */
	perror("fflush");
	exit(ERROR_fflush);
}

void *malloc_orDie(size_t size) {
	void *const buff = malloc(size);
	if (buff)
		return buff;
	/* error */
	perror("malloc");
	exit(ERROR_malloc);
}

void *realloc_orDie(void *ptr, size_t size) {
	void *new_ptr = realloc(ptr, size);
	if (new_ptr)
		return new_ptr;
	/* error */
	perror("realloc");
	exit(ERROR_malloc);
}

int main(int argc, char **argv) {
	if (argc < 2) {
		print_usage(argv[0]);
		return 1;
	}

	// Find and execute subcommand
	for (int i = 0; subcommands[i].name; i++) {
		if (strcmp(argv[1], subcommands[i].name) == 0) {
			// Shift arguments: subcommand becomes argv[0]
			return subcommands[i].func(argc - 1, argv + 1);
		}
	}

	printf("Unknown subcommand: %s\n", argv[1]);
	print_usage(argv[0]);
	return 1;
}

#define ZSTD_MAGICNUMBER 0xFD2FB528

int compress_main(int argc, char **argv) {
	char *infile = NULL;
	char *outfile = NULL;
	int level = 10;
	int frame_size = 65536;
	int verbose = 0;

	static struct option long_options[] = {
	    {"infile", required_argument, 0, 'i'},
	    {"outfile", required_argument, 0, 'o'},
	    {"level", required_argument, 0, 'l'},
	    {"frame-size", required_argument, 0, 's'},
	    {"verbose", no_argument, 0, 'v'},
	    {"help", no_argument, 0, 'h'},
	    {0, 0, 0, 0}};

	while (1) {
		int c = getopt_long(argc, argv, "i:o:l:s:vh", long_options, NULL);
		if (c == -1) break;

		switch (c) {
		case 'i':
			infile = optarg;
			break;
		case 'o':
			outfile = optarg;
			break;
		case 'l':
			level = atoi(optarg);
			break;
		case 's':
			frame_size = atoi(optarg);
			break;
		case 'v':
			verbose = 1;
			break;
		case 'h':
			printf("Usage: %s [options]\n", argv[0]);
			printf("Options:\n");
			printf("  -i, --infile FILE     Input file (default: stdin)\n");
			printf("  -o, --outfile FILE    Output file (default: stdout)\n");
			printf("  -l, --level INT       Compression level (default: 10)\n");
			printf("  -s, --frame-size INT  Frame size (default: 65536)\n");
			printf("  -v, --verbose         Enable verbose output\n");
			printf("  -h, --help            Show this help\n");
			return 0;
		case '?':
			return 1;
		}
	}

	printf("Compressing with level %d, frame size %d\n", level, frame_size);
	if (infile) printf("Input: %s\n", infile);
	if (outfile) printf("Output: %s\n", outfile);
	if (verbose) printf("Verbose mode enabled\n");

	int ret = ERR_OK;

	FILE *in = infile ? fopen_orDie(infile, "rb") : stdin;
	FILE *out = outfile ? fopen_orDie(outfile, "wb") : stdout;

	ZSTD_seekable_CStream *zcs = ZSTD_seekable_createCStream();
	if (zcs == NULL) {
		return ERR_ZSTD_INIT;
	}

	size_t const buff_in_size = ZSTD_CStreamInSize();
	void *const buff_in = malloc_orDie(buff_in_size);
	size_t const buff_out_size = ZSTD_CStreamOutSize();
	void *const buff_out = malloc_orDie(buff_out_size);

	size_t const init_result =
	    ZSTD_seekable_initCStream(zcs, level, 1, frame_size);
	if (ZSTD_isError(init_result)) {
		fprintf(stderr, "ZSTD_seekable_initCStream() error : %s \n",
		        ZSTD_getErrorName(init_result));
		exit(11);
	}

	size_t read, to_read = buff_in_size;
	while ((read = fread_orDie(buff_in, to_read, in))) {
		ZSTD_inBuffer input = {buff_in, read, 0};
		while (input.pos < input.size) {
			ZSTD_outBuffer output = {buff_out, buff_out_size, 0};
			to_read = ZSTD_seekable_compressStream(zcs, &output, &input);
			if (ZSTD_isError(to_read)) {
				fprintf(stderr, "ZSTD_seekable_compressStream() error : %s \n",
				        ZSTD_getErrorName(to_read));
				exit(12);
			}
			if (to_read > buff_in_size)
				to_read = buff_in_size;
			fwrite_orDie(buff_out, output.pos, out);
		}
	}

	while (1) {
		ZSTD_outBuffer output = {buff_out, buff_out_size, 0};
		size_t const remaining_to_flush = ZSTD_seekable_endStream(zcs, &output);
		CHECK_ZSTD(remaining_to_flush);
		fwrite_orDie(buff_out, output.pos, out);
		if (!remaining_to_flush) {
			break;
		}
	}

	ZSTD_seekable_freeCStream(zcs);
	free(buff_in);
	free(buff_out);

	return ret;
}

struct print_info_args {
	bool print_seek_table;
	bool print_frames_list;
};

void stringify_bits(u8 byte, char *result) {
	for (int bit = 0; bit < (sizeof(u8) * 8); bit++) {
		memcpy(result, (byte & 0x01) ? "1" : "0", 1);
		byte = byte >> 1;
		result++;
	}
}

void print_frame(u8 *ptr) {
	size_t offset = 0;

	u32 magic;
	memcpy(&magic, ptr + offset, sizeof(u32));
	offset += sizeof(u32);  // 4 byte magic

	if (magic != ZSTD_MAGICNUMBER) {
		printf("Invalid magic number\n");
		return;
	}

	/* Frame header */

	/* Frame header descriptor (1 byte) */
	u8 frame_header_descriptor = ptr[offset++];

	char *fhd_bits = malloc(9);
	fhd_bits[8] = '\0';
	stringify_bits(frame_header_descriptor, fhd_bits);
	printf("Frame header descriptor: %s\n", fhd_bits);

	u8 fcs_field_size = (frame_header_descriptor >> 6) & 0x03;
	u8 single_segment = (frame_header_descriptor >> 5) & 0x01;
	u8 content_checksum = (frame_header_descriptor >> 2) & 0x01;
	u8 dictionary_id_flag = frame_header_descriptor & 0x03;

	printf("\tFrame content size field size: %d", fcs_field_size);

	int fcs_bytes = 0;
	if (fcs_field_size == 0) {
		fcs_bytes = single_segment ? 1 : 0;
		printf(" (%d bytes)\n", fcs_bytes);
	} else if (fcs_field_size == 1) {
		fcs_bytes = 2;
		printf(" (%d bytes)\n", fcs_bytes);
	} else if (fcs_field_size == 2) {
		fcs_bytes = 4;
		printf(" (%d bytes)\n", fcs_bytes);
	} else if (fcs_field_size == 3) {
		fcs_bytes = 8;
		printf(" (%d bytes)\n", fcs_bytes);
	}

	printf("\tSingle segment: %d\n", single_segment);
	printf("\tContent checksum: %d\n", content_checksum);
	printf("\tDictionary ID flag: %d\n", dictionary_id_flag);

	/* Window descriptor (0-1 byte) */
	if (!single_segment) {
		u8 window_descriptor = ptr[offset++];
		printf("Window descriptor: %x\n", window_descriptor);
	}

	/* Dictionary ID (0-4 bytes) */
	if (dictionary_id_flag > 0) {
		u32 dictionary_id = 0;
		int dict_size = dictionary_id_flag;  // 1, 2, or 3 bytes
		if (dictionary_id_flag == 3) dict_size = 4;

		memcpy(&dictionary_id, ptr + offset, dict_size);
		offset += dict_size;
		printf("Dictionary ID: %x\n", dictionary_id);
	}

	/* Frame content size (0-8 bytes) */
	if (fcs_bytes > 0) {
		u64 frame_content_size = 0;
		memcpy(&frame_content_size, ptr + offset, fcs_bytes);

		if (fcs_bytes == 2) {
			frame_content_size += 256;
		}
		offset += fcs_bytes;

		printf("Frame content size (decompressed): %ld\n", frame_content_size);
	} else {
		printf("Frame content size: not present\n");
	}

	if (content_checksum) {
		offset += 4;
	}

	free(fhd_bits);
}

void zstd_seekable_print_info(void *ptr, size_t size, struct print_info_args args) {}

int info_main(int argc, char **argv) {
	char *infile = NULL;
	char *outfile = NULL;

	struct print_info_args args = {.print_seek_table = false, .print_frames_list = false};

	static struct option long_options[] = {
	    {"infile", required_argument, 0, 'i'},
	    {"outfile", required_argument, 0, 'o'},
	    {"print-seek-table", no_argument, 0, 's'},
	    {"print-frames-list", no_argument, 0, 'f'},
	    {"help", no_argument, 0, 'h'},
	    {0, 0, 0, 0}};

	while (1) {
		int c = getopt_long(argc, argv, "i:o:l:s:f:vh", long_options, NULL);
		if (c == -1) break;

		switch (c) {
		case 'i':
			infile = optarg;
			break;
		case 'o':
			outfile = optarg;
			break;
		case 's':
			args.print_seek_table = true;
			break;
		case 'f':
			args.print_frames_list = true;
			break;
		case 'h':
			printf("Usage: %s [options]\n", argv[0]);
			printf("Options:\n");
			printf("  -i, --infile FILE     Input file (default: stdin)\n");
			printf("  -o, --outfile FILE    Output file (default: stdout)\n");
			printf("  -h, --help            Show this help\n");
			return 0;
		case '?':
			return 1;
		}
	}

	if (infile) printf("Input: %s\n", infile);
	if (outfile) printf("Output: %s\n", outfile);

	FILE *in = infile ? fopen_orDie(infile, "rb") : stdin;

	struct stat st;
	if (fstat(fileno(in), &st) != 0) {
		printf("Failed to stat file: %s\n", strerror(errno));
		return 1;
	}

	u8 *ptr = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fileno(in), 0);
	if (ptr == MAP_FAILED) {
		printf("Failed to map file: %s\n", strerror(errno));
		return 1;
	}

	// Print first frame
	printf("--- Frame 0 ---\n");
	print_frame(ptr);
	printf("\n");

	// Print seektable entries
	printf("--- Seektable ---\n");
	zstd_seekable_print_info(ptr, st.st_size, args);

	return 0;
}

/* ---- begin CPUID ---- */

// Function to execute CPUID instruction
static inline void cpuid(uint32_t leaf, uint32_t subleaf, uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx) {
#ifdef _MSC_VER
	// Microsoft Visual C++ compiler
	int regs[4];
	__cpuidex(regs, leaf, subleaf);
	*eax = regs[0];
	*ebx = regs[1];
	*ecx = regs[2];
	*edx = regs[3];
#else
	// GCC and Clang
	__asm__ volatile("cpuid"
	                 : "=a"(*eax), "=b"(*ebx), "=c"(*ecx), "=d"(*edx)
	                 : "a"(leaf), "c"(subleaf));
#endif
}

// Check if CPU supports SSE4.1 and SSE4.2
int check_sse4_support() {
	uint32_t eax, ebx, ecx, edx;

	// CPUID leaf 1: Feature Information
	cpuid(1, 0, &eax, &ebx, &ecx, &edx);

	// SSE4.1 is bit 19 of ECX, SSE4.2 is bit 20 of ECX
	int sse4_1 = (ecx >> 19) & 1;
	int sse4_2 = (ecx >> 20) & 1;

	return sse4_1 && sse4_2;
}

// Check if CPU supports AVX
int check_avx_support() {
	uint32_t eax, ebx, ecx, edx;

	// CPUID leaf 1: Feature Information
	cpuid(1, 0, &eax, &ebx, &ecx, &edx);

	// AVX is bit 28 of ECX
	int avx_cpuid = (ecx >> 28) & 1;

	// Also need to check if OS supports AVX (XSAVE/XRSTOR)
	int osxsave = (ecx >> 27) & 1;

	if (!avx_cpuid || !osxsave) {
		return 0;
	}

	// Check if OS has enabled AVX support
	uint64_t xcr0;
#ifdef _MSC_VER
	xcr0 = _xgetbv(0);
#else
	__asm__ volatile("xgetbv" : "=a"(xcr0) : "c"(0) : "edx");
#endif

	// Check if YMM state is enabled (bits 1 and 2 of XCR0)
	return (xcr0 & 6) == 6;
}

// Check if CPU supports AVX2
int check_avx2_support() {
	uint32_t eax, ebx, ecx, edx;

	// First check if AVX is supported
	if (!check_avx_support()) {
		return 0;
	}

	// CPUID leaf 7, subleaf 0: Extended Features
	cpuid(7, 0, &eax, &ebx, &ecx, &edx);

	// AVX2 is bit 5 of EBX
	return (ebx >> 5) & 1;
}

/* ---- end CPUID ---- */

#define INDEX_MAGIC 0x7EFB8DC1

int index_of_newline_scalar(char *data, ssize_t start, ssize_t size) {
	if (start < 0 || start >= size) return -1;
	if ((size - start) == 0) return -1;
	for (ssize_t i = start; i < size; i++) {
		if (data[i] == '\n') {
			return i;
		}
	}
	return -1;
}

int index_of_newline_sse(char *data, ssize_t start, ssize_t size) {
	if (start < 0 || start >= size) return -1;
	if ((size - start) == 0) return -1;

	const __m128i newline_vec = _mm_set1_epi8('\n');
	ssize_t i = 0;

	// Process 16 bytes at a time
	for (i = start; i <= size - 16; i += 16) {
		__m128i chunk = _mm_loadu_si128((__m128i *)(data + i));
		__m128i cmp = _mm_cmpeq_epi8(chunk, newline_vec);

		int mask = _mm_movemask_epi8(cmp);
		if (mask != 0) {
			// Found a newline, find the first one
			int offset = __builtin_ctz(mask);
			return i + offset;
		}
	}

	// Handle remaining bytes (less than 16)
	for (; i < size; i++) {
		if (data[i] == '\n') {
			return i;
		}
	}

	return -1;
}

int index_of_newline_avx2(char *data, ssize_t start, ssize_t size) {
	if (start < 0 || start >= size) return -1;
	if ((size - start) == 0) return -1;

	const __m256i newline_vec = _mm256_set1_epi8('\n');
	ssize_t i = 0;

	// Process 32 bytes at a time
	for (i = start; i <= size - 32; i += 32) {
		__m256i chunk = _mm256_loadu_si256((__m256i *)(data + i));
		__m256i cmp = _mm256_cmpeq_epi8(chunk, newline_vec);

		int mask = _mm256_movemask_epi8(cmp);
		if (mask != 0) {
			// Found a newline, find the first one
			int offset = __builtin_ctz(mask);
			return i + offset;
		}
	}

	// Handle remaining bytes (less than 32)
	for (; i < size; i++) {
		if (data[i] == '\n') {
			return i;
		}
	}

	return -1;
}

int index_of_newline_avx2_aligned(char *data, ssize_t start, ssize_t size) {
	if (size == 0) return -1;

	const __m256i newline_vec = _mm256_set1_epi8('\n');
	size_t i = 0;

	// Handle unaligned prefix to reach 32-byte boundary
	uintptr_t addr = (uintptr_t)data;
	size_t prefix_len = (32 - (addr & 31)) & 31;

	if (prefix_len > 0 && prefix_len < size) {
		for (i = 0; i < prefix_len; i++) {
			if (data[i] == '\n') {
				return i;
			}
		}
	}

	// Process 32 bytes at a time with aligned access
	for (; i <= size - 32; i += 32) {
		__m256i chunk;
		if ((addr + i) & 31) {
			chunk = _mm256_loadu_si256((__m256i *)(data + i));
		} else {
			chunk = _mm256_load_si256((__m256i *)(data + i));
		}

		__m256i cmp = _mm256_cmpeq_epi8(chunk, newline_vec);
		int mask = _mm256_movemask_epi8(cmp);

		if (mask != 0) {
			int offset = __builtin_ctz(mask);
			return i + offset;
		}
	}

	// Handle remaining bytes
	for (; i < size; i++) {
		if (data[i] == '\n') {
			return i;
		}
	}

	return -1;
}

int index_of_newline_auto(char *data, ssize_t start, ssize_t size) {
	if (start < 0 || start >= size) return -1;
	if ((size - start) < 32) {
		return index_of_newline_scalar(data, start, size);
	}
	if ((size - start) < 128 && check_sse4_support()) {
		return index_of_newline_sse(data, start, size);
	}
	if ((size - start) < 256 && check_avx2_support()) {
		return index_of_newline_avx2(data, start, size);
	}
	return index_of_newline_scalar(data, start, size);
}

union xxhash64_result {
	u8 bytes[8];
	u64 value;
};

union xxhash64_result __attribute__((always_inline)) xxhash64(void *data, size_t len) {
	return (union xxhash64_result)XXH3_64bits(data, len);
}

#define CHECKSUM_FLAG_MASK 1 << 0

#define FRAME_SIZE_FLAG_MASK 1 << 0
#define OFFSET_WITHIN_FRAME_FLAG_MASK 1 << 7

#define INDEX_MAGIC_NUMBER 0x6A767BE
#define INDEX_GROUP_MAGIC_NUMBER 0x3A9B0643

struct index_header {
	u32 magic_number;

	// Descriptor
	// 0 0 0 0 0 0 0 0
	// | | | | | | | |
	// | | | | | | | +--- checksum flag
	// | | | | | | +----- unused
	// | | | | | +------- unused
	// | | | | +--------- unused
	// | | | +----------- unused
	// | | +------------- unused
	// | +--------------- unused
	u8 descriptor;
};

struct index_group_table_entry {
	u64 offset;
};

struct index_group_header {
	u32 magic_number;
	u64 entry_size;
	u64 entries_count;
};

/*
    The actual on-disk layout of the index entry is as follows:

    | key | descriptor | frame_start | frame_size | offset_within_frame_start | offset_within_frame_end | checksum (optional) |
    +-----+------------+-------------+------------+--------------------------+--------------------------+----------------------+
    | 8   | 1          | 8           | 8          | 8                        | 8                        | 4                    |

    The struct fields are arranged in this way to minimize paddings.
*/
struct index_entry {
	union xxhash64_result key;
	u64 frame_start;
	u64 frame_size;
	u64 offset_within_frame_start;
	u64 offset_within_frame_end;

	u32 checksum;

	// Descriptor bit layout:
	//
	//  15 14 13 12 11 10  9  8  7  6  5  4  3  2  1  0
	// ┌──┬──┬──┬──┬──┬──┬──┬──┬──┬──┬──┬──┬──┬──┬──┬──┐
	// │  │  │  │  │  │  │  │  │  │  │  │  │  │  │  │  │
	// └──┴──┴──┴──┴──┴──┴──┴──┴──┴──┴──┴──┴──┴──┴──┴──┘
	//         │  │  │  │  │  │  │  │  │  │  │  │  │  │
	//         │  │  │  │  │  │  │  │  │  │  │  │  │  └─── bit 0      : frame size flag
	//         │  │  │  │  │  │  │  │  │  │  └──┴──┴────── bit 1-3    : frame start byte size length
	//         │  │  │  │  │  │  │  └──┴──┴─────────────── bit 4-6    : frame size byte size length
	//         │  │  │  │  │  │  └──────────────────────── bit 7      : offset_within_frame flag
	//         │  │  │  └──┴──┴─────────────────────────── bit 8-10   : offset_within_frame byte size length
	//         └──┴──┴──────────────────────────────────── bit 11-13  : offset_within_frame_end byte size length
	//
	u16 descriptor;
};

struct index_header create_index_header(bool with_checksum) {
	struct index_header header = {.magic_number = INDEX_MAGIC_NUMBER, .descriptor = with_checksum ? CHECKSUM_FLAG_MASK : 0};
	return header;
}

size_t write_index_header(FILE *stream, struct index_header hdr) {
	char buf[sizeof(struct index_header)];
	size_t written = 0;
	memcpy(buf, &((u32){INDEX_MAGIC_NUMBER}), sizeof(u32));
	written += sizeof(u32);
	memccpy(buf + written, &hdr.descriptor, 0, sizeof(u8));
	written += sizeof(u8);
	return fwrite(buf, written, 1, stream);
}

size_t write_index_group_header(FILE *stream, struct index_header hdr, u64 entry_size, u64 entries_count) {
	if (hdr.descriptor & CHECKSUM_FLAG_MASK) {
		entry_size += sizeof(u32);
	}
	size_t written = 0;
	char buf[sizeof(struct index_group_header)];
	memcpy(buf, &((u32){INDEX_GROUP_MAGIC_NUMBER}), sizeof(u32));
	written += sizeof(u32);
	memccpy(buf + written, &entries_count, 0, sizeof(u64));
	written += sizeof(u64);
	memccpy(buf + written, &entry_size, 0, sizeof(u64));
	written += sizeof(u64);
	return fwrite(buf, written, 1, stream);
}

#define sizeof_struct_member(type, member) sizeof(((type *)0)->member)
#define sizeof_index_entry_member(member) sizeof_struct_member(struct index_entry, member)

i8 get_byte_length(size_t value) {
	if (value <= UINT8_MAX) {
		return 1;
	} else if (value <= UINT16_MAX) {
		return 2;
	} else if (value <= UINT32_MAX) {
		return 3;
	} else if (value <= UINT64_MAX) {
		return 4;
	}
	return -1;
}

size_t write_index_entry(FILE *stream, u8 index_mode, struct index_header hdr, struct index_entry entry) {
	size_t written = 0;

	char buf[sizeof(struct index_entry)];

	size_t checksum_size = sizeof_index_entry_member(checksum);
	memcpy(buf, &entry.key, sizeof_index_entry_member(key));
	written += sizeof_index_entry_member(key);

	char *descriptor_buf_ptr = buf + sizeof_index_entry_member(key);
	char *frame_start_buf_ptr = descriptor_buf_ptr + sizeof_index_entry_member(descriptor);
	char *frame_size_buf_ptr = frame_start_buf_ptr + sizeof_index_entry_member(frame_start);
	char *offset_within_frame_start_buf_ptr = frame_size_buf_ptr + sizeof_index_entry_member(frame_size);
	char *offset_within_frame_end_buf_ptr = offset_within_frame_start_buf_ptr + sizeof_index_entry_member(offset_within_frame_start);

	u16 descriptor = 0;

	i8 frame_start_byte_length = get_byte_length(entry.frame_start);
	if (frame_start_byte_length < 0) {
		fprintf(stderr, "frame_start_byte_length is invalid\n");
		return 0;
	}
	// frame start byte length
	if (frame_start_byte_length > 1) {
		descriptor |= (frame_start_byte_length << 1);
	}
	memcpy(frame_start_buf_ptr, &entry.frame_start, frame_start_byte_length);
	written += frame_start_byte_length;

	i8 frame_size_byte_length = get_byte_length(entry.frame_size);
	if (entry.frame_size > 0) {
		descriptor |= FRAME_SIZE_FLAG_MASK;
		if (frame_size_byte_length < 0) {
			fprintf(stderr, "frame_size_byte_length is invalid\n");
			return 0;
		}
		// frame size byte length
		if (frame_size_byte_length > 1) {
			descriptor |= (frame_size_byte_length << 4);
		}
		memcpy(frame_size_buf_ptr, &entry.frame_size, frame_size_byte_length);
		written += frame_size_byte_length;
	}

	memcpy(descriptor_buf_ptr, &descriptor, sizeof(descriptor));
	written += sizeof(descriptor);

	return fwrite(buf, written, 1, stream);
}

size_t write_index_group_table(FILE *stream, struct index_group_table_entry *entries, u64 entries_count) {
	size_t written = 0;
	for (size_t i = 0; i < entries_count; i++) {
		size_t to_write = min(entries_count * sizeof(struct index_group_table_entry), 50 * sizeof(struct index_group_table_entry));
		size_t ret = fwrite(entries, to_write, 1, stream);
		if (ret != 1) {
			return 0;
		}
		written += ret;
	}
	return written;
}

struct decompressed_frame_result {
	u64 frame;
	size_t c_offset;
	size_t c_size;
	size_t d_offset;
	size_t d_size;
	ssize_t decompressed_bytes;
	ssize_t decompressed_bytes_remaining;
	char *decompressed_data;
	char *decompressed_data_ptr;
};

typedef struct index_entrier_package (*index_entrier_create_package)();
typedef struct index_entrier_return_val (*index_entrier)(struct decompressed_frame_result result, void **entrier_ctx);
typedef size_t (*index_entrier_init)(void **entrier_ctx);
typedef size_t (*index_entrier_reset_before_next_frame)(void **entrier_ctx);
typedef size_t (*index_entrier_reset_before_next_local_iter)(void **entrier_ctx);
typedef void (*index_entrier_free)(void **entrier_ctx);

struct index_entrier_package {
	index_entrier entrier;
	index_entrier_init init;
	index_entrier_reset_before_next_frame reset_before_next_frame;
	index_entrier_reset_before_next_local_iter reset_before_next_local_iter;
	index_entrier_free free;
};

struct index_entrier_line_entry_ctx {
	int prev_newline_index;
	int prev_newline_frame;
	int newline_index;
	int last_d_offset;
	Slice *line_buf;
	struct index_entry entry;
	u8 index_mode;
	int lines;
};

struct index_entrier_return_val {
	struct index_entry entry;
	ssize_t advance_n;
	bool has_index_entry;
};

struct index_entrier_return_val index_entrier_line_entry(struct decompressed_frame_result result, void **entrier_ctx) {
	struct index_entrier_line_entry_ctx **t_ctx = (struct index_entrier_line_entry_ctx **)entrier_ctx;
	struct index_entrier_return_val ret = {.entry = {0}, .advance_n = 0};

	u8 index_mode = (*t_ctx)->index_mode;

	struct index_entry entry;
	memset(&entry, 0, sizeof(entry));

	Slice *line_buf = (*t_ctx)->line_buf;

	char *decompressed_data = result.decompressed_data;
	char *decompressed_data_ptr = result.decompressed_data_ptr;
	(*t_ctx)->newline_index = index_of_newline_auto(decompressed_data, (*t_ctx)->prev_newline_index + 1, result.decompressed_bytes);
	if ((*t_ctx)->newline_index != -1) {
		ssize_t diff = (*t_ctx)->newline_index - (*t_ctx)->prev_newline_index;
		if (diff < 0) {
			fwrite(decompressed_data, 1, (*t_ctx)->newline_index, stdout);
		}
		slice_append_n(line_buf, decompressed_data_ptr, diff);

		char *line = slice_get_ptr_begin_offset(line_buf);
		size_t line_len = slice_get_len(line_buf);
		union xxhash64_result line_hash = xxhash64(line, line_len);
		entry.key = line_hash;

		slice_reset(line_buf);

		entry.frame_start = (*t_ctx)->prev_newline_frame;
		if (entry.frame_start != result.frame) {
			entry.frame_size = result.frame - entry.frame_start;
		}
		entry.offset_within_frame_start = (*t_ctx)->prev_newline_index + 1;
		entry.offset_within_frame_end = (*t_ctx)->newline_index;

		(*t_ctx)->prev_newline_index = (*t_ctx)->newline_index;
		(*t_ctx)->prev_newline_frame = result.frame;
		(*t_ctx)->lines++;

		struct index_entrier_return_val ret = {.entry = entry, .advance_n = diff, .has_index_entry = true};
		return ret;
	} else {
		if (result.decompressed_bytes_remaining >= 0) {
			slice_append_n(line_buf, decompressed_data_ptr, result.decompressed_bytes_remaining);
		}
		struct index_entrier_return_val ret = {.advance_n = result.decompressed_bytes_remaining};
		return ret;
	}
}

size_t index_entrier_line_entry_init(void **entrier_ctx) {
	struct index_entrier_line_entry_ctx **t_ctx = (struct index_entrier_line_entry_ctx **)entrier_ctx;
	if (t_ctx == NULL) {
		return 0;
	}
	if (*t_ctx == NULL) {
		*t_ctx = malloc(sizeof(struct index_entrier_line_entry_ctx));
		if (*t_ctx == NULL) {
			fprintf(stderr, "malloc() ctx failed!\n");
			return 0;
		}
	}
	memset(*t_ctx, 0, sizeof(struct index_entrier_line_entry_ctx));
	if ((*t_ctx)->line_buf == NULL) {
		(*t_ctx)->line_buf = slice_char_new(1 * 1024 * 1024, 0);
		if ((*t_ctx)->line_buf == NULL) {
			fprintf(stderr, "Slice *line_buf = slice_char_new() failed!\n");
			return 0;
		}
	}
	(*t_ctx)->newline_index = -1;
	(*t_ctx)->last_d_offset = -1;
	(*t_ctx)->index_mode = 0 | FRAME_SIZE_FLAG_MASK | OFFSET_WITHIN_FRAME_FLAG_MASK;
	return 1;
}

size_t index_entrier_line_entry_reset_before_next_frame(void **entrier_ctx) {
	struct index_entrier_line_entry_ctx **t_ctx = (struct index_entrier_line_entry_ctx **)entrier_ctx;
	(*t_ctx)->prev_newline_index = 0;
	return 1;
}

void index_entrier_line_entry_free(void **entrier_ctx) {
	struct index_entrier_line_entry_ctx **t_ctx = (struct index_entrier_line_entry_ctx **)entrier_ctx;
	if (*t_ctx != NULL) {
		if ((*t_ctx)->line_buf != NULL) {
			slice_free((*t_ctx)->line_buf);
		}
		free(*t_ctx);
		*t_ctx = NULL;
	}
}

struct index_entrier_package newline_entrier_create_package() {
	return (struct index_entrier_package){
	    .entrier = index_entrier_line_entry,
	    .init = index_entrier_line_entry_init,
	    .reset_before_next_frame = index_entrier_line_entry_reset_before_next_frame,
	    .reset_before_next_local_iter = NULL,
	    .free = index_entrier_line_entry_free};
}

static void inline zero_fill(u8 *arr, size_t len) {
	memset(arr, 0, len);
}

struct radix_sort_item_key {
	u8 *key;
	size_t size;
};

struct radix_sort_args {
	void *arr;
	size_t rows;
	size_t elem_size;
	size_t cols;
	struct radix_sort_item_key (*arr_key)(void *item, size_t idx);
};

static void radix_sort_8bit_digits(struct radix_sort_args args) {
	i64 iters = 0;

	size_t cols = args.cols;

	for (int j = cols - 1; j >= 0; j--) {
		zero_fill(bucket, bucket_len);
		zero_fill(freqbucket, bucket_len);

		for (int i = 0; i < rows; i++) {
			u8 digit = arr[i * cols + j];
			freqbucket[digit]++;
		}

		memcpy(bucket, freqbucket, bucket_len);

		for (int i = 1; i < bucket_len; i++) {
			bucket[i] += bucket[i - 1];
		}

		for (int i = bucket_len - 1; i > 0; --i) {
			bucket[i] = bucket[i - 1];
			if (i == 1) {
				bucket[i - 1] = 0;
			}
		}

		int row = 0;
		for (int i = 0; i < bucket_len; i++) {
			u8 freq = freqbucket[i];
			while (freq > 0) {
				arr[row * cols + j] = i;
				freq--;
				row++;
			}
		}
	}
}

int build_index_main(int argc, char **argv) {
	char *infile = NULL;
	char *outfile = NULL;

	static struct option long_options[] = {
	    {"infile", required_argument, 0, 'i'},
	    {"outfile", required_argument, 0, 'o'},
	    {"help", no_argument, 0, 'h'},
	    {0, 0, 0, 0}};

	while (1) {
		int c = getopt_long(argc, argv, "i:o:vh", long_options, NULL);
		if (c == -1) break;

		switch (c) {
		case 'i':
			infile = optarg;
			break;
		case 'o':
			outfile = optarg;
			break;
		case 'h':
			printf("Usage: %s [options]\n", argv[0]);
			printf("Options:\n");
			printf("  -i, --infile FILE     Pairs file\n");
			printf("  -o, --outfile FILE    Index output file\n");
			printf("  -h, --help            Show this help\n");
			return 0;
		case '?':
			return 1;
		}
	}

	if (!infile || !outfile) {
		fprintf(stderr, "No input or output file specified\n");
		return 1;
	}

	FILE *fin = fopen_orDie(infile, "rb");
	struct stat st;
	if (fstat(fileno(fin), &st) != 0) {
		printf("Failed to stat file: %s\n", strerror(errno));
		return 1;
	}

	ZSTD_seekable *const seekable = ZSTD_seekable_create();
	if (seekable == NULL) {
		fprintf(stderr, "ZSTD_seekable_create() error \n");
		exit(10);
	}

	u8 *fin_mmap = mmap_or_die(fin, st.st_size);
	size_t const zstd_init_buf_ret = ZSTD_seekable_initBuff(seekable, fin_mmap, st.st_size);
	if (ZSTD_isError(zstd_init_buf_ret)) {
		fprintf(stderr, "ZSTD_seekable_init() error : %s \n", ZSTD_getErrorName(zstd_init_buf_ret));
		exit(11);
	}

	FILE *fout = fopen_orDie(outfile, "wb");

	size_t const buff_in_size = ZSTD_DStreamInSize();
	void *buf_in = malloc_orDie(buff_in_size);
	size_t const buf_out_size = ZSTD_DStreamOutSize();
	void *buf_out = malloc_orDie(buf_out_size);

	int ret = 0;

	size_t groups_entries_count = 0;
	// Calculate how many entries that can fit in 1 GB of memory
	size_t group_max_entries = (1024 * 1024 * 1024) / sizeof(struct index_entry);
	Slice *group_entries = slice_new(group_max_entries, 0, sizeof(struct index_entry));
	if (group_entries == NULL) {
		fprintf(stderr, "Slice *group_entries = slice_new failed!\n");
		ret = 1;
		goto cleanup;
	}

	struct index_group_table_entry *group_table_entries = malloc(sizeof(struct index_group_table_entry) * group_max_entries);
	if (group_table_entries == NULL) {
		fprintf(stderr, "group_table_entries = malloc failed!\n");
		ret = 1;
		goto cleanup;
	}
	u64 group_table_entries_count = 0;

	u8 index_mode = 0 | FRAME_SIZE_FLAG_MASK | OFFSET_WITHIN_FRAME_FLAG_MASK;

	struct index_entrier_line_entry_ctx *entrier_ctx = NULL;
	struct index_entrier_package entrier_package = newline_entrier_create_package();
	if (entrier_package.init != NULL) {
		if (!entrier_package.init((void **)&entrier_ctx)) {
			fprintf(stderr, "entrier_package.init() failed!\n");
			ret = 1;
			goto cleanup;
		}
	}

	struct index_header idx_hdr = create_index_header(false);

	unsigned num_frames = ZSTD_seekable_getNumFrames(seekable);
	if (num_frames > 0) {
		if (!write_index_header(fout, idx_hdr)) {
			fprintf(stderr, "write_index_header() failed!\n");
			ret = 1;
			goto cleanup;
		}
	}

	for (unsigned i = 0; i < num_frames; i++) {
		unsigned long long c_offset = ZSTD_seekable_getFrameCompressedOffset(seekable, i);
		unsigned long long d_offset = ZSTD_seekable_getFrameDecompressedOffset(seekable, i);
		size_t c_size = ZSTD_seekable_getFrameCompressedSize(seekable, i);
		size_t d_size = ZSTD_seekable_getFrameDecompressedSize(seekable, i);

		size_t start_off = d_offset;
		size_t end_off = d_offset + d_size;
		while (start_off < end_off) {
			size_t result = ZSTD_seekable_decompress(seekable, buf_out, min(end_off - start_off, buf_out_size), start_off);

			if (!result) {
				break;
			}
			if (ZSTD_isError(result)) {
				fprintf(stderr, "ZSTD_seekable_decompress() error : %s \n",
				        ZSTD_getErrorName(result));
				exit(12);
			}

			struct decompressed_frame_result dfr = {
			    .frame = i,
			    .c_offset = c_offset,
			    .c_size = c_size,
			    .d_offset = d_offset,
			    .d_size = d_size,
			    .decompressed_bytes = result,
			    .decompressed_bytes_remaining = result,
			    .decompressed_data = buf_out,
			    .decompressed_data_ptr = buf_out,
			};

			do {
				struct index_entrier_return_val entrier_retval = entrier_package.entrier(dfr, (void **)&entrier_ctx);
				if (entrier_retval.has_index_entry) {
					// indices++;
					if (slice_get_len(group_entries) == group_max_entries) {
						slice_reset(group_entries);
					}
					if (!slice_append(group_entries, &entrier_retval.entry)) {
						fprintf(stderr, "slice_append() failed!\n");
						ret = 1;
						goto cleanup;
					}
					// if (!write_index_entry(fout, index_mode, idx_hdr, entrier_retval.entry)) {
					// 	fprintf(stderr, "write_index() failed!\n");
					// 	ret = 1;
					// 	goto cleanup;
					// }
				}
				// if (indices % 1000000 == 0) {
				// 	fprintf(stderr, "Created %lld indices\n", indices);
				// }
				if (entrier_retval.advance_n <= 0) {
					break;
				}
				dfr.decompressed_data_ptr += entrier_retval.advance_n;
				dfr.decompressed_bytes_remaining -= entrier_retval.advance_n;
			} while (true);

			if (entrier_package.reset_before_next_frame != NULL) {
				if (!entrier_package.reset_before_next_frame((void **)&entrier_ctx)) {
					fprintf(stderr, "entrier_package.reset_before_next_frame() failed!\n");
					ret = 1;
					goto cleanup;
				}
			}

			start_off += result;
		}
	}

	// if (!write_index_footer(fout, idx_hdr, indices)) {
	// 	fprintf(stderr, "write_index_footer() failed!\n");
	// 	ret = 1;
	// 	goto cleanup;
	// }

cleanup:
	munmap(fin_mmap, st.st_size);
	if (entrier_ctx != NULL && entrier_package.free != NULL) {
		entrier_package.free((void **)&entrier_ctx);
	}
	ZSTD_seekable_free(seekable);
	free(buf_in);
	free(buf_out);
	return ret;
}
