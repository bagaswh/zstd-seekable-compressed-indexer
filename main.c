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

#include "zstd.h"
#include "zstd_seekable.h"

typedef uint8_t u8;
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
    {"write-pairs", write_pairs_main, "Write pairs"},
    {"build-index", build_index_main, "Build index from streaming pairs"},
    // {"decompress", decompress_main, "Decompress files"},
    {"decompress-frame", decompress_frame_main, "Decompress frame"},
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

struct seek_table_entry {
	u32 compressed_size;
	u32 decompressed_size;
	u32 checksum;

	u64 compressed_end_offset;
	u64 decompressed_end_offset;
};

struct seek_table {
	u32 footer_magic;
	u32 num_of_frames;
	u8 seek_table_descriptor;
	u32 entry_size;
	u8 checksum_flag;
	struct seek_table_entry *entries;
};

#define ZSTD_MAGICNUMBER 0xFD2FB528
#define ZSTD_SEEKABLE_MAGICNUMBER 0x8F92EAB1
#define ZSTD_SEEKTABLE_FOOTER_SIZE 9

struct seek_table *load_seek_table(u8 *data, size_t file_size, struct seek_table *table) {
	u8 *footer_ptr = data + file_size - ZSTD_SEEKTABLE_FOOTER_SIZE;

	u32 footer_magic;
	memcpy(&footer_magic, footer_ptr + 5, sizeof(u32));
	if (footer_magic != ZSTD_SEEKABLE_MAGICNUMBER) {
		fprintf(stderr, "Invalid footer magic number, got: %x\n", footer_magic);
		return NULL;
	}
	table->footer_magic = footer_magic;

	u32 num_of_frames;
	memcpy(&num_of_frames, footer_ptr, sizeof(u32));
	table->num_of_frames = num_of_frames;
	table->entries = malloc(sizeof(struct seek_table_entry) * num_of_frames);
	if (table->entries == NULL) {
		fprintf(stderr, "malloc() table->entries failed!\n");
		return NULL;
	}

	u8 seek_table_descriptor;
	memcpy(&seek_table_descriptor, footer_ptr + 4, sizeof(u8));
	table->seek_table_descriptor = seek_table_descriptor;

	u32 entry_size = 8;

	u8 checksum_flag = (seek_table_descriptor >> 7) & 0x1;
	if (checksum_flag) {
		entry_size += 4;
	}
	table->entry_size = entry_size;
	table->checksum_flag = checksum_flag;

	u8 *seek_table_ptr = footer_ptr - (entry_size * num_of_frames);
	u64 last_compressed_offset = 0;
	u64 last_decompressed_offset = 0;
	for (int i = 0; i < num_of_frames; i++) {
		memcpy(&(table->entries[i]), seek_table_ptr + i * entry_size, entry_size);
		last_compressed_offset += table->entries[i].compressed_size;
		last_decompressed_offset += table->entries[i].decompressed_size;
		(&(table->entries[i]))->compressed_end_offset = last_compressed_offset;
		(&(table->entries[i]))->decompressed_end_offset = last_decompressed_offset;
	}

	return table;
}

struct print_info_args {
	bool print_seek_table;
	bool print_frames_list;
};

void zstd_seekable_print_info(u8 *data, size_t file_size, struct print_info_args args) {
	struct seek_table table;
	if (!load_seek_table(data, file_size, &table)) {
		fprintf(stderr, "load_seek_table() failed!\n");
		return;
	}

	printf("Number of frames: %d\n", table.num_of_frames);

	if (table.checksum_flag) {
		printf("Checksum: enabled\n");
	}

	if (args.print_seek_table) {
		for (int i = 0; i < table.num_of_frames; i++) {
			struct seek_table_entry entry = table.entries[i];
			size_t c_start_off = entry.compressed_end_offset - entry.compressed_size;
			size_t c_end_off = entry.compressed_end_offset;
			size_t d_start_off = entry.decompressed_end_offset - entry.decompressed_size;
			size_t d_end_off = entry.decompressed_end_offset;
			printf("Frame %d: (coffset: %ld - %ld, %ld bytes); (doffset: %ld - %ld, %ld bytes), checksum: %x\n",
			       i, c_start_off, c_end_off, c_end_off - c_start_off, d_start_off, d_end_off, d_end_off - d_start_off, entry.checksum);
		}
	}
}

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

#define MIN(a, b) ((a) < (b) ? (a) : (b))

int decompress_frame(ZSTD_seekable *seekable, void *buf_out, size_t buf_out_size, size_t start_offset, size_t end_offset) {
	size_t const result = ZSTD_seekable_decompress(seekable, buf_out, MIN(end_offset - start_offset, buf_out_size), end_offset);
	if (ZSTD_isError(result)) {
		fprintf(stderr, "ZSTD_seekable_decompress() error : %s \n",
		        ZSTD_getErrorName(result));
		exit(12);
	}
	return result;
}

int decompress_frame_main(int argc, char **argv) {
	char *infile = NULL;
	char *outfile = NULL;
	size_t frame_index = 0;
	size_t start_offset = 0;
	size_t end_offset = 0;

	static struct option long_options[] = {
	    {"infile", required_argument, 0, 'i'},
	    {"outfile", required_argument, 0, 'o'},
	    {"frame-index", required_argument, 0, 'f'},
	    {"start-offset", required_argument, 0, 's'},
	    {"end-offset", required_argument, 0, 'e'},
	    {"help", no_argument, 0, 'h'},
	    {0, 0, 0, 0}};

	while (1) {
		int c = getopt_long(argc, argv, "i:o:f:s:e:vh", long_options, NULL);
		if (c == -1) break;

		switch (c) {
		case 'i':
			infile = optarg;
			break;
		case 'o':
			outfile = optarg;
			break;
		case 'f':
			frame_index = atoi(optarg);
			break;
		case 's':
			start_offset = atoi(optarg);
			break;
		case 'e':
			end_offset = atoi(optarg);
			break;
		case 'h':
			printf("Usage: %s [options]\n", argv[0]);
			printf("Options:\n");
			printf("  -i, --infile FILE     Input file (default: stdin)\n");
			printf("  -o, --outfile FILE    Output file (default: stdout)\n");
			printf("  -f, --frame-index INT Frame index\n");
			printf("  -s, --start-offset INT Start offset\n");
			printf("  -e, --end-offset INT End offset\n");
			printf("  -h, --help            Show this help\n");
			return 0;
		case '?':
			return 1;
		}
	}

	if (frame_index == 0 && start_offset == 0 && end_offset == 0) {
		printf("Please specify at least one of the following options: --frame-index, --start-offset, --end-offset\n");
		return 1;
	}

	FILE *in = infile ? fopen_orDie(infile, "rb") : stdin;
	struct stat st;
	if (fstat(fileno(in), &st) != 0) {
		printf("Failed to stat file: %s\n", strerror(errno));
		return 1;
	}

	ZSTD_seekable *const seekable = ZSTD_seekable_create();
	if (seekable == NULL) {
		fprintf(stderr, "ZSTD_seekable_create() error \n");
		exit(10);
	}

	u8 *data = infile ? mmap_or_die(in, st.st_size) : NULL;
	size_t const zstd_init_buf_ret = ZSTD_seekable_initBuff(seekable, data, st.st_size);
	if (ZSTD_isError(zstd_init_buf_ret)) {
		fprintf(stderr, "ZSTD_seekable_init() error : %s \n", ZSTD_getErrorName(zstd_init_buf_ret));
		exit(11);
	}

	FILE *out = outfile ? fopen_orDie(outfile, "wb") : stdout;

	size_t const buff_in_size = ZSTD_DStreamInSize();
	void *buf_in = malloc_orDie(buff_in_size);
	struct seek_table table;
	if (!load_seek_table(data, st.st_size, &table)) {
		fprintf(stderr, "load_seek_table() failed!\n");
		return 1;
	}

	if (frame_index != 0 && frame_index < table.num_of_frames) {
		struct seek_table_entry entry = table.entries[frame_index];
		size_t start_off = entry.decompressed_end_offset - entry.decompressed_size;
		size_t end_off = entry.decompressed_end_offset;
		char *buf_out = malloc(end_off - start_off);
		if (buf_out == NULL) {
			fprintf(stderr, "malloc() buf_out failed!\n");
			return 1;
		}
		while (start_off < end_off) {
			size_t const result = ZSTD_seekable_decompress(seekable, buf_out, end_off - start_off, start_off);
			if (!result) {
				break;
			}
			if (ZSTD_isError(result)) {
				fprintf(stderr, "ZSTD_seekable_decompress() error : %s \n",
				        ZSTD_getErrorName(result));
				exit(12);
			}
			fwrite_orDie(buf_out, result, stdout);
			start_off += result;
		}
	} else if (frame_index != 0) {
		fprintf(stderr, "Invalid frame index: %ld\n", frame_index);
		return 1;
	}

	return 0;
}

#define OFFSET_CONTENT_PAIR_MAGIC 0x9143DCA8

struct __attribute__((packed)) offset_content_pair {
	u32 magic;
	u64 content_length;

	u64 frame_index;

	u64 compressed_start_offset;
	u64 decompressed_start_offset;
	u64 compressed_end_offset;
	u64 decompressed_end_offset;

	char content[];
};

int write_pairs_main(int argc, char **argv) {
	char *infile = NULL;
	char *outfile = NULL;

	static struct option long_options[] = {
	    {"infile", required_argument, 0, 'i'},
	    {"outfile", required_argument, 0, 'o'},
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
		case 'h':
			printf("Usage: %s [options]\n", argv[0]);
			printf("Options:\n");
			printf("  -i, --infile FILE     Compressed file to build the index from\n");
			printf("  -o, --outfile FILE    Index file output\n");
			printf("  -h, --help            Show this help\n");
			return 0;
		case '?':
			return 1;
		}
	}

	FILE *in = infile ? fopen_orDie(infile, "rb") : stdin;
	struct stat st;
	if (fstat(fileno(in), &st) != 0) {
		printf("Failed to stat file: %s\n", strerror(errno));
		return 1;
	}

	ZSTD_seekable *const seekable = ZSTD_seekable_create();
	if (seekable == NULL) {
		fprintf(stderr, "ZSTD_seekable_create() error \n");
		exit(10);
	}

	u8 *data = infile ? mmap_or_die(in, st.st_size) : NULL;
	size_t const zstd_init_buf_ret = ZSTD_seekable_initBuff(seekable, data, st.st_size);
	if (ZSTD_isError(zstd_init_buf_ret)) {
		fprintf(stderr, "ZSTD_seekable_init() error : %s \n", ZSTD_getErrorName(zstd_init_buf_ret));
		exit(11);
	}

	FILE *out = outfile ? fopen_orDie(outfile, "wb") : stdout;

	size_t const buff_in_size = ZSTD_DStreamInSize();
	void *buf_in = malloc_orDie(buff_in_size);
	struct seek_table table;
	if (!load_seek_table(data, st.st_size, &table)) {
		fprintf(stderr, "load_seek_table() failed!\n");
		return 1;
	}

	size_t const buf_out_size = ZSTD_DStreamOutSize();
	struct offset_content_pair *pair = malloc(sizeof(struct offset_content_pair) + buf_out_size);
	if (pair == NULL) {
		fprintf(stderr, "malloc() pair failed!\n");
		return 1;
	}

	pair->magic = OFFSET_CONTENT_PAIR_MAGIC;
	for (int i = 0; i < table.num_of_frames; i++) {
		pair->frame_index = i;
		pair->compressed_start_offset = table.entries[i].compressed_end_offset - table.entries[i].compressed_size;
		pair->compressed_end_offset = table.entries[i].compressed_end_offset;

		pair->decompressed_start_offset = table.entries[i].decompressed_end_offset - table.entries[i].decompressed_size;
		pair->decompressed_end_offset = table.entries[i].decompressed_end_offset;

		struct seek_table_entry entry = table.entries[i];
		size_t start_off = entry.decompressed_end_offset - entry.decompressed_size;
		size_t end_off = entry.decompressed_end_offset;
		while (start_off < end_off) {
			size_t const result = ZSTD_seekable_decompress(seekable, &(pair->content), MIN(end_off - start_off, buf_out_size), start_off);
			if (!result) {
				break;
			}
			if (ZSTD_isError(result)) {
				fprintf(stderr, "ZSTD_seekable_decompress() error : %s \n",
				        ZSTD_getErrorName(result));
				exit(12);
			}
			pair->content_length = result;
			fwrite_orDie(pair, sizeof(struct offset_content_pair) + pair->content_length, stdout);
			start_off += result;
		}
	}

	ZSTD_seekable_free(seekable);
	fclose_orDie(in);
	fclose_orDie(out);
	free(buf_in);
	free(pair);

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

int index_of_newline_scalar(char *data, size_t size) {
	if (size == 0) return -1;
	for (size_t i = 0; i < size; i++) {
		if (data[i] == '\n') {
			return i;
		}
	}
	return -1;
}

int index_of_newline_sse(char *data, size_t size) {
	if (size == 0) return -1;

	const __m128i newline_vec = _mm_set1_epi8('\n');
	size_t i = 0;

	// Process 16 bytes at a time
	for (i = 0; i <= size - 16; i += 16) {
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

int index_of_newline_avx2(char *data, size_t size) {
	if (size == 0) return -1;

	const __m256i newline_vec = _mm256_set1_epi8('\n');
	size_t i = 0;

	// Process 32 bytes at a time
	for (i = 0; i <= size - 32; i += 32) {
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

int index_of_newline_avx2_aligned(char *data, size_t size) {
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

int index_of_newline_auto(char *data, size_t size) {
	if (size < 32) {
		return index_of_newline_scalar(data, size);
	}
	if (size < 128 && check_sse4_support()) {
		return index_of_newline_sse(data, size);
	}
	if (size < 256 && check_avx2_support()) {
		return index_of_newline_avx2(data, size);
	}
	return index_of_newline_scalar(data, size);
}

struct pair_parser_ctx {
	char *data;
	char *data_ptr;
	size_t data_size;

	void *hdr_buf;

	bool prev_hdr_incomplete;
	size_t prev_hdr_remaining;
	size_t prev_content_read_remaining;
	u32 partial_magic;
	int partial_magic_bytes;
	u64 frame_count;

	void *content_buf;
	size_t content_buf_size;
	size_t content_buf_used;

	struct pair_parser_ctx *snapshots;
	size_t snapshots_buffer_size;
	size_t snapshot_count;
};

void __attribute__((always_inline)) pair_parser_printf(struct pair_parser_ctx *ctx, FILE *out, char *format, ...) {
#if DEBUG
	va_list args;
	char *myfmt = "[pair_parser_ctx] data_size=%zu prev_hdr_incomplete=%d prev_hdr_remaining=%zu partial_magic=%x partial_magic_bytes=%d frame_count=%ld content_buf_used=%zu content_buf_size=%zu ";
	char *fmt = malloc(strlen(format) + strlen(myfmt) + 1);
	strcpy(fmt, myfmt);
	strcat(fmt, format);
	va_start(args, format);
	fprintf(out, myfmt,
	        ctx->data_size,
	        ctx->prev_hdr_incomplete,
	        ctx->prev_hdr_remaining,
	        ctx->partial_magic,
	        ctx->partial_magic_bytes,
	        ctx->frame_count,
	        ctx->content_buf_used,
	        ctx->content_buf_size);
	vfprintf(out, format, args);
	va_end(args);
	free(fmt);
#endif
}

void __attribute__((always_inline)) pair_parser_debug(struct pair_parser_ctx *ctx, char *format, ...) {
#if DEBUG
	va_list args;
	va_start(args, format);
	char buffer[1024];
	vsnprintf(buffer, sizeof(buffer), format, args);
	va_end(args);
	pair_parser_printf(ctx, stderr, "%s", buffer);
#endif
}

struct pair_parser_ctx __attribute__((always_inline)) * snapshot_state(struct pair_parser_ctx *ctx) {
#if false
	if (ctx->snapshots == NULL) {
		return NULL;
	}

	struct pair_parser_ctx *new_ctx = malloc(sizeof(struct pair_parser_ctx));
	if (new_ctx == NULL) {
		return NULL;
	}

	memcpy(new_ctx, ctx, sizeof(struct pair_parser_ctx));

	if (ctx->content_buf != NULL && ctx->content_buf_size > 0) {
		new_ctx->content_buf = malloc(ctx->content_buf_size);
		if (new_ctx->content_buf == NULL) {
			free(new_ctx);
			return NULL;
		}
		memcpy(new_ctx->content_buf, ctx->content_buf, ctx->content_buf_used);
	}

	if (ctx->hdr_buf != NULL) {
		new_ctx->hdr_buf = malloc(sizeof(struct offset_content_pair));
		if (new_ctx->hdr_buf == NULL) {
			free(new_ctx->content_buf);
			free(new_ctx);
			return NULL;
		}
		memcpy(new_ctx->hdr_buf, ctx->hdr_buf, sizeof(struct offset_content_pair));
	}

	if (ctx->data != NULL && ctx->data_size > 0) {
		new_ctx->data = malloc(ctx->data_size);
		if (new_ctx->data == NULL) {
			free(new_ctx->content_buf);
			free(new_ctx->hdr_buf);
			free(new_ctx);
			return NULL;
		}
		memcpy(new_ctx->data, ctx->data, ctx->data_size);
		new_ctx->data_ptr = new_ctx->data + (ctx->data_ptr - ctx->data);
	}

	new_ctx->snapshots = NULL;
	new_ctx->snapshots_buffer_size = 0;
	new_ctx->snapshot_count = 0;

	if (ctx->snapshots_buffer_size < ctx->snapshot_count + 1) {
		ctx->snapshots_buffer_size = ctx->snapshot_count + 1;
		ctx->snapshots = realloc(ctx->snapshots, ctx->snapshots_buffer_size * sizeof(struct pair_parser_ctx));
		if (ctx->snapshots == NULL) {
			fprintf(stderr, "realloc() snapshots failed!\n");
			free(new_ctx->content_buf);
			free(new_ctx->hdr_buf);
			free(new_ctx->data);
			free(new_ctx);
			return NULL;
		}
	}

	memcpy(&ctx->snapshots[ctx->snapshot_count], new_ctx, sizeof(struct pair_parser_ctx));
	ctx->snapshot_count++;

	return new_ctx;
#else
	return NULL;
#endif
}

void *realloc_content_buf(struct pair_parser_ctx *ctx, size_t size) {
	if ((ctx->content_buf_size - ctx->content_buf_used) < size) {
		size_t new_size = max(ctx->content_buf_used + size, ctx->content_buf_size * 2);
		ctx->content_buf = realloc(ctx->content_buf, new_size);
		if (ctx->content_buf == NULL) {
			fprintf(stderr, "realloc() content_buf failed!\n");
			return NULL;
		}
		ctx->content_buf_size = new_size;
	}
	return (char *)ctx->content_buf + ctx->content_buf_used;
}

int copy_to_content_buf(struct pair_parser_ctx *ctx, char *data, size_t size) {
	void *write_pos = realloc_content_buf(ctx, size);
	if (write_pos == NULL) {
		return -1;
	}
	memcpy(write_pos, data, size);
	ctx->content_buf_used += size;
	return 0;
}

struct offset_content_pair *
get_next_content_pair(struct pair_parser_ctx *ctx) {
	while (ctx->data_size > 0) {
		if (ctx->prev_hdr_incomplete) {
			pair_parser_debug(ctx, "ctx->prev_hdr_incomplete\n");

			size_t copy_start_offset = sizeof(struct offset_content_pair) - ctx->prev_hdr_remaining;
			if (ctx->data_size >= ctx->prev_hdr_remaining) {
				pair_parser_debug(ctx, "ctx->data_size >= ctx->prev_hdr_remaining\n");

				memcpy(ctx->hdr_buf + copy_start_offset, ctx->data_ptr, ctx->prev_hdr_remaining);
				ctx->data_ptr += ctx->prev_hdr_remaining;
				ctx->data_size -= ctx->prev_hdr_remaining;
				ctx->prev_hdr_incomplete = false;

				struct offset_content_pair *pair = (struct offset_content_pair *)ctx->hdr_buf;

				if (pair->content_length > 1024 * 1024 * 1024) {  // 1GB limit
					fprintf(stderr, "Content length too large: %zu\n", pair->content_length);
					return NULL;
				}

				if (ctx->data_size <= pair->content_length) {
					pair_parser_debug(ctx, "ctx->data_size <= pair->content_length\n");

					if (copy_to_content_buf(ctx, ctx->data_ptr, ctx->data_size) != 0) {
						return NULL;
					}
					ctx->data_ptr += ctx->data_size;
					ctx->prev_content_read_remaining = pair->content_length - ctx->data_size;
					ctx->data_size = 0;
				} else {
					pair_parser_debug(ctx, "ctx->data_size > pair->content_length\n");

					if (copy_to_content_buf(ctx, ctx->data_ptr, pair->content_length) != 0) {
						return NULL;
					}
					ctx->data_ptr += pair->content_length;
					ctx->data_size -= pair->content_length;
					snapshot_state(ctx);
					// Full pair, no content. Content is read from ctx->content_buf
					return pair;
				}
			} else {
				pair_parser_debug(ctx, "ctx->data_size <= pair->content_length\n");

				memcpy(ctx->hdr_buf + copy_start_offset, ctx->data_ptr, ctx->data_size);
				ctx->prev_hdr_remaining -= ctx->data_size;
				ctx->data_size = 0;
				continue;
			}
		} else if (ctx->prev_content_read_remaining > 0) {
			pair_parser_debug(ctx, "ctx->prev_content_read_remaining > 0\n");

			if (ctx->prev_content_read_remaining <= ctx->data_size) {
				pair_parser_debug(ctx, "ctx->prev_content_read_remaining <= ctx->data_size\n");

				if (copy_to_content_buf(ctx, ctx->data_ptr, ctx->prev_content_read_remaining) != 0) {
					return NULL;
				}
				ctx->data_ptr += ctx->prev_content_read_remaining;
				ctx->data_size -= ctx->prev_content_read_remaining;
				ctx->prev_content_read_remaining = 0;
				snapshot_state(ctx);
				return (struct offset_content_pair *)ctx->data_ptr;
			} else {
				pair_parser_debug(ctx, "ctx->prev_content_read_remaining > ctx->data_size\n");

				if (copy_to_content_buf(ctx, ctx->data_ptr, ctx->data_size) != 0) {
					return NULL;
				}
				ctx->prev_content_read_remaining -= ctx->data_size;
				ctx->data_size = 0;
				snapshot_state(ctx);
				continue;
			}
		}

		// Search magic number
		bool found_magic = false;
		while (ctx->data_size > 0) {
			if (ctx->partial_magic_bytes > 0) {
				pair_parser_debug(ctx, "ctx->partial_magic_bytes > 0\n");

				int bytes_needed = sizeof(u32) - ctx->partial_magic_bytes;
				int bytes_available = ctx->data_size < bytes_needed ? ctx->data_size : bytes_needed;

				for (int i = 0; i < bytes_available; i++) {
					ctx->partial_magic = (ctx->partial_magic << 8) | ctx->data_ptr[i];
				}
				ctx->partial_magic_bytes += bytes_available;

				if (ctx->partial_magic_bytes == sizeof(u32)) {
					pair_parser_debug(ctx, "ctx->partial_magic_bytes == sizeof(u32)\n");

					if (ctx->partial_magic == OFFSET_CONTENT_PAIR_MAGIC) {
						found_magic = true;
						ctx->frame_count++;
						ctx->data_ptr += bytes_available;
						ctx->data_size -= bytes_available;
						ctx->partial_magic_bytes = 0;
						break;
					} else {
						ctx->partial_magic_bytes = 0;
					}
				} else {
					pair_parser_debug(ctx, "ctx->partial_magic_bytes != sizeof(u32)\n");

					ctx->data_ptr += bytes_available;
					ctx->data_size -= bytes_available;
					continue;
				}
			}

			if (ctx->data_size >= sizeof(u32)) {
				pair_parser_debug(ctx, "ctx->data_size >= sizeof(u32)\n");

				u32 magic;
				memcpy(&magic, ctx->data_ptr, sizeof(u32));
				if (magic == OFFSET_CONTENT_PAIR_MAGIC) {
					found_magic = true;
					ctx->frame_count++;
					ctx->data_ptr += sizeof(u32);
					ctx->data_size -= sizeof(u32);
					break;
				}
				ctx->data_ptr++;
				ctx->data_size--;
			} else {
				pair_parser_debug(ctx, "ctx->data_size < sizeof(u32)\n");
				ctx->partial_magic = 0;
				for (int i = 0; i < ctx->data_size; i++) {
					ctx->partial_magic = (ctx->partial_magic << 8) | ctx->data_ptr[i];
				}
				ctx->partial_magic_bytes = ctx->data_size;
				ctx->data_size = 0;
				break;
			}
		}

		if (!found_magic) {
			pair_parser_debug(ctx, "has not found magic after allat\n");
			continue;
		}

		// Check if we read more than the header length
		if (ctx->data_size >= sizeof(struct offset_content_pair) - sizeof(u32)) {
			pair_parser_debug(ctx, "ctx->data_size >= sizeof(struct offset_content_pair) - sizeof(u32)\n");

			memcpy(ctx->hdr_buf, ctx->data_ptr, sizeof(u32));
			struct offset_content_pair *pair = (struct offset_content_pair *)(ctx->data_ptr - sizeof(u32));
			ctx->data_ptr += (sizeof(struct offset_content_pair) - sizeof(u32));
			ctx->data_size -= (sizeof(struct offset_content_pair) - sizeof(u32));

			if (pair->content_length > 1024 * 1024 * 1024) {  // 1GB limit
				fprintf(stderr, "Content length too large: %zu\n", pair->content_length);
				snapshot_state(ctx);
				return NULL;
			}

			if (ctx->data_size < pair->content_length) {
				pair_parser_debug(ctx, "ctx->data_size < pair->content_length\n");

				if (copy_to_content_buf(ctx, ctx->data_ptr, ctx->data_size) != 0) {
					return NULL;
				}
				ctx->prev_content_read_remaining = pair->content_length - ctx->data_size;
				ctx->data_size = 0;
				snapshot_state(ctx);
				continue;
			} else {
				pair_parser_debug(ctx, "ctx->data_size >= pair->content_length\n");

				if (copy_to_content_buf(ctx, ctx->data_ptr, pair->content_length) != 0) {
					return NULL;
				}
				ctx->data_ptr += pair->content_length;
				ctx->data_size -= pair->content_length;
				snapshot_state(ctx);
				return pair;
			}
		} else {
			pair_parser_debug(ctx, "ctx->data_size < sizeof(struct offset_content_pair) - sizeof(u32)\n");

			ctx->prev_hdr_incomplete = true;
			ctx->prev_hdr_remaining = sizeof(struct offset_content_pair) - sizeof(u32) - ctx->data_size;

			memcpy(ctx->hdr_buf, ctx->data_ptr - sizeof(u32), sizeof(u32));
			memcpy(ctx->hdr_buf + sizeof(u32), ctx->data_ptr, ctx->data_size);
			ctx->data_size = 0;
		}
	}

	return NULL;
}

int build_index_main(int argc, char **argv) {
	char *infile = NULL;
	char *outfile = NULL;

	static struct option long_options[] = {
	    {"infile", required_argument, 0, 'i'},
	    {"help", no_argument, 0, 'h'},
	    {0, 0, 0, 0}};

	while (1) {
		int c = getopt_long(argc, argv, "i:vh", long_options, NULL);
		if (c == -1) break;

		switch (c) {
		case 'i':
			infile = optarg;
			break;
		case 'h':
			printf("Usage: %s [options]\n", argv[0]);
			printf("Options:\n");
			printf("  -i, --infile FILE     Compressed file to build the index from\n");
			printf("  -h, --help            Show this help\n");
			return 0;
		case '?':
			return 1;
		}
	}

	FILE *fin = infile ? fopen_orDie(infile, "rb") : stdin;
	struct stat st;
	if (fstat(fileno(fin), &st) != 0) {
		printf("Failed to stat file: %s\n", strerror(errno));
		return 1;
	}

	struct index_entry *index = malloc(1024);
	size_t prev_newline_offset = 0;
	size_t prev_newline_frame = 0;
	free(index);

	struct pair_parser_ctx ctx;
	memset(&ctx, 0, sizeof(ctx));

	struct pair_parser_ctx *snapshots = malloc(sizeof(struct pair_parser_ctx));
	if (snapshots == NULL) {
		fprintf(stderr, "malloc() snapshots failed!\n");
		return 1;
	}
	memset(snapshots, 0, sizeof(struct pair_parser_ctx));
	ctx.snapshots = snapshots;

	size_t buf_size = 10 * 1024 * 1024;
	// size_t buf_size = st.st_size;
	ctx.data = malloc_orDie(buf_size);

	ctx.hdr_buf = malloc_orDie(sizeof(struct offset_content_pair));

	size_t content_buf_size = buf_size;
	ctx.content_buf = malloc_orDie(content_buf_size);
	ctx.content_buf_size = content_buf_size;

	char *orig_file = "humongous_file.txt";
	FILE *orig_file_fin = fopen(orig_file, "r");
	if (orig_file_fin == NULL) {
		fprintf(stderr, "Failed to open file: %s\n", orig_file);
		return 1;
	}
	char *orig_file_data = malloc(4096);

	// char *content_str = malloc(4096);
	// size_t content_str_size = 4096;
	while ((ctx.data_size = fread_orDie(ctx.data, buf_size, fin))) {
		ctx.data_ptr = ctx.data;

		while (ctx.data_size > 0) {
			struct offset_content_pair *pair = get_next_content_pair(&ctx);
			if (pair == NULL) {
				break;
			}
			int n = fread(orig_file_data, pair->content_length, 1, orig_file_fin);
			if (memcmp(ctx.content_buf, orig_file_data, pair->content_length) != 0) {
				pair_parser_debug(&ctx, "Content mismatch on frame %ld, content length: %ld\n", pair->frame_index, pair->content_length);
				fprintf(stdout, "\n----- Original file content -----\n");
				fwrite(orig_file_data, pair->content_length, 1, stdout);
				fprintf(stdout, "\n\n----- Current file content -----\n\n");
				fwrite(ctx.content_buf, pair->content_length, 1, stdout);
				fprintf(stdout, "FIN\n");
				return 1;
			}

			// dump parser state
			// fprintf(stdout, "----- Parser states leading up to this mismatch -----\n");
			// for (int i = 0; i < ctx.snapshot_count; i++) {
			// struct pair_parser_ctx snapshot = ctx.snapshots[i];
			// fprintf(stdout, "Snapshot %d:\n", i);
			// fprintf(stdout, "data_size: %zu\n", snapshot.data_size);
			// fprintf(stdout, "data_ptr: %p\n", snapshot.data_ptr);
			// fprintf(stdout, "prev_hdr_incomplete: %d\n", snapshot.prev_hdr_incomplete);
			// fprintf(stdout, "prev_hdr_remaining: %zu\n", snapshot.prev_hdr_remaining);
			// fprintf(stdout, "partial_magic: %x\n", snapshot.partial_magic);
			// fprintf(stdout, "partial_magic_bytes: %d\n", snapshot.partial_magic_bytes);
			// fprintf(stdout, "frame_count: %ld\n", snapshot.frame_count);
			// fprintf(stdout, "content_buf_used: %zu\n", snapshot.content_buf_used);
			// fprintf(stdout, "content_buf_size: %zu\n", snapshot.content_buf_size);
			// fprintf(stdout, "\n");
			// }

			// fprintf(stderr, "Content mismatch\n");

			// return 1;
			// }
			// fwrite(ctx.content_buf, pair->content_length, 1, stdout);
			// fwrite(ctx.content_buf, pair->content_length, 1, stdout);
			// // if (pair->content_length > content_str_size + 1) {
			// // 	content_str_size = pair->content_length + 1;
			// // 	content_str = realloc(content_str, content_str_size);
			// // }
			// // memcpy(content_str, pair->content, pair->content_length);
			// // content_str[pair->content_length] = '\0';
			// // printf("%s\n", content_str);
			// return 0;
			ctx.content_buf_used = 0;
			fwrite(ctx.content_buf, pair->content_length, 1, stdout);
		}
	}

cleanup:
	free(ctx.data);
	free(ctx.hdr_buf);
	free(ctx.content_buf);
	if (fin != stdin) fclose(fin);
	return 0;
}