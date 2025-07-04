#define _POSIX_C_SOURCE 200809L
#include <argp.h>
#include <errno.h>
#include <error.h>
#include <stdbool.h>
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
int print_offset_content_pair(int argc, char **argv);
int decompress_frame_main(int argc, char **argv);

struct subcommand {
	const char *name;
	int (*func)(int argc, char **argv);
	const char *description;
};

static struct subcommand subcommands[] = {
    {"compress", compress_main, "Compress files"},
    {"write-pairs", write_pairs_main, "Write pairs"},
    {"print-offset-content-pair", print_offset_content_pair, "Print offset content pairs from stdin"},
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

int process_frame(void *buf, size_t buf_size, int *frames, int num_of_frames, size_t start_offset, size_t end_offset) {}

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
		fprintf(stderr, "Invalid frame index: %d\n", frame_index);
		return 1;
	}
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

// Implement streaming read.
int print_offset_content_pair_broken(int argc, char **argv) {
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
	size_t buf_size = 1024;
	// if (fin != stdin) {
	//     struct stat st;
	//     if (fstat(fileno(fin), &st) != 0) {
	//         printf("Failed to stat file: %s\n", strerror(errno));
	//         return 1;
	//     }
	//     buf_size = st.st_size;
	// }
	char *buf = malloc(buf_size);
	if (buf == NULL) {
		fprintf(stderr, "malloc() buf failed!\n");
		return 1;
	}
	char *bufptr = buf;
	ssize_t read = 0;
	size_t prev_content_read_remaining = 0;
	bool prev_hdr_incomplete = false;
	size_t prev_hdr_remaining = 0;
	void *hdr_buf = malloc(sizeof(struct offset_content_pair));
	if (hdr_buf == NULL) {
		fprintf(stderr, "malloc() hdr_buf failed!\n");
		return 1;
	}
	u64 frame_count = 0;
	while ((read = fread_orDie(buf, buf_size, fin))) {
		bufptr = buf;
		while (read > 0) {
			if (prev_hdr_incomplete) {
				printf("print_hdr_incomplete\n");
				size_t copy_start_offset = sizeof(struct offset_content_pair) - prev_hdr_remaining;
				if (read >= prev_hdr_remaining) {
					printf("read >= prev_hdr_remaining\n");
					memcpy(hdr_buf + copy_start_offset, bufptr, prev_hdr_remaining);
					bufptr += prev_hdr_remaining;
					read -= prev_hdr_remaining;
					prev_hdr_incomplete = false;
				} else {
					printf("read < prev_hdr_remaining\n");
					memcpy(hdr_buf + copy_start_offset, bufptr, read);
					prev_hdr_remaining -= read;
					read = 0;
					continue;
				}
			} else {
				if (prev_content_read_remaining > 0) {
					printf("prev_content_read_remaining > 0\n");

					if (prev_content_read_remaining <= read) {
						printf("prev_content_read_remaining <= read\n");
						// fwrite(bufptr, 1, prev_content_read_remaining, stdout);
						bufptr += prev_content_read_remaining;
						read -= prev_content_read_remaining;
						prev_content_read_remaining = 0;
					} else {
						printf("prev_content_read_remaining > read\n");
						// fwrite(bufptr, 1, read, stdout);
						prev_content_read_remaining -= read;
						continue;
					}
				}

				// Tries to find magic number
				u32 magic = 0;
				do {
					memcpy(&magic, bufptr, sizeof(u32));
					if (magic == OFFSET_CONTENT_PAIR_MAGIC) {
						frame_count++;
						bufptr += sizeof(u32);
						read -= sizeof(u32);
						break;
					}
					bufptr++;
					read--;
				} while (read > 0);

				// buffer exhausted but still haven't found magic number
				// TODO: implement partial magic number handling
				if (magic != OFFSET_CONTENT_PAIR_MAGIC) {
					printf("read == 0 && magic != OFFSET_CONTENT_PAIR_MAGIC\n");
					continue;
				}

				if (read >= sizeof(struct offset_content_pair)) {
					printf("read >= sizeof(struct offset_content_pair)\n");
					prev_hdr_incomplete = false;
					struct offset_content_pair *pair = (struct offset_content_pair *)(bufptr - 4);
					bufptr += (sizeof(struct offset_content_pair) - sizeof(u32));
					read -= (sizeof(struct offset_content_pair) - sizeof(u32));
					if (read < pair->content_length) {
						printf("raed < pair->content_length\n");
						// fwrite(bufptr, 1, read, stdout);
						prev_content_read_remaining = pair->content_length - read;
						read = 0;
						continue;
					} else {
						printf("read >= pair->content_length\n");
						// fwrite(bufptr, 1, pair->content_length, stdout);
						bufptr += pair->content_length;
						read -= pair->content_length;
					}
				} else {
					printf("read < sizeof(struct offset_content_pair)\n");
					prev_hdr_incomplete = true;
					prev_hdr_remaining = sizeof(struct offset_content_pair) - read;
					memcpy(hdr_buf, bufptr, read);
					read = 0;
				}
			}
		}
	}
	free(buf);
}

int print_offset_content_pair(int argc, char **argv) {
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
	size_t buf_size = 1024;
	char *buf = malloc(buf_size);
	if (buf == NULL) {
		fprintf(stderr, "malloc() buf failed!\n");
		if (fin != stdin) fclose(fin);
		return 1;
	}

	char *bufptr = buf;
	ssize_t read = 0;
	size_t prev_content_read_remaining = 0;
	bool prev_hdr_incomplete = false;
	size_t prev_hdr_remaining = 0;
	void *hdr_buf = malloc(sizeof(struct offset_content_pair));
	if (hdr_buf == NULL) {
		fprintf(stderr, "malloc() hdr_buf failed!\n");
		free(buf);
		if (fin != stdin) fclose(fin);
		return 1;
	}

	u32 partial_magic = 0;
	int partial_magic_bytes = 0;

	u64 frame_count = 0;

	while ((read = fread_orDie(buf, buf_size, fin))) {
		bufptr = buf;

		while (read > 0) {
			if (prev_hdr_incomplete) {
				size_t copy_start_offset = sizeof(struct offset_content_pair) - prev_hdr_remaining;
				if (read >= prev_hdr_remaining) {
					memcpy(hdr_buf + copy_start_offset, bufptr, prev_hdr_remaining);
					bufptr += prev_hdr_remaining;
					read -= prev_hdr_remaining;
					prev_hdr_incomplete = false;

					struct offset_content_pair *pair = (struct offset_content_pair *)hdr_buf;

					if (pair->content_length > 1024 * 1024 * 1024) {  // 1GB limit
						fprintf(stderr, "Content length too large: %zu\n", pair->content_length);
						goto cleanup;
					}

					if (read < pair->content_length) {
						fwrite(bufptr, 1, read, stdout);
						prev_content_read_remaining = pair->content_length - read;
						read = 0;
						continue;
					} else {
						fwrite(bufptr, 1, pair->content_length, stdout);
						bufptr += pair->content_length;
						read -= pair->content_length;
					}
				} else {
					memcpy(hdr_buf + copy_start_offset, bufptr, read);
					prev_hdr_remaining -= read;
					read = 0;
					continue;
				}
			} else if (prev_content_read_remaining > 0) {
				if (prev_content_read_remaining <= read) {
					fwrite(bufptr, 1, prev_content_read_remaining, stdout);
					bufptr += prev_content_read_remaining;
					read -= prev_content_read_remaining;
					prev_content_read_remaining = 0;
				} else {
					fwrite(bufptr, 1, read, stdout);
					prev_content_read_remaining -= read;
					read = 0;
					continue;
				}
			}

			bool found_magic = false;
			while (read > 0) {
				if (partial_magic_bytes > 0) {
					int bytes_needed = sizeof(u32) - partial_magic_bytes;
					int bytes_available = read < bytes_needed ? read : bytes_needed;

					for (int i = 0; i < bytes_available; i++) {
						partial_magic = (partial_magic << 8) | bufptr[i];
					}
					partial_magic_bytes += bytes_available;

					if (partial_magic_bytes == sizeof(u32)) {
						if (partial_magic == OFFSET_CONTENT_PAIR_MAGIC) {
							found_magic = true;
							frame_count++;
							bufptr += bytes_available;
							read -= bytes_available;
							partial_magic_bytes = 0;
							break;
						} else {
							partial_magic_bytes = 0;
						}
					} else {
						bufptr += bytes_available;
						read -= bytes_available;
						continue;
					}
				}

				if (read >= sizeof(u32)) {
					u32 magic;
					memcpy(&magic, bufptr, sizeof(u32));
					if (magic == OFFSET_CONTENT_PAIR_MAGIC) {
						found_magic = true;
						frame_count++;
						bufptr += sizeof(u32);
						read -= sizeof(u32);
						break;
					}
					bufptr++;
					read--;
				} else {
					partial_magic = 0;
					for (int i = 0; i < read; i++) {
						partial_magic = (partial_magic << 8) | bufptr[i];
					}
					partial_magic_bytes = read;
					read = 0;
					break;
				}
			}

			if (!found_magic) {
				continue;
			}

			if (read >= sizeof(struct offset_content_pair) - sizeof(u32)) {
				struct offset_content_pair *pair = (struct offset_content_pair *)(bufptr - sizeof(u32));
				bufptr += (sizeof(struct offset_content_pair) - sizeof(u32));
				read -= (sizeof(struct offset_content_pair) - sizeof(u32));

				if (pair->content_length > 1024 * 1024 * 1024) {  // 1GB limit
					fprintf(stderr, "Content length too large: %zu\n", pair->content_length);
					goto cleanup;
				}

				if (read < pair->content_length) {
					fwrite(bufptr, 1, read, stdout);
					prev_content_read_remaining = pair->content_length - read;
					read = 0;
					continue;
				} else {
					fwrite(bufptr, 1, pair->content_length, stdout);
					bufptr += pair->content_length;
					read -= pair->content_length;
				}
			} else {
				prev_hdr_incomplete = true;
				prev_hdr_remaining = sizeof(struct offset_content_pair) - sizeof(u32) - read;

				memcpy(hdr_buf, bufptr - sizeof(u32), sizeof(u32));
				memcpy(hdr_buf + sizeof(u32), bufptr, read);
				read = 0;
			}
		}
	}

cleanup:
	free(buf);
	free(hdr_buf);
	if (fin != stdin) fclose(fin);
	return 0;
}