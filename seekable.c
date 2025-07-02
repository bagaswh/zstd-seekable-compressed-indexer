#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <error.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

#define ZSTD_MAGICNUMBER 0xFD2FB528
#define ZSTD_SEEKABLE_MAGICNUMBER 0x8F92EAB1
#define ZSTD_SEEKTABLE_FOOTER_SIZE 9

struct seek_table_entry {
	u32 compressed_size;
	u32 decompressed_size;
	u32 checksum;
};

int zstd_seekable_print_info(u8 *data, size_t file_size) {
	u8 *footer_ptr = data + file_size - ZSTD_SEEKTABLE_FOOTER_SIZE;

	u32 footer_magic;
	memcpy(&footer_magic, footer_ptr + 5, sizeof(u32));
	if (footer_magic != ZSTD_SEEKABLE_MAGICNUMBER) {
		fprintf(stderr, "Invalid footer magic number, got: %x\n", footer_magic);
		return 1;
	}

	u32 num_of_frames;
	memcpy(&num_of_frames, footer_ptr, sizeof(u32));
	printf("Number of frames: %d\n", num_of_frames);

	u8 seek_table_descriptor;
	memcpy(&seek_table_descriptor, footer_ptr + 4, sizeof(u8));

	u32 entry_size = 8;

	u8 checksum_flag = (seek_table_descriptor >> 7) & 0x1;
	if (checksum_flag) {
		printf("Checksum: enabled\n");
		entry_size += 4;
	}

	u8 *seek_table_ptr = footer_ptr - (entry_size * num_of_frames);
	struct seek_table_entry *entry = malloc(sizeof(struct seek_table_entry));
	memset(entry, 0, sizeof(struct seek_table_entry));
	for (int i = 0; i < num_of_frames; i++) {
		memcpy(entry, seek_table_ptr + i * entry_size, entry_size);
		printf("Frame %d: compressed_size: %d, decompressed_size: %d, checksum: %x\n", i, entry->compressed_size, entry->decompressed_size, entry->checksum);
	}

	free(entry);

	return 0;
}

// Find the next frame by looking for the magic number
size_t find_next_frame(u8 *data, size_t start, size_t file_size) {
	for (size_t i = start; i <= file_size - 4; i++) {
		u32 magic;
		memcpy(&magic, data + i, sizeof(u32));
		if (magic == ZSTD_MAGICNUMBER) {
			return i;
		}
	}
	return file_size;  // No more frames found
}

int main(int argc, char *argv[]) {
	if (argc < 2) {
		fprintf(stderr, "Usage: %s <file>\n", argv[0]);
		return 1;
	}

	FILE *f = fopen(argv[1], "rb");
	if (f == NULL) {
		fprintf(stderr, "Failed to open file: %s\n", strerror(errno));
		return 1;
	}

	struct stat st;
	if (fstat(fileno(f), &st) != 0) {
		fprintf(stderr, "Failed to stat file: %s\n", strerror(errno));
		return 1;
	}

	u8 *data = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fileno(f), 0);
	if (data == MAP_FAILED) {
		fprintf(stderr, "Failed to map file: %s\n", strerror(errno));
		return 1;
	}
	fclose(f);

	zstd_seekable_print_info(data, st.st_size);

	// size_t current_pos = 0;
	// int frame_index = 0;

	// while (current_pos < st.st_size) {
	// 	if (current_pos + 4 > st.st_size) break;

	// 	u32 magic;
	// 	memcpy(&magic, data + current_pos, sizeof(u32));

	// 	if (magic != ZSTD_MAGICNUMBER) {
	// 		fprintf(stderr, "Invalid magic number at position %zu\n", current_pos);
	// 		break;
	// 	}

	// 	// Find the start of the next frame
	// 	size_t next_frame_pos = find_next_frame(data, current_pos + 4, st.st_size);
	// 	size_t frame_size = next_frame_pos - current_pos;

	// 	fprintf(stderr, "Frame %d: %zu bytes\n", frame_index, frame_size);

	// 	// Write the complete frame to stdout
	// 	// if (fwrite(data + current_pos, frame_size, 1, stdout) != 1) {
	// 	// 	fprintf(stderr, "Failed to write frame %d\n", frame_index);
	// 	// 	return 1;
	// 	// }

	// 	current_pos = next_frame_pos;
	// 	frame_index++;
	// 	// break;
	// }

	// fprintf(stderr, "Extracted %d frames\n", frame_index);
	munmap(data, st.st_size);
	return 0;
}