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

void stringify_bits(u8 byte, char *result) {
	for (int bit = 0; bit < (sizeof(u8) * 8); bit++) {
		memcpy(result, (byte & 0x01) ? "1" : "0", 1);
		byte = byte >> 1;
		result++;
	}
}

int print_frame_header(u8 *ptr) {
	u8 *data = (u8 *)ptr;
	size_t offset = 0;

	u32 magic;
	memcpy(&magic, data + offset, sizeof(u32));
	offset += sizeof(u32);  // 4 byte magic

	if (magic != ZSTD_MAGICNUMBER) {
		printf("Invalid magic number\n");
		return 1;
	}
	printf("Magic: %x\n", magic);

	/* Frame header */

	/* Frame header descriptor (1 byte) */
	u8 frame_header_descriptor = data[offset++];

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
		u8 window_descriptor = data[offset++];
		printf("Window descriptor: %x\n", window_descriptor);
	}

	/* Dictionary ID (0-4 bytes) */
	if (dictionary_id_flag > 0) {
		u32 dictionary_id = 0;
		int dict_size = dictionary_id_flag;  // 1, 2, or 3 bytes
		if (dictionary_id_flag == 3) dict_size = 4;

		memcpy(&dictionary_id, data + offset, dict_size);
		offset += dict_size;
		printf("Dictionary ID: %x\n", dictionary_id);
	}

	/* Frame content size (0-8 bytes) */
	if (fcs_bytes > 0) {
		u64 frame_content_size = 0;
		memcpy(&frame_content_size, data + offset, fcs_bytes);

		if (fcs_bytes == 2) {
			frame_content_size += 256;
		}
		offset += fcs_bytes;

		printf("Frame content size: %llu\n", frame_content_size);
	} else {
		printf("Frame content size: not present\n");
	}

	if (content_checksum) {
		offset += 4;
	}

	free(fhd_bits);
	return offset;
}

int main(int argc, char *argv[]) {
	if (argc < 2) {
		printf("Usage: %s <file>\n", argv[0]);
		return 1;
	}

	FILE *f = fopen(argv[1], "rb");
	if (f == NULL) {
		printf("Failed to open file: %s\n", strerror(errno));
		return 1;
	}

	struct stat st;
	if (fstat(fileno(f), &st) != 0) {
		printf("Failed to stat file: %s\n", strerror(errno));
		return 1;
	}

	char *ptr = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fileno(f), 0);
	if (ptr == MAP_FAILED) {
		printf("Failed to map file: %s\n", strerror(errno));
		return 1;
	}
	fclose(f);

	int frame_index = 0;
	// for (;;) {
	printf("------ Frame %d ------\n", frame_index);
	int offset = print_frame_header(ptr);
	printf("\n");
	// }

	return 0;
}