#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// Sample text patterns for variety
const char* words[] = {
    "the", "quick", "brown", "fox", "jumps", "over", "lazy", "dog",
    "hello", "world", "computer", "science", "programming", "language",
    "data", "structure", "algorithm", "memory", "processor", "system",
    "network", "database", "software", "hardware", "application", "program",
    "function", "variable", "constant", "buffer", "pointer", "array",
    "string", "integer", "float", "double", "character", "boolean",
    "process", "thread", "mutex", "semaphore", "socket", "protocol",
    "interface", "implementation", "abstraction", "encapsulation", "inheritance",
    "polymorphism", "recursion", "iteration", "optimization", "performance"};

const char* sentences[] = {
    "This is line number %lld in our humongous file.",
    "The current timestamp is %ld and we're still generating content.",
    "Lorem ipsum dolor sit amet, consectetur adipiscing elit line %lld.",
    "Programming in C is fun, especially when creating large files at line %lld.",
    "Data processing requires efficient algorithms, now at line %lld.",
    "Memory management is crucial in systems programming - line %lld.",
    "Network protocols enable communication between systems at line %lld.",
    "Database optimization techniques improve query performance at line %lld.",
    "Software engineering principles guide development practices at line %lld.",
    "System architecture design considerations for scalability at line %lld."};

typedef enum {
	MODE_RANDOM,
	MODE_FIXED_LENGTH
} generation_mode_t;

void print_progress(long long current, long long total) {
	if (current % 100000 == 0) {
		fprintf(stderr, "Progress: %.2f%% (%lld/%lld lines)\n",
		        (double)current / total * 100, current, total);
		fflush(stderr);
	}
}

void generate_random_line(FILE* fp, long long line_num) {
	// Generate a single line with random content
	int sentence_idx = rand() % (sizeof(sentences) / sizeof(sentences[0]));
	fprintf(fp, sentences[sentence_idx], line_num);

	// Add some random words to make each line unique
	int word_count = 3 + (rand() % 15);  // 3-17 additional words
	for (int j = 0; j < word_count; j++) {
		int word_idx = rand() % (sizeof(words) / sizeof(words[0]));
		fprintf(fp, " %s", words[word_idx]);
	}
	fprintf(fp, "\n");
}

void generate_structured_line(FILE* fp, long long line_num) {
	// Generate different types of content based on line number
	int content_type = line_num % 8;

	switch (content_type) {
	case 0:  // Header section
		fprintf(fp, "=== SECTION %lld: DATA PROCESSING === Timestamp: %ld\n", line_num / 1000, time(NULL));
		break;

	case 1:  // Code-like content - function definition
		fprintf(fp, "function processData_%lld() { var result = []; return computeValue(%lld); }\n", line_num, line_num % 1000);
		break;

	case 2:  // Code-like content - loop
		fprintf(fp, "for (var i = 0; i < %lld; i++) { result.push(computeValue(i + %lld)); }\n", line_num % 100, line_num);
		break;

	case 3:  // Data table entry
		fprintf(fp, "ID:%lld\tNAME:Record_%lld\tVALUE:%.2f\tTIMESTAMP:%ld\n",
		        line_num, line_num % 1000, (double)(rand() % 10000) / 100.0, time(NULL));
		break;

	case 4:  // Log entries
		fprintf(fp, "[%ld] INFO: Processing line %lld with status: %s\n",
		        time(NULL), line_num, (line_num % 3 == 0) ? "SUCCESS" : "PENDING");
		break;

	case 5:  // System information
		fprintf(fp, "SYSTEM: Memory usage %d MB, CPU load %.1f%%, Line %lld processed\n",
		        rand() % 1024, (double)(rand() % 100), line_num);
		break;

	case 6:  // Configuration entries
		fprintf(fp, "CONFIG: parameter_%lld = %d, buffer_size = %d, enabled = %s\n",
		        line_num % 100, rand() % 256, 1024 + (rand() % 1024), (line_num % 2 == 0) ? "true" : "false");
		break;

	case 7:  // Narrative text - single line
		generate_random_line(fp, line_num);
		break;
	}
}

void generate_fixed_length_line(FILE* fp, long long line_num, int target_length) {
	char line_buffer[target_length + 1];
	char temp_buffer[target_length * 2];  // Temporary buffer for building content

	// Generate base content that varies by line number
	int content_type = line_num % 10;

	switch (content_type) {
	case 0:
		snprintf(temp_buffer, sizeof(temp_buffer), "LINE_%lld: Header section with timestamp %ld", line_num, time(NULL) + line_num);
		break;
	case 1:
		snprintf(temp_buffer, sizeof(temp_buffer), "LINE_%lld: Function definition processData_%lld returns value %d", line_num, line_num % 1000, (int)(line_num % 999) + 1);
		break;
	case 2:
		snprintf(temp_buffer, sizeof(temp_buffer), "LINE_%lld: Loop iteration from %lld to %lld with step %d", line_num, line_num % 100, (line_num % 100) + 50, (int)(line_num % 5) + 1);
		break;
	case 3:
		snprintf(temp_buffer, sizeof(temp_buffer), "LINE_%lld: Data record ID_%lld value %.2f status %s", line_num, line_num % 10000, (double)(line_num % 1000) / 10.0, (line_num % 2 == 0) ? "ACTIVE" : "INACTIVE");
		break;
	case 4:
		snprintf(temp_buffer, sizeof(temp_buffer), "LINE_%lld: Log entry timestamp %ld level %s message processing", line_num, time(NULL) + line_num, (line_num % 3 == 0) ? "INFO" : "DEBUG");
		break;
	case 5:
		snprintf(temp_buffer, sizeof(temp_buffer), "LINE_%lld: System metrics CPU %.1f%% memory %d MB disk %d GB", line_num, (double)(line_num % 100), (int)(line_num % 1024), (int)(line_num % 100) + 100);
		break;
	case 6:
		snprintf(temp_buffer, sizeof(temp_buffer), "LINE_%lld: Configuration param_%lld equals %d buffer_size %d", line_num, line_num % 50, (int)(line_num % 256), 1024 + (int)(line_num % 1024));
		break;
	case 7:
		snprintf(temp_buffer, sizeof(temp_buffer), "LINE_%lld: Network packet from %d.%d.%d.%d to %d.%d.%d.%d", line_num, (int)(line_num % 256), (int)((line_num / 256) % 256), (int)((line_num / 65536) % 256), (int)((line_num / 16777216) % 256), (int)((line_num + 1) % 256), (int)(((line_num + 1) / 256) % 256), (int)(((line_num + 1) / 65536) % 256), (int)(((line_num + 1) / 16777216) % 256));
		break;
	case 8:
		snprintf(temp_buffer, sizeof(temp_buffer), "LINE_%lld: Database query SELECT * FROM table_%lld WHERE id = %lld", line_num, line_num % 100, line_num % 10000);
		break;
	case 9:
		snprintf(temp_buffer, sizeof(temp_buffer), "LINE_%lld: Algorithm execution step %lld result %d complexity O(%d)", line_num, line_num % 1000, (int)(line_num % 999) + 1, (int)(line_num % 10) + 1);
		break;
	}

	int temp_len = strlen(temp_buffer);

	// If content is longer than target, truncate it
	if (temp_len >= target_length) {
		strncpy(line_buffer, temp_buffer, target_length - 1);
		line_buffer[target_length - 1] = '\0';
	} else {
		// If content is shorter, pad with additional varied content
		strcpy(line_buffer, temp_buffer);
		int remaining = target_length - temp_len - 1;  // -1 for null terminator

		// Add padding with words that vary by line number
		while (remaining > 0) {
			int word_idx = (line_num + strlen(line_buffer)) % (sizeof(words) / sizeof(words[0]));
			const char* word = words[word_idx];
			int word_len = strlen(word);

			if (remaining > word_len + 1) {  // +1 for space
				strcat(line_buffer, " ");
				strcat(line_buffer, word);
				remaining -= (word_len + 1);
			} else {
				// Fill remaining space with characters that vary by line
				for (int i = 0; i < remaining; i++) {
					line_buffer[strlen(line_buffer)] = 'a' + ((line_num + i) % 26);
					line_buffer[strlen(line_buffer) + 1] = '\0';
				}
				remaining = 0;
			}
		}
	}

	// Ensure exact length
	line_buffer[target_length - 1] = '\0';

	fprintf(fp, "%s\n", line_buffer);
}

void show_help(const char* program_name) {
	printf("Usage: %s <subcommand> [options]\n\n", program_name);
	printf("Subcommands:\n");
	printf("  random           Generate random content (structured or unstructured)\n");
	printf("  fixed-line-length Generate lines with fixed length\n\n");
	printf("Options:\n");
	printf("  -o, --output FILE    Output filename (default: stdout)\n");
	printf("  -l, --lines N        Number of lines to generate (default: 1000000)\n");
	printf("  -r, --random-only    Generate random content only (for random subcommand)\n");
	printf("  -w, --width N        Line width for fixed-line-length (default: 80)\n");
	printf("  -h, --help           Show this help\n\n");
	printf("Examples:\n");
	printf("  %s random -l 100000 -o output.txt\n", program_name);
	printf("  %s fixed-line-length -w 120 -l 50000\n", program_name);
	printf("  %s random -r | head -n 10\n", program_name);
}

int main(int argc, char* argv[]) {
	// Default parameters
	char* output_filename = NULL;
	long long target_lines = 1000000;
	int structured = 1;
	int line_width = 80;
	generation_mode_t mode = MODE_RANDOM;

	// Check for subcommand
	if (argc < 2) {
		show_help(argv[0]);
		return 1;
	}

	// Parse subcommand
	if (strcmp(argv[1], "random") == 0) {
		mode = MODE_RANDOM;
	} else if (strcmp(argv[1], "fixed-line-length") == 0) {
		mode = MODE_FIXED_LENGTH;
	} else if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
		show_help(argv[0]);
		return 0;
	} else {
		fprintf(stderr, "Unknown subcommand: %s\n", argv[1]);
		show_help(argv[0]);
		return 1;
	}

	// Parse options
	for (int i = 2; i < argc; i++) {
		if ((strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--output") == 0) && i + 1 < argc) {
			output_filename = argv[++i];
		} else if ((strcmp(argv[i], "-l") == 0 || strcmp(argv[i], "--lines") == 0) && i + 1 < argc) {
			target_lines = atoll(argv[++i]);
		} else if (strcmp(argv[i], "-r") == 0 || strcmp(argv[i], "--random-only") == 0) {
			structured = 0;
		} else if ((strcmp(argv[i], "-w") == 0 || strcmp(argv[i], "--width") == 0) && i + 1 < argc) {
			line_width = atoi(argv[++i]);
			if (line_width < 10) {
				fprintf(stderr, "Line width must be at least 10 characters\n");
				return 1;
			}
		} else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
			show_help(argv[0]);
			return 0;
		} else {
			fprintf(stderr, "Unknown option: %s\n", argv[i]);
			show_help(argv[0]);
			return 1;
		}
	}

	// Open output file or use stdout
	FILE* fp = stdout;
	if (output_filename) {
		fp = fopen(output_filename, "w");
		if (!fp) {
			perror("Error opening output file");
			return 1;
		}
	}

	// Print configuration to stderr so it doesn't interfere with stdout output
	fprintf(stderr, "Generating file with %s mode...\n",
	        (mode == MODE_RANDOM) ? "random" : "fixed-line-length");
	if (output_filename) {
		fprintf(stderr, "Output file: %s\n", output_filename);
	} else {
		fprintf(stderr, "Output: stdout\n");
	}
	fprintf(stderr, "Target lines: %lld\n", target_lines);
	if (mode == MODE_RANDOM) {
		fprintf(stderr, "Content type: %s\n", structured ? "Structured" : "Random");
	} else {
		fprintf(stderr, "Line width: %d\n", line_width);
	}

	// Seed random number generator
	srand(time(NULL));

	// Write file header
	if (mode == MODE_RANDOM) {
		fprintf(fp, "HUMONGOUS READABLE FILE - Generated on: %ld - Target lines: %lld - Content type: %s\n",
		        time(NULL), target_lines, structured ? "Structured" : "Random");
	} else {
		char header[line_width + 1];
		snprintf(header, sizeof(header), "FIXED-LENGTH FILE - Generated: %ld - Lines: %lld - Width: %d",
		         time(NULL), target_lines, line_width);
		// Pad header to exact width
		int header_len = strlen(header);
		if (header_len < line_width - 1) {
			for (int i = header_len; i < line_width - 1; i++) {
				header[i] = ' ';
			}
		}
		header[line_width - 1] = '\0';
		fprintf(fp, "%s\n", header);
	}

	// Generate content
	clock_t start_time = clock();

	for (long long line = 1; line <= target_lines; line++) {
		if (mode == MODE_RANDOM) {
			if (structured) {
				generate_structured_line(fp, line);
			} else {
				generate_random_line(fp, line);
			}
		} else {
			generate_fixed_length_line(fp, line, line_width);
		}

		print_progress(line, target_lines);

		// Flush buffer periodically
		if (line % 10000 == 0) {
			fflush(fp);
		}
	}

	// Write file footer
	if (mode == MODE_RANDOM) {
		fprintf(fp, "END OF FILE - Total lines: %lld - Generation completed at: %ld\n",
		        target_lines, time(NULL));
	} else {
		char footer[line_width + 1];
		snprintf(footer, sizeof(footer), "END OF FILE - Lines: %lld - Completed: %ld",
		         target_lines, time(NULL));
		int footer_len = strlen(footer);
		if (footer_len < line_width - 1) {
			for (int i = footer_len; i < line_width - 1; i++) {
				footer[i] = ' ';
			}
		}
		footer[line_width - 1] = '\0';
		fprintf(fp, "%s\n", footer);
	}

	if (output_filename) {
		fclose(fp);
	}

	clock_t end_time = clock();
	double elapsed = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;

	// Print statistics to stderr
	if (output_filename) {
		FILE* temp = fopen(output_filename, "r");
		if (temp) {
			fseek(temp, 0, SEEK_END);
			long file_size = ftell(temp);
			fclose(temp);

			fprintf(stderr, "\nFile generation completed!\n");
			fprintf(stderr, "File: %s\n", output_filename);
			fprintf(stderr, "Size: %.2f MB (%ld bytes)\n", (double)file_size / (1024 * 1024), file_size);
		}
	} else {
		fprintf(stderr, "\nGeneration completed!\n");
	}

	fprintf(stderr, "Lines: %lld\n", target_lines);
	fprintf(stderr, "Time: %.2f seconds\n", elapsed);
	if (elapsed > 0) {
		fprintf(stderr, "Speed: %.0f lines/second\n", target_lines / elapsed);
	}

	return 0;
}