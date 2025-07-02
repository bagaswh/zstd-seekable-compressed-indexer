#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// Sample text patterns for variety
const char* words[] = {
    "the", "quick", "brown", "fox", "jumps", "over", "lazy", "dog",
    "hello", "world", "computer", "science", "programming", "language",
    "data", "structure", "algorithm", "memory", "processor", "system",
    "network", "database", "software", "hardware", "application", "program"};

const char* sentences[] = {
    "This is line number %lld in our humongous file.",
    "The current timestamp is %ld and we're still generating content.",
    "Lorem ipsum dolor sit amet, consectetur adipiscing elit line %lld.",
    "Programming in C is fun, especially when creating large files at line %lld.",
    "Data processing requires efficient algorithms, now at line %lld.",
    "Memory management is crucial in systems programming - line %lld.",
    "Network protocols enable communication between systems at line %lld."};

void print_progress(long long current, long long total) {
	if (current % 100000 == 0) {
		printf("Progress: %.2f%% (%lld/%lld lines)\n",
		       (double)current / total * 100, current, total);
		fflush(stdout);
	}
}

void generate_random_paragraph(FILE* fp, long long line_num) {
	int sentence_count = 3 + (rand() % 5);  // 3-7 sentences per paragraph

	for (int i = 0; i < sentence_count; i++) {
		int sentence_idx = rand() % (sizeof(sentences) / sizeof(sentences[0]));
		fprintf(fp, sentences[sentence_idx], line_num);
		fprintf(fp, " ");

		// Add some random words
		int word_count = 5 + (rand() % 10);  // 5-14 additional words
		for (int j = 0; j < word_count; j++) {
			int word_idx = rand() % (sizeof(words) / sizeof(words[0]));
			fprintf(fp, "%s ", words[word_idx]);
		}
	}
	fprintf(fp, "\n\n");
}

void generate_structured_content(FILE* fp, long long line_num) {
	// Generate different types of content based on line number
	int content_type = line_num % 5;

	switch (content_type) {
	case 0:  // Header section
		fprintf(fp, "=== SECTION %lld: DATA PROCESSING ===\n", line_num / 1000);
		fprintf(fp, "Timestamp: %ld\n", time(NULL));
		fprintf(fp, "Processing large datasets requires efficient algorithms.\n\n");
		break;

	case 1:  // Code-like content
		fprintf(fp, "function processData_%lld() {\n", line_num);
		fprintf(fp, "    var result = [];\n");
		fprintf(fp, "    for (var i = 0; i < %lld; i++) {\n", line_num % 1000);
		fprintf(fp, "        result.push(computeValue(i));\n");
		fprintf(fp, "    }\n");
		fprintf(fp, "    return result;\n");
		fprintf(fp, "}\n\n");
		break;

	case 2:  // Data table
		fprintf(fp, "ID\tNAME\tVALUE\tTIMESTAMP\n");
		for (int i = 0; i < 5; i++) {
			fprintf(fp, "%lld\tRecord_%d\t%.2f\t%ld\n",
			        line_num + i, i, (double)(rand() % 10000) / 100.0, time(NULL));
		}
		fprintf(fp, "\n");
		break;

	case 3:  // Log entries
		fprintf(fp, "[%ld] INFO: Processing line %lld\n", time(NULL), line_num);
		fprintf(fp, "[%ld] DEBUG: Memory usage: %d MB\n", time(NULL), rand() % 1024);
		fprintf(fp, "[%ld] WARN: Large file generation in progress\n", time(NULL));
		fprintf(fp, "\n");
		break;

	case 4:  // Narrative text
		generate_random_paragraph(fp, line_num);
		break;
	}
}

int main(int argc, char* argv[]) {
	// Default parameters
	char filename[256] = "humongous_file.txt";
	long long target_lines = 1000000;  // 1 million lines
	int structured = 1;                // Use structured content by default

	// Parse command line arguments
	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-f") == 0 && i + 1 < argc) {
			strcpy(filename, argv[++i]);
		} else if (strcmp(argv[i], "-l") == 0 && i + 1 < argc) {
			target_lines = atoll(argv[++i]);
		} else if (strcmp(argv[i], "-r") == 0) {
			structured = 0;  // Random content only
		} else if (strcmp(argv[i], "-h") == 0) {
			printf("Usage: %s [-f filename] [-l lines] [-r] [-h]\n", argv[0]);
			printf("  -f filename: Output filename (default: humongous_file.txt)\n");
			printf("  -l lines: Number of lines to generate (default: 1000000)\n");
			printf("  -r: Generate random content only (default: structured)\n");
			printf("  -h: Show this help\n");
			return 0;
		}
	}

	printf("Generating humongous readable file...\n");
	printf("Filename: %s\n", filename);
	printf("Target lines: %lld\n", target_lines);
	printf("Content type: %s\n", structured ? "Structured" : "Random");

	FILE* fp = fopen(filename, "w");
	if (!fp) {
		perror("Error opening file");
		return 1;
	}

	// Seed random number generator
	srand(time(NULL));

	// Write file header
	fprintf(fp, "HUMONGOUS READABLE FILE\n");
	fprintf(fp, "Generated on: %s", ctime(&(time_t){time(NULL)}));
	fprintf(fp, "Target lines: %lld\n", target_lines);
	fprintf(fp, "Content type: %s\n\n", structured ? "Structured" : "Random");

	// Generate content
	clock_t start_time = clock();

	for (long long line = 1; line <= target_lines; line++) {
		if (structured) {
			generate_structured_content(fp, line);
		} else {
			generate_random_paragraph(fp, line);
		}

		print_progress(line, target_lines);

		// Flush buffer periodically to show progress
		if (line % 10000 == 0) {
			fflush(fp);
		}
	}

	// Write file footer
	fprintf(fp, "END OF HUMONGOUS FILE\n");
	fprintf(fp, "Total lines generated: %lld\n", target_lines);
	fprintf(fp, "Generation completed at: %s", ctime(&(time_t){time(NULL)}));

	fclose(fp);

	clock_t end_time = clock();
	double elapsed = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;

	// Get file size
	FILE* temp = fopen(filename, "r");
	if (temp) {
		fseek(temp, 0, SEEK_END);
		long file_size = ftell(temp);
		fclose(temp);

		printf("\nFile generation completed!\n");
		printf("File: %s\n", filename);
		printf("Size: %.2f MB (%ld bytes)\n", (double)file_size / (1024 * 1024), file_size);
		printf("Lines: %lld\n", target_lines);
		printf("Time: %.2f seconds\n", elapsed);
		printf("Speed: %.0f lines/second\n", target_lines / elapsed);
	}

	return 0;
}