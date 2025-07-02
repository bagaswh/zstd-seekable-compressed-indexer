.PHONY : build

build:
	clang -O0 -g -ggdb3 -fsanitize=address -fsanitize=undefined -fno-omit-frame-pointer -fno-optimize-sibling-calls -fno-common -march=native -std=c17 -I. main.c -o main

build-genfile:
	clang -O2 -march=native -std=c17 -I. genfile.c -o genfile