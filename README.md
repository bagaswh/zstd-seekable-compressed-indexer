# zstd-playground

## Scenario 1: I have a large line-separated text file (50 GB or more). I need to store the decompressed offset of each line in another storage.

1. Visit each frame, pass the frame, {compressed,decompressed} {frame size,offset} to decoder 

2. Decoder decompresses the frame, pass the decompressed bytes to line processor along with sizes and offsets

3. Line processor finds newline or beginning of data, mark as the starting offset (+1 if newline, since +1 is the next line)

4. Line processor finds another newline or end of data, mark as the ending offset

5. Line processor hashes the line, stores a mapping of hash to offset