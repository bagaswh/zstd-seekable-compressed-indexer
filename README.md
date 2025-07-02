# zstd-playground

## Scenario 1: I have a large line-separated text file (50 GB or more). I need to store the decompressed offset of each line in another storage.

1. Visit each frame, pass the frame to decoder

2. Decoder pass to line processor

3. Line processor finds newline