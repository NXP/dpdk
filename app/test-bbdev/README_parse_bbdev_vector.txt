# parse_bbdev_vector (LDPC SD/SE/CD/CE)

Parses DPDK bbdev test vector files and prints:

- Provided sizes for each `inputX` and `outputX` list (counts 32-bit hex words -> bytes).
- Parsed descriptor fields, supporting both `key=value` and `key=\nvalue`.
- Expected sizes for common **LDPC** vector types:

  * **SD**: LDPC Decode TB-mode (code_block_mode=0 + ea/eb/c/r/cab)
  * **CD**: LDPC Decode CB-mode (code_block_mode=1 + e)
  * **SE**: LDPC Encode TB-mode (code_block_mode=0 + ea/eb/c/r/cab)
  * **CE**: LDPC Encode CB-mode (code_block_mode=1 + e)

## Build

```bash
gcc -O2 -Wall -Wextra -std=c11 -o parse_bbdev_vector parse_bbdev_vector.c
```

## Run

```bash
./parse_bbdev_vector <vector_file>
```

## Assumptions

- Decode input is treated as **LLR stream**, so input bytes are shown for **int8** and **int16** LLR.
- Encode input/output are treated as **packed hard bits**, so bytes = ceil(bits/8).
- The tool also prints word-aligned requirements (ceil(bytes/4)) since vectors commonly use 32-bit words.
