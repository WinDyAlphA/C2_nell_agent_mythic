#ifndef UTILS_H
#define UTILS_H

#include <windows.h>
#include <stdio.h>

#ifdef DEBUG_BUILD
    #define LOG(...) do { printf(__VA_ARGS__); printf("\n"); } while(0)
#else
    #define LOG(...)
#endif

// Base64 encoding/decoding
SIZE_T b64EncodedSize(SIZE_T inputSize);
SIZE_T b64DecodedSize(PBYTE input, SIZE_T inputSize);
PCHAR b64Encode(const PBYTE data, SIZE_T inputSize);
PBYTE b64Decode(const PCHAR input, SIZE_T inputSize, PSIZE_T outputSize);

#endif // UTILS_H
