#include "Utils.h"

static const char b64Table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";



SIZE_T b64EncodedSize(SIZE_T inputSize)
{
    SIZE_T size = inputSize;
    if (inputSize % 3 != 0)
        size += 3 - (inputSize % 3);
    size = (size / 3) * 4;
    return size;
}

SIZE_T b64DecodedSize(PBYTE input, SIZE_T inputSize)
{
    if (inputSize == 0)
        return 0;

    SIZE_T size = (inputSize / 4) * 3;

    // Check padding
    if (input[inputSize - 1] == '=')
        size--;
    if (input[inputSize - 2] == '=')
        size--;

    return size;
}

PCHAR b64Encode(const PBYTE data, SIZE_T inputSize)
{
    if (!data || inputSize == 0)
        return NULL;

    SIZE_T outputSize = b64EncodedSize(inputSize);
    PCHAR encoded = (PCHAR)LocalAlloc(LPTR, outputSize + 1);
    if (!encoded)
        return NULL;

    SIZE_T i, j;
    for (i = 0, j = 0; i < inputSize; i += 3, j += 4)
    {
        UINT32 octet0 = i < inputSize ? data[i] : 0;
        UINT32 octet1 = (i + 1) < inputSize ? data[i + 1] : 0;
        UINT32 octet2 = (i + 2) < inputSize ? data[i + 2] : 0;

        UINT32 triple = (octet0 << 16) | (octet1 << 8) | octet2;

        encoded[j]     = b64Table[(triple >> 18) & 0x3F];
        encoded[j + 1] = b64Table[(triple >> 12) & 0x3F];
        encoded[j + 2] = b64Table[(triple >> 6) & 0x3F];
        encoded[j + 3] = b64Table[triple & 0x3F];
    }

    // Padding
    SIZE_T mod = inputSize % 3;
    if (mod == 1)
    {
        encoded[outputSize - 1] = '=';
        encoded[outputSize - 2] = '=';
    }
    else if (mod == 2)
    {
        encoded[outputSize - 1] = '=';
    }

    encoded[outputSize] = '\0';
    return encoded;
}

PBYTE b64Decode(const PCHAR input, SIZE_T inputSize, PSIZE_T outputSize)
{
    if (!input || inputSize == 0)
        return NULL;

    // First pass: Calculate valid length (ignoring whitespace and padding)
    SIZE_T validChars = 0;
    SIZE_T padding = 0;
    
    for (SIZE_T i = 0; i < inputSize; i++)
    {
        char c = input[i];
        if (c == '=')
        {
            padding++;
        }
        else if ((c >= 'A' && c <= 'Z') || 
                 (c >= 'a' && c <= 'z') || 
                 (c >= '0' && c <= '9') || 
                 c == '+' || c == '/')
        {
            validChars++;
        }
        // implicit else: ignore whitespace and other chars
    }

    if (validChars == 0)
        return NULL;

    // Calculate output size
    // Each 4 valid chars -> 3 bytes
    // Padding reduces the final count
    SIZE_T totalBlocks = (validChars + padding) / 4;
    *outputSize = (totalBlocks * 3) - padding;

    PBYTE decoded = (PBYTE)LocalAlloc(LPTR, *outputSize + 1);
    if (!decoded)
        return NULL;

    // Second pass: decode
    SIZE_T i = 0; // input index
    SIZE_T j = 0; // output index
    UINT32 triple = 0;
    int digitCount = 0;

    for (i = 0; i < inputSize && j < *outputSize; i++)
    {
        char c = input[i];
        int val = -1;

        if (c >= 'A' && c <= 'Z') val = c - 'A';
        else if (c >= 'a' && c <= 'z') val = c - 'a' + 26;
        else if (c >= '0' && c <= '9') val = c - '0' + 52;
        else if (c == '+') val = 62;
        else if (c == '/') val = 63;
        // Skip everything else (whitespace, =, etc)

        if (val >= 0)
        {
            triple = (triple << 6) | val;
            digitCount++;

            if (digitCount == 4)
            {
                decoded[j++] = (triple >> 16) & 0xFF;
                if (j < *outputSize) decoded[j++] = (triple >> 8) & 0xFF;
                if (j < *outputSize) decoded[j++] = triple & 0xFF;

                triple = 0;
                digitCount = 0;
            }
        }
    }

    // Handle remaining bytes if any (should handle cases with 2 or 3 valid chars + padding)
    // But since we pre-calculated outputSize based on padding count, the loop above covers mostly full blocks.
    // The "correct" way matches the standard logic where we don't necessarily need the explicit padding chars if we know the count.
    // However, if we stopped mid-block, we need to flush.
    
    if (digitCount > 0)
    {
        // This case generally happens if padding was missing or we are processing the last chunk
        // 2 chars -> 1 byte
        // 3 chars -> 2 bytes
        if (digitCount >= 2)
        {
            triple <<= 6 * (4 - digitCount); // shift remaining
            decoded[j++] = (triple >> 16) & 0xFF;
            if (digitCount >= 3 && j < *outputSize)
            {
                decoded[j++] = (triple >> 8) & 0xFF;
            }
        }
    }

    return decoded;
}
