#include "Parser.h"

// Helper: lit un UINT32 big-endian depuis le buffer
static UINT32 ReadInt32BE(PUCHAR src)
{
    return ((UINT32)src[0] << 24) |
           ((UINT32)src[1] << 16) |
           ((UINT32)src[2] << 8)  |
           ((UINT32)src[3]);
}

// Helper: lit un UINT64 big-endian depuis le buffer
static UINT64 ReadInt64BE(PUCHAR src)
{
    return ((UINT64)src[0] << 56) |
           ((UINT64)src[1] << 48) |
           ((UINT64)src[2] << 40) |
           ((UINT64)src[3] << 32) |
           ((UINT64)src[4] << 24) |
           ((UINT64)src[5] << 16) |
           ((UINT64)src[6] << 8)  |
           ((UINT64)src[7]);
}

PParser ParserCreate(PBYTE data, SIZE_T size)
{
    if (!data || size == 0)
        return NULL;

    PParser parser = (PParser)LocalAlloc(LPTR, sizeof(Parser));
    if (!parser)
        return NULL;

    // Copie des données pour éviter les problèmes de lifetime
    parser->original = (PBYTE)LocalAlloc(LPTR, size);
    if (!parser->original)
    {
        LocalFree(parser);
        return NULL;
    }

    memcpy(parser->original, data, size);
    parser->buffer = parser->original;
    parser->length = size;
    parser->originalLength = size;

    return parser;
}

VOID ParserDestroy(PParser parser)
{
    if (parser)
    {
        if (parser->original)
            LocalFree(parser->original);
        LocalFree(parser);
    }
}

UINT32 ParserGetInt32(PParser parser)
{
    if (!parser || parser->length < sizeof(UINT32))
        return 0;

    UINT32 value = ReadInt32BE(parser->buffer);
    parser->buffer += sizeof(UINT32);
    parser->length -= sizeof(UINT32);

    return value;
}

UINT64 ParserGetInt64(PParser parser)
{
    if (!parser || parser->length < sizeof(UINT64))
        return 0;

    UINT64 value = ReadInt64BE(parser->buffer);
    parser->buffer += sizeof(UINT64);
    parser->length -= sizeof(UINT64);

    return value;
}

BYTE ParserGetByte(PParser parser)
{
    if (!parser || parser->length < sizeof(BYTE))
        return 0;

    BYTE value = *parser->buffer;
    parser->buffer += sizeof(BYTE);
    parser->length -= sizeof(BYTE);

    return value;
}

// Lit d'abord la taille (UINT32), puis extrait les données
// Retourne une copie allouée (à libérer avec LocalFree)
PBYTE ParserGetBytes(PParser parser, PSIZE_T outSize)
{
    if (!parser || !outSize)
        return NULL;

    // Lire la taille
    SIZE_T size = (SIZE_T)ParserGetInt32(parser);
    *outSize = size;

    if (size == 0)
        return NULL;

    return ParserGetBytesRaw(parser, size);
}

// Lit N bytes sans lire de taille préfixée
// Retourne une copie allouée (à libérer avec LocalFree)
PBYTE ParserGetBytesRaw(PParser parser, SIZE_T size)
{
    if (!parser || parser->length < size || size == 0)
        return NULL;

    PBYTE outData = (PBYTE)LocalAlloc(LPTR, size);
    if (!outData)
        return NULL;

    memcpy(outData, parser->buffer, size);
    parser->buffer += size;
    parser->length -= size;

    return outData;
}
