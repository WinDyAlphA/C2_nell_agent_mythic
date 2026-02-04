#ifndef PARSER_H
#define PARSER_H

#include <windows.h>

typedef struct {
    PBYTE   original;       // Pointeur original (pour free)
    PBYTE   buffer;         // Pointeur courant (avance au fur et à mesure)
    SIZE_T  length;         // Taille restante
    SIZE_T  originalLength; // Taille originale
} Parser, *PParser;

// Création / Destruction
PParser ParserCreate(PBYTE data, SIZE_T size);
VOID ParserDestroy(PParser parser);

// Extraction de données du buffer (décrémente length, avance buffer)
UINT32 ParserGetInt32(PParser parser);
UINT64 ParserGetInt64(PParser parser);
BYTE ParserGetByte(PParser parser);
PBYTE ParserGetBytes(PParser parser, PSIZE_T outSize);      // Lit size puis data, retourne copie allouée
PBYTE ParserGetBytesRaw(PParser parser, SIZE_T size);       // Lit N bytes, retourne copie allouée

#endif // PARSER_H
