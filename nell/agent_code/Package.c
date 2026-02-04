#include "Package.h"

// Helper: écrit un UINT32 en big-endian dans le buffer
static VOID WriteInt32BE(PUCHAR dest, UINT32 value)
{
    dest[0] = (UCHAR)(value >> 24);
    dest[1] = (UCHAR)(value >> 16);
    dest[2] = (UCHAR)(value >> 8);
    dest[3] = (UCHAR)(value);
}

// Helper: écrit un UINT64 en big-endian dans le buffer
static VOID WriteInt64BE(PUCHAR dest, UINT64 value)
{
    dest[0] = (UCHAR)(value >> 56);
    dest[1] = (UCHAR)(value >> 48);
    dest[2] = (UCHAR)(value >> 40);
    dest[3] = (UCHAR)(value >> 32);
    dest[4] = (UCHAR)(value >> 24);
    dest[5] = (UCHAR)(value >> 16);
    dest[6] = (UCHAR)(value >> 8);
    dest[7] = (UCHAR)(value);
}

PPackage PackageCreate(VOID)
{
    PPackage package = (PPackage)LocalAlloc(LPTR, sizeof(Package));
    if (!package)
        return NULL;

    package->buffer = NULL;
    package->length = 0;

    return package;
}

VOID PackageDestroy(PPackage package)
{
    if (package)
    {
        if (package->buffer)
            LocalFree(package->buffer);
        LocalFree(package);
    }
}

BOOL PackageAddInt32(PPackage package, UINT32 value)
{
    if (!package)
        return FALSE;

    SIZE_T newSize = package->length + sizeof(UINT32);

    if (package->buffer)
        package->buffer = LocalReAlloc(package->buffer, newSize, LMEM_MOVEABLE | LMEM_ZEROINIT);
    else
        package->buffer = LocalAlloc(LPTR, newSize);

    if (!package->buffer)
        return FALSE;

    WriteInt32BE((PUCHAR)package->buffer + package->length, value);
    package->length = newSize;

    return TRUE;
}

BOOL PackageAddInt64(PPackage package, UINT64 value)
{
    if (!package)
        return FALSE;

    SIZE_T newSize = package->length + sizeof(UINT64);

    if (package->buffer)
        package->buffer = LocalReAlloc(package->buffer, newSize, LMEM_MOVEABLE | LMEM_ZEROINIT);
    else
        package->buffer = LocalAlloc(LPTR, newSize);

    if (!package->buffer)
        return FALSE;

    WriteInt64BE((PUCHAR)package->buffer + package->length, value);
    package->length = newSize;

    return TRUE;
}

BOOL PackageAddByte(PPackage package, BYTE value)
{
    if (!package)
        return FALSE;

    SIZE_T newSize = package->length + sizeof(BYTE);

    if (package->buffer)
        package->buffer = LocalReAlloc(package->buffer, newSize, LMEM_MOVEABLE | LMEM_ZEROINIT);
    else
        package->buffer = LocalAlloc(LPTR, newSize);

    if (!package->buffer)
        return FALSE;

    *((PBYTE)package->buffer + package->length) = value;
    package->length = newSize;

    return TRUE;
}

// Ajoute des bytes AVEC leur taille en préfixe (size + data)
BOOL PackageAddBytes(PPackage package, PBYTE data, SIZE_T size)
{
    if (!package || (!data && size > 0))
        return FALSE;

    // D'abord ajouter la taille (UINT32)
    if (!PackageAddInt32(package, (UINT32)size))
        return FALSE;

    // Puis les données raw
    return PackageAddBytesRaw(package, data, size);
}

// Ajoute des bytes SANS leur taille (juste les données)
BOOL PackageAddBytesRaw(PPackage package, PBYTE data, SIZE_T size)
{
    if (!package || (!data && size > 0))
        return FALSE;

    if (size == 0)
        return TRUE;

    SIZE_T newSize = package->length + size;

    if (package->buffer)
        package->buffer = LocalReAlloc(package->buffer, newSize, LMEM_MOVEABLE | LMEM_ZEROINIT);
    else
        package->buffer = LocalAlloc(LPTR, newSize);

    if (!package->buffer)
        return FALSE;

    memcpy((PUCHAR)package->buffer + package->length, data, size);
    package->length = newSize;

    return TRUE;
}
