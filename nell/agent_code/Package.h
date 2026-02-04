#ifndef PACKAGE_H
#define PACKAGE_H

#include <windows.h>

typedef struct {
    PVOID   buffer;
    SIZE_T  length;
} Package, *PPackage;

// Création / Destruction
PPackage PackageCreate(VOID);
VOID PackageDestroy(PPackage package);

// Ajout de données au buffer (incrémente length)
BOOL PackageAddInt32(PPackage package, UINT32 value);
BOOL PackageAddInt64(PPackage package, UINT64 value);
BOOL PackageAddByte(PPackage package, BYTE value);
BOOL PackageAddBytes(PPackage package, PBYTE data, SIZE_T size);        // Ajoute size + data
BOOL PackageAddBytesRaw(PPackage package, PBYTE data, SIZE_T size);     // Ajoute data sans size

#endif // PACKAGE_H
