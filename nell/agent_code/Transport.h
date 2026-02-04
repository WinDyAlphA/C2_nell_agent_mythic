#ifndef TRANSPORT_H
#define TRANSPORT_H

#include <windows.h>
#include <winhttp.h>

#include "Package.h"
#include "Parser.h"
#include "nell.h"

// Define transport type (extensible for other protocols)
#define HTTP_TRANSPORT

// Abstract transport layer - add other protocols here
PParser sendAndReceive(PBYTE data, SIZE_T size);

// HTTP transport implementation
PParser makeHTTPRequest(PBYTE data, SIZE_T size);

// High-level function: encode Package to B64, send, receive Parser
// Format sent: B64(UUID + PackageData)
PParser sendPackage(PPackage package);

#endif // TRANSPORT_H
