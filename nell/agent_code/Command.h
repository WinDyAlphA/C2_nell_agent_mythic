#ifndef COMMAND_H
#define COMMAND_H

#include <windows.h>
#include "Package.h"
#include "Parser.h"
#include "Transport.h"

// Command IDs (Must match translator.py)
// Command IDs (Must match translator.py)
#define GET_TASKING     0x01
#define POST_RESPONSE   0x02

#define NUMBER_OF_TASKS 1

// Task IDs
#define SHELL_CMD       0x10
#define DIR_LIST        0x11
#define EXIT_CMD        0x12
#define CD_CMD          0x13
#define CAT_CMD         0x14
#define PS_CMD          0x15

// Function Prototypes
BOOL routine(VOID);
BOOL commandDispatch(PParser response);
BOOL handleGetTasking(PParser getTasking);
BOOL executeShell(PParser taskParser);
BOOL executeDir(PParser taskParser);
BOOL executeExit(PParser taskParser);
BOOL executeCd(PParser taskParser);
BOOL executeCat(PParser taskParser);
BOOL executePs(PParser taskParser);

#endif // COMMAND_H
