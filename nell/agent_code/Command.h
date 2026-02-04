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
#define SHELL_CMD       0x10  // 0x10 is what translator uses for shell! 0x54 was example.
#define DIR_LIST        0x11

// Function Prototypes
BOOL routine(VOID);
BOOL commandDispatch(PParser response);
BOOL handleGetTasking(PParser getTasking);
BOOL executeShell(PParser taskParser);
BOOL executeDir(PParser taskParser);

#endif // COMMAND_H
