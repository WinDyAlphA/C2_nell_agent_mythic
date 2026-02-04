# Nell

Simple C implant for Mythic. Cross-compiles for Windows (x64/x86) using MinGW. 

## Capabilities
- HTTP Transport
- Shell execution (`shell`)
- Directory listing (`dir`)
- Adjustable sleep intervals

## Development
Source is in `agent_code/`.
- `Command.c` handles the logic.
- `translator.py` bridges the JSON tasks to our binary protocol.
- `Transport.c` handles the WinHTTP stuff.

Adding a command requires touching `builder.py` (UI), `translator.py` (Protocol), and the C source.