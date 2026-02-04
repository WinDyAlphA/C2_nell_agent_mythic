# Nell

Simple C implant for Mythic. Cross-compiles for Windows (x64/x86) using MinGW.

## Capabilities

*   **HTTP Transport**: Robust communication with C2 using WinHTTP.
*   **Sleep and jitter**: Configurable **Sleep** and **Jitter** to evade detection.

## Commands

| Command | Description | Syntax |
| :--- | :--- | :--- |
| `shell` | Execute a shell command via `cmd.exe`. | `shell <command>` |
| `dir` | List files in a directory. | `dir <path>` or `dir .` |
| `cd` | Change the current working directory. | `cd <path>` |
| `cat` | Read and display file content (UTF-8/16 support). | `cat <path>` |
| `ps` | List running processes (PID and Name). | `ps` |
| `exit` | Terminate the agent process. | `exit` |

## Development

Source is located in `agent_code/`. It uses a custom binary protocol for C2 communication.

1.  **Mythic UI (`builder.py`)**: Defines commands and parameters shown in the web interface.
2.  **Protocol (`translator.py`)**: Translates Mythic's JSON tasks into the agent's binary format (and vice-versa).
3.  **Agent Logic (`agent_code/`)**:
    *   `Command.c`: Core logic for task execution (`shell`, `upload`, etc.).
    *   `Transport.c`: HTTP communication via WinHTTP.
    *   `nell.c`: Main entry point and configuration.

### Adding a Command workflow
1. Add command definition in `builder.py`.
2. Map command ID in `translator.py` and `Command.h`.
3. Implement logic in `Command.c`.

## TODO

- [ ] **Download**: Exfiltrate files from the target.
- [ ] **Upload**: Send files to the target.
- [ ] **Jobs**: Manage long-running tasks.
- [ ] **Socks5**: Proxy support.
- [ ] **HTTPS**: Use HTTPS instead of HTTP.
- [ ] **DNS**: Use DNS instead of HTTP.