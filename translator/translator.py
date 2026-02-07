import json
import base64
import ipaddress

from mythic_container.TranslationBase import *

# Command definitions
commands = {
    "checkin": {"hex_code": 0xF1, "name": "checkin"},
    "get_tasking": {"hex_code": 0x01, "name": "get_tasking"},
    "post_response": {"hex_code": 0x02, "name": "post_response"},
    "shell": {"hex_code": 0x10, "name": "shell"},
    "dir": {"hex_code": 0x11, "name": "dir"},
    "exit": {"hex_code": 0x12, "name": "exit"},
    "cd": {"hex_code": 0x13, "name": "cd"},
    "cat": {"hex_code": 0x14, "name": "cat"},
    "ps": {"hex_code": 0x15, "name": "ps"},
    "download_start": {"hex_code": 0x03, "name": "download_start"},
    "download_chunk": {"hex_code": 0x04, "name": "download_chunk"},
}

# ============================================================================
# Helpers - Because parsing binary manually is pain
# ============================================================================

def getBytesWithSize(data: bytes) -> tuple[bytes, bytes]:
    """
    Reads a chunk prefixed by its 4-byte big-endian size.
    Returns (chunk, leftovers)
    """
    if len(data) < 4:
        return b"", data
    size = int.from_bytes(data[0:4], byteorder='big')
    data = data[4:]
    return data[:size], data[size:]


def getInt32(data: bytes) -> tuple[int, bytes]:
    """
    Grab a 4-byte int.
    Returns (value, leftovers)
    """
    if len(data) < 4:
        return 0, data
    value = int.from_bytes(data[0:4], byteorder='big')
    return value, data[4:]


def getByte(data: bytes) -> tuple[int, bytes]:
    """
    Grab a single byte.
    Returns (value, leftovers)
    """
    if len(data) < 1:
        return 0, data
    return data[0], data[1:]


def getStringWithSize(data: bytes) -> tuple[str, bytes]:
    """
    Extract a string (prefixed with size).
    Returns (string, leftovers)
    """
    raw, remaining = getBytesWithSize(data)
    try:
        return raw.decode('utf-8'), remaining
    except:
        try:
            return raw.decode('cp850'), remaining
        except:
            return raw.hex(), remaining


def getWStringWithSize(data: bytes) -> tuple[str, bytes]:
    """
    Reads a size-prefixed wide string (UTF-16LE).
    Returns (string, remaining_data)
    """
    raw, remaining = getBytesWithSize(data)
    try:
        return raw.decode('utf-16le'), remaining
    except:
        return raw.hex(), remaining

# ============================================================================

def checkIn(data: bytes) -> dict:
    # ... (Same as before) ...
    uuid = data[:36].decode('utf-8', errors='replace')
    data = data[36:]
    numIPs, data = getInt32(data)
    IPs = []
    for _ in range(numIPs):
        if len(data) >= 4:
            ip_bytes = data[:4]
            data = data[4:]
            try:
                addr = str(ipaddress.ip_address(ip_bytes))
                IPs.append(addr)
            except:
                IPs.append("0.0.0.0")
    targetOS, data = getStringWithSize(data)
    arch_byte, data = getByte(data)
    arch_map = {1: "x86", 2: "x64", 3: "arm"}
    architecture = arch_map.get(arch_byte, "unknown")
    hostname, data = getStringWithSize(data)
    username, data = getStringWithSize(data)
    domain, data = getWStringWithSize(data)
    pid, data = getInt32(data)
    processName, data = getStringWithSize(data)
    externalIP, data = getStringWithSize(data)
    
    dataJson = {
        "action": "checkin",
        "uuid": uuid,
        "ips": IPs,
        "os": targetOS,
        "architecture": architecture,
        "host": hostname,
        "user": username,
        "domain": domain,
        "pid": pid,
        "process_name": processName,
        "external_ip": externalIP,
    }
    return dataJson


class NellTranslator(TranslationContainer):
    name = "NellTranslator"
    description = "Translation service for Nell agent"
    author = "@nxvh"

    async def generate_keys(self, inputMsg: TrGenerateEncryptionKeysMessage) -> TrGenerateEncryptionKeysMessageResponse:
        response = TrGenerateEncryptionKeysMessageResponse(Success=True)
        response.DecryptionKey = b""
        response.EncryptionKey = b""
        return response

    async def translate_from_c2_format(self, inputMsg: TrCustomMessageToMythicC2FormatMessage) -> TrCustomMessageToMythicC2FormatMessageResponse:
        response = TrCustomMessageToMythicC2FormatMessageResponse(Success=True)
        data = inputMsg.Message
        
        if len(data) == 0:
            response.Success = False
            return response
        
        command_byte = data[0]

        # Fix: Agent sends [UUID(36)] [CommandByte] ...
        # Check if we have a UUID prefix
        if len(data) >= 37:
            possible_cmd = data[36]
            if possible_cmd in [
                commands["checkin"]["hex_code"],
                commands["get_tasking"]["hex_code"],
                commands["post_response"]["hex_code"],
                commands["download_start"]["hex_code"],
                commands["download_chunk"]["hex_code"]
            ]:
                # It's likely the UUID prefix
                data = data[36:]
                command_byte = data[0]
        
        if command_byte == commands["checkin"]["hex_code"]:
            response.Message = checkIn(data[1:])
        
        elif command_byte == commands["get_tasking"]["hex_code"]:
            response.Message = {
                "action": "get_tasking",
                "tasking_size": -1
            }
        
        elif command_byte == commands["post_response"]["hex_code"]:
            # Parse responses
            # Agent sends: [Action 0x02] [UUID(36)] [RespSize] [RespData]
            # Wait, verify Command.c post_response structure
            # executeShell sends: [Action 0x02] [UUID size+data] [Output size+data]
            # NO! Command.c:
            # PackageAddByte(responseTask, POST_RESPONSE);
            # PackageAddBytes(responseTask, taskUuid, uuidLen); (Size + UUID)
            # PackageAddBytes(responseTask, output, len); (Size + Output)
            
            # Let's parse it properly here or in postResponse helper
            # Skip Command Byte
            data = data[1:]
            
            uuid_task, data = getStringWithSize(data)
            output, data = getStringWithSize(data)
            
            response.Message = {
                "action": "post_response",
                "responses": [
                    {
                        "task_id": uuid_task,
                        "user_output": output,
                        "completed": True
                    }
                ]
            }
            
        elif command_byte == commands["download_start"]["hex_code"]:
            # Download Start: [0x03] [UUID Size][UUID] [TotalChunks] [Path Size][Path] [ChunkSize]
            
            data = data[1:]
            uuid_task, data = getStringWithSize(data)
            total_chunks, data = getInt32(data)
            path, data = getStringWithSize(data)
            chunk_size, data = getInt32(data)
            
            response.Message = {
                "action": "post_response",
                "responses": [
                    {
                        "task_id": uuid_task,
                        "download": {
                            "total_chunks": total_chunks,
                            "filename": path,
                            "chunk_size": chunk_size,
                            "is_screenshot": False
                        }
                    }
                ]
            }

        elif command_byte == commands["download_chunk"]["hex_code"]:
            # Download Chunk: [0x04] [UUID Size][UUID] [ChunkNum] [FileID Size][FileID] [Chunk Size][Chunk Data] [BytesRead]
            
            data = data[1:]
            uuid_task, data = getStringWithSize(data)
            chunk_num, data = getInt32(data)
            file_id, data = getStringWithSize(data)
            chunk_data, data = getBytesWithSize(data)
            bytes_read, data = getInt32(data)
            
            # Helper to encode chunk data
            encoded_chunk = base64.b64encode(chunk_data).decode()
            
            response.Message = {
                "action": "post_response",
                "responses": [
                    {
                        "task_id": uuid_task,
                        "download": {
                            "chunk_num": chunk_num,
                            "file_id": file_id,
                            "chunk_data": encoded_chunk,
                            "chunk_size": bytes_read # Mythic docs say optional but helpful? 
                        }
                    }
                ]
            }

        else:
            response.Success = False
        
        return response


    async def translate_to_c2_format(self, inputMsg: TrMythicC2ToCustomMessageFormatMessage) -> TrMythicC2ToCustomMessageFormatMessageResponse:
        response = TrMythicC2ToCustomMessageFormatMessageResponse(Success=True)
        mythic_message = inputMsg.Message
        
        if mythic_message.get("action") == "checkin":
            new_uuid = mythic_message.get("id", "").encode('utf-8')[:36].ljust(36, b'\x00')
            status = 0x00 if mythic_message.get("status") == "success" else 0x01
            raw_msg = bytes([commands["checkin"]["hex_code"]]) + new_uuid + bytes([status])
            response.Message = base64.b64encode(raw_msg)
        
        elif mythic_message.get("action") == "get_tasking":
            response.Message = self.responseTasking(mythic_message.get("tasks", []))

        elif mythic_message.get("action") == "post_response":
            # Check for file_id in responses to send back to agent
            # Mythic sends: {"action": "post_response", "responses": [{"task_id": "...", "status": "success", "file_id": "..."}]}
            
            responses = mythic_message.get("responses", [])
            data = b""
            
            for resp in responses:
                if "file_id" in resp and resp["file_id"]:
                    # Found a file_id (start of download)
                    # Send to Agent: [0x03] [UUID Size][UUID] [FileID Size][FileID]
                    
                    cmd_id = commands["download_start"]["hex_code"]
                    uuid_bytes = resp["task_id"].encode()
                    file_id_bytes = resp["file_id"].encode()
                    
                    payload = len(uuid_bytes).to_bytes(4, "big") + uuid_bytes
                    payload += len(file_id_bytes).to_bytes(4, "big") + file_id_bytes
                    
                    chunk = cmd_id.to_bytes(1, "big") + payload
                    data += chunk
            
            if data:
                response.Message = base64.b64encode(data)
            else:
                response.Message = b"" # No data to send back
        
        return response

    def responseTasking(self, tasks):
        # Build Tasking Response
        # Header: [0x01] [NumTasks(4)]
        data = commands["get_tasking"]["hex_code"].to_bytes(1, "big") + len(tasks).to_bytes(4, "big")
        
        for task in tasks:
            cmd_name = task["command"]
            if cmd_name not in commands:
                continue

            # Cmd ID
            cmd_id = commands[cmd_name]["hex_code"]
            
            # UUID (Size + Bytes)
            uuid_bytes = task["id"].encode()
            
            # Parameters
            # For shell, parameters is a string, possibly JSON
            param_str = task["parameters"]
            
            # Attempt to parse as JSON to extract 'command' if relevant
            try:
                param_json = json.loads(param_str)
                # If command is 'shell' and we have a 'command' key
                if cmd_name == "shell" and isinstance(param_json, dict) and "command" in param_json:
                    param_str = param_json["command"]
                # If command is 'dir' and we have a 'path' key
                elif cmd_name == "dir" and isinstance(param_json, dict) and "path" in param_json:
                    param_str = param_json["path"]
                # If command is 'cd' and we have a 'path' key
                elif cmd_name == "cd" and isinstance(param_json, dict) and "path" in param_json:
                    param_str = param_json["path"]
                # If command is 'cat' and we have a 'path' key
                elif cmd_name == "cat" and isinstance(param_json, dict) and "path" in param_json:
                    param_str = param_json["path"]
            except:
                pass # Not JSON or parse error, use raw string

            param_bytes = param_str.encode()
            
            # Payload construction: [UUID Size][UUID] [NumArgs] [Cmd Size][Cmd]
            payload = len(uuid_bytes).to_bytes(4, "big") + uuid_bytes
            payload += (1).to_bytes(4, "big") # NumArgs
            payload += len(param_bytes).to_bytes(4, "big") + param_bytes
            
            # Task Block: [TotalSize] [CmdID] [Payload]
            total_size = 1 + len(payload)
            
            data += total_size.to_bytes(4, "big")
            data += cmd_id.to_bytes(1, "big")
            data += payload
            
        return base64.b64encode(data)

