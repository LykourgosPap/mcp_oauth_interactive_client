#!/usr/bin/env python3
"""Simple MCP client example with OAuth authentication support.

This client connects to an MCP server using streamable HTTP transport with OAuth.
It persists tokens to a local file (.mcp_token) to avoid re-login.
"""

from __future__ import annotations as _annotations

import asyncio
import json
import os
import socketserver
import threading
import time
import traceback
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx
from anyio.streams.memory import MemoryObjectReceiveStream, MemoryObjectSendStream
from mcp.client.auth import OAuthClientProvider, TokenStorage
from mcp.client.session import ClientSession
from mcp.client.sse import sse_client
from mcp.client.streamable_http import streamable_http_client
from mcp.shared.auth import OAuthClientInformationFull, OAuthClientMetadata, OAuthToken
from mcp.shared.message import SessionMessage

# Config: Where to save the token
TOKEN_FILE_PATH = ".mcp_token"


class FilePersistedTokenStorage(TokenStorage):
    """
    Token storage that:
    1. Tries to load from a local file (.mcp_token) on init.
    2. Saves the token to that file automatically on successful login.
    """

    def __init__(self):
        self._tokens: OAuthToken | None = None
        self._client_info: OAuthClientInformationFull | None = None

        # Try to load from file
        if os.path.exists(TOKEN_FILE_PATH):
            try:
                with open(TOKEN_FILE_PATH, "r") as f:
                    token_data = json.load(f)
                self._tokens = OAuthToken.model_validate(token_data)
                print(f" Loaded cached OAuth token from {TOKEN_FILE_PATH}")
            except Exception as e:
                print(f"⚠️ Found {TOKEN_FILE_PATH} but failed to parse it: {e}")
                print("   Will proceed with fresh login.")

    async def get_tokens(self) -> OAuthToken | None:
        return self._tokens

    async def set_tokens(self, tokens: OAuthToken) -> None:
        self._tokens = tokens

        # Save to File
        try:
            with open(TOKEN_FILE_PATH, "w") as f:
                f.write(tokens.model_dump_json(indent=2))
            print(f"💾 Token saved to {TOKEN_FILE_PATH} (Auto-login enabled for next time)")
        except Exception as e:
            print(f"❌ Failed to save token to file: {e}")

    async def get_client_info(self) -> OAuthClientInformationFull | None:
        return self._client_info

    async def set_client_info(self, client_info: OAuthClientInformationFull) -> None:
        self._client_info = client_info


class CallbackHandler(BaseHTTPRequestHandler):
    """Simple HTTP handler to capture OAuth callback."""

    def __init__(
            self,
            request: Any,
            client_address: tuple[str, int],
            server: socketserver.BaseServer,
            callback_data: dict[str, Any],
    ):
        """Initialize with callback data storage."""
        self.callback_data = callback_data
        super().__init__(request, client_address, server)

    def do_GET(self):
        """Handle GET request from OAuth redirect."""
        parsed = urlparse(self.path)
        query_params = parse_qs(parsed.query)

        if "code" in query_params:
            self.callback_data["authorization_code"] = query_params["code"][0]
            self.callback_data["state"] = query_params.get("state", [None])[0]
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b"""
            <html>
            <body>
                <h1>Authorization Successful!</h1>
                <p>You can close this window and return to the terminal.</p>
                <script>setTimeout(() => window.close(), 2000);</script>
            </body>
            </html>
            """)
        elif "error" in query_params:
            self.callback_data["error"] = query_params["error"][0]
            self.send_response(400)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(
                f"""
            <html>
            <body>
                <h1>Authorization Failed</h1>
                <p>Error: {query_params["error"][0]}</p>
                <p>You can close this window and return to the terminal.</p>
            </body>
            </html>
            """.encode()
            )
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format: str, *args: Any):
        """Suppress default logging."""


class CallbackServer:
    """Simple server to handle OAuth callbacks."""

    def __init__(self, port: int = 3000):
        self.port = port
        self.server = None
        self.thread = None
        self.callback_data = {"authorization_code": None, "state": None, "error": None}

    def _create_handler_with_data(self):
        """Create a handler class with access to callback data."""
        callback_data = self.callback_data

        class DataCallbackHandler(CallbackHandler):
            def __init__(
                    self,
                    request: BaseHTTPRequestHandler,
                    client_address: tuple[str, int],
                    server: socketserver.BaseServer,
            ):
                super().__init__(request, client_address, server, callback_data)

        return DataCallbackHandler

    def start(self):
        """Start the callback server in a background thread."""
        handler_class = self._create_handler_with_data()
        try:
            self.server = HTTPServer(("localhost", self.port), handler_class)
            self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
            self.thread.start()
            print(f"🖥️  Started callback server on http://localhost:{self.port}")
        except OSError as e:
            print(f"❌ Could not start callback server on port {self.port}: {e}")
            raise

    def stop(self):
        """Stop the callback server."""
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.server = None
        if self.thread:
            self.thread.join(timeout=1)
            self.thread = None

    def wait_for_callback(self, timeout: int = 300):
        """Wait for OAuth callback with timeout."""
        start_time = time.time()
        while time.time() - start_time < timeout:
            if self.callback_data["authorization_code"]:
                return self.callback_data["authorization_code"]
            elif self.callback_data["error"]:
                raise Exception(f"OAuth error: {self.callback_data['error']}")
            time.sleep(0.1)
        raise Exception("Timeout waiting for OAuth callback")

    def get_state(self):
        """Get the received state parameter."""
        return self.callback_data["state"]


def httpx_factory(use_http2_version, **kwargs):

    return httpx.AsyncClient(
        verify=False,
        http2=use_http2_version,
        **kwargs
    )


class SimpleAuthClient:
    """Simple MCP client with auth support."""

    def __init__(
            self,
            server_url: str,
            transport_type: str = "streamable-http",
            client_metadata_url: str | None = None,
    ):
        self.server_url = server_url
        self.transport_type = transport_type
        self.client_metadata_url = client_metadata_url
        self.session: ClientSession | None = None

    async def connect(self):
        """Wrapper to handle connection retry logic if cached token is invalid."""
        has_cached_token = os.path.exists(TOKEN_FILE_PATH)

        try:
            await self._attempt_connection()
        except Exception as e:
            # If we failed AND we were using a cached token file, retry from scratch
            if has_cached_token:
                print(f"\n❌ Connection failed with cached token: {e}")
                print("🔄 Deleting invalid token file and retrying with fresh interactive login...")

                # Delete the file
                try:
                    os.remove(TOKEN_FILE_PATH)
                    print(f"🗑️  Deleted {TOKEN_FILE_PATH}")
                except OSError:
                    pass

                # Retry
                await self._attempt_connection()
            else:
                # If we weren't using a cached token (or it was the second attempt), raise the error
                print(f"❌ Failed to connect: {e}")
                traceback.print_exc()  # <--- THIS REVEALS THE HIDDEN ERROR

    async def _attempt_connection(self):
        """Internal method to perform the actual connection logic."""
        print(f"🔗 Attempting to connect to {self.server_url}...")

        callback_server = None

        try:
            callback_server = CallbackServer(port=3030)
            callback_server.start()

            async def callback_handler() -> tuple[str, str | None]:
                """Wait for OAuth callback and return auth code and state."""
                print("⏳ Waiting for authorization callback...")
                try:
                    if callback_server:
                        auth_code = callback_server.wait_for_callback(timeout=300)
                        return auth_code, callback_server.get_state()
                    else:
                        raise Exception("Callback server not initialized")
                finally:
                    pass

            client_metadata_dict = {
                "client_name": "Simple Auth Client",
                "redirect_uris": ["http://localhost:3030/callback"],
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
            }

            async def _default_redirect_handler(authorization_url: str) -> None:
                """Default redirect handler that opens the URL in a browser."""
                print(f"Opening browser for authorization: {authorization_url}")
                webbrowser.open(authorization_url)

            # Initialize Storage (this will read from File if available)
            token_storage = FilePersistedTokenStorage()

            # Create OAuth authentication handler
            oauth_auth = OAuthClientProvider(
                server_url=self.server_url,
                client_metadata=OAuthClientMetadata.model_validate(client_metadata_dict),
                storage=token_storage,
                redirect_handler=_default_redirect_handler,
                callback_handler=callback_handler,
                client_metadata_url=self.client_metadata_url,
            )

            async def _make_connection(use_http2_version=True):
                # Create transport with auth handler based on transport type
                if self.transport_type == "sse":
                    print("📡 Opening SSE transport connection with auth...")
                    async with sse_client(
                            url=self.server_url,
                            auth=oauth_auth,
                            timeout=60.0,
                            httpx_client_factory=httpx_factory(use_http2_version)
                    ) as (read_stream, write_stream):
                        await self._run_session(read_stream, write_stream)
                else:
                    print("📡 Opening StreamableHTTP transport connection with auth...")
                    async with httpx_factory(use_http2_version=True, auth=oauth_auth, follow_redirects=True) as custom_client:
                        async with streamable_http_client(url=self.server_url, http_client=custom_client) as (
                                read_stream,
                                write_stream,
                                *_
                        ):
                            await self._run_session(read_stream, write_stream)
            try:
                await _make_connection()
            except Exception:
                # fallback to HTTP1
                # Create transport with auth handler based on transport type
                await _make_connection(False)
        finally:
            if callback_server:
                callback_server.stop()

    async def _run_session(
            self,
            read_stream: MemoryObjectReceiveStream[SessionMessage | Exception],
            write_stream: MemoryObjectSendStream[SessionMessage],
    ):
        """Run the MCP session with the given streams."""
        print("🤝 Initializing MCP session...")
        async with ClientSession(read_stream, write_stream) as session:
            self.session = session
            print("⚡ Starting session initialization...")
            await session.initialize()
            print("✨ Session initialization complete!")

            print(f"\n✅ Connected to MCP server at {self.server_url}")

            # Run interactive loop
            await self.interactive_loop(session)

    async def interactive_loop(self, session):
        print("Fetching available tools...")
        try:
            tools_response = await session.list_tools()
            tools = tools_response.tools
        except Exception as e:
            print(f"Error fetching tools: {e}")
            return

        while True:


            # Enumerate Tools
            print("\n-------------------------------------------")
            for idx, t in enumerate(tools):
                print(f"{idx + 1}. {t.name}")

            print("-------------------------------------------")
            print("0. Exit")

            choice = input("\nSelect a tool by number: ").strip()

            if choice == "0":
                print("Exiting...")
                break

            # Validate Input
            try:
                tool_idx = int(choice) - 1
                if tool_idx < 0 or tool_idx >= len(tools):
                    print("Invalid selection. Please try again.")
                    continue

                selected_tool = tools[tool_idx]

                # --- Sub-Menu Loop ---
                while True:
                    print(f"\n--- Tool: {selected_tool.name} ---")
                    print("1. Describe")
                    print("2. Call")
                    print("3. Back to Main Menu")

                    sub_choice = input("Select option: ").strip()

                    if sub_choice == "1":
                        # DESCRIBE
                        print(f"\n[Description]: {selected_tool.description}")
                        print(f"[Input Schema]:\n{json.dumps(selected_tool.inputSchema, indent=2)}")
                        input("\nPress Enter to continue...")

                    elif sub_choice == "2":
                        # CALL
                        print("\n--- parameter builder ---")
                        print("Press Enter to skip an optional parameter (empty values are discarded).")

                        # extract properties and required list from schema
                        properties = selected_tool.input_schema.get("properties", {})
                        required_list = selected_tool.input_schema.get("required", [])
                        final_arguments = {}

                        if not properties:
                            print("(No arguments required for this tool)")

                        for arg_name, arg_schema in properties.items():
                            arg_type = arg_schema.get("type", "string")
                            arg_desc = arg_schema.get("description", "")

                            # Check if this specific argument is in the required list
                            is_required = arg_name in required_list
                            req_label = "[REQUIRED]" if is_required else "[Optional]"

                            # Construct prompt
                            prompt_text = f" -> {arg_name} ({arg_type}) {req_label}"
                            if arg_desc:
                                prompt_text += f" - {arg_desc}"
                            prompt_text += ": "

                            user_val = input(prompt_text).strip()

                            # LOGIC: Only add if not empty
                            if user_val:
                                try:
                                    if arg_type == "integer":
                                        final_arguments[arg_name] = int(user_val)
                                    elif arg_type == "number":
                                        final_arguments[arg_name] = float(user_val)
                                    elif arg_type == "boolean":
                                        final_arguments[arg_name] = user_val.lower() in ('true', '1', 'yes')
                                    elif arg_type == "array":
                                        items_schema = arg_schema.get("items", {})
                                        items_type = items_schema.get("type", "string")
                                        if items_type == "object":
                                            parsed = json.loads(user_val)
                                            if not isinstance(parsed, list):
                                                parsed = [parsed]
                                            final_arguments[arg_name] = parsed
                                        else:
                                            # Simple types: split by comma or space
                                            parts = [v.strip() for v in user_val.replace(",", " ").split() if v.strip()]
                                            if items_type == "integer":
                                                parts = [int(p) for p in parts]
                                            elif items_type == "number":
                                                parts = [float(p) for p in parts]
                                            final_arguments[arg_name] = parts
                                    elif arg_type == "object":
                                        final_arguments[arg_name] = json.loads(user_val)
                                    else:
                                        final_arguments[arg_name] = user_val
                                except ValueError:
                                    print(
                                        f"⚠️ Warning: Could not convert '{user_val}' to {arg_type}. Sending as string.")
                                    final_arguments[arg_name] = user_val
                            elif is_required:
                                print(f"⚠️ Warning: '{arg_name}' is REQUIRED but you left it empty.")

                        print(f"\nSending arguments: {json.dumps(final_arguments, indent=2)}")
                        print(f"Calling {selected_tool.name}...")

                        try:
                            result = await session.call_tool(selected_tool.name, arguments=final_arguments)

                            print("\n[Result]:")
                            for content in result.content:
                                if content.type == 'text':
                                    print(content.text)
                                else:
                                    print(f"<{content.type} content>")
                        except Exception as e:
                            print(f"❌ Error calling tool: {e}")

                        input("\nPress Enter to continue...")

                    elif sub_choice == "3":
                        # BACK
                        break
                    else:
                        print("Invalid option.")

            except ValueError:
                print("Please enter a valid number.")


async def main():
    """Main entry point."""
    server_url = os.getenv("MCP_SERVER_URL")
    print(f"Server URL: {server_url}")
    if not server_url:
        print("Please set MCP_SERVER_URL environment variable.")
        exit()

    transport_type = os.getenv("MCP_TRANSPORT_TYPE", "streamable-http")
    client_metadata_url = os.getenv("MCP_CLIENT_METADATA_URL")

    print("🚀 Simple MCP Auth Client")
    print(f"Connecting to: {server_url}")
    print(f"Transport type: {transport_type}")
    if client_metadata_url:
        print(f"Client metadata URL: {client_metadata_url}")

    # Start connection flow
    client = SimpleAuthClient(server_url, transport_type, client_metadata_url)
    await client.connect()


def cli():
    """CLI entry point for uv script."""
    asyncio.run(main())


if __name__ == "__main__":
    cli()