# Introduction
A simple MCP client practical for enumerating/calling servers

# Setup
```commandline
uv pip install .
```

# Use
```commandline
export MCP_SERVER_URL=<YourMcpUrl>

#optionally set proxy if you also want to see the traffic exchanged
export HTTPS_PROXY=<your_proxy>
export HTTP_PROXY=<your_proxy>

python MCP_client.py
```
The client will try to connect using OAuth, after you successfully sign-in it will store the token to current folder with `.mcp_token` and re-use it in subsequent executions. !!!DONT FORGET TO DELETE IF SENSITIVE!!! 

After successful connection, the script will enumerate and print all available tools. Then you can select 1-X tool and either describe it (which will pull all info from server) or call it.
In the calling screen every expected argument is present with their description, you just need to input the values, if left empty the argument is not set