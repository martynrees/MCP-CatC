# Catalyst Center MCP Server

A Python-based MCP (Model Context Protocol) server designed to integrate Cisco Catalyst Center with Claude desktop.

## Overview

The Catalyst Center MCP Server provides a bridge between Cisco Catalyst Center network management platform and Claude desktop application. It enables network administrators to leverage Claude's capabilities for enhanced network monitoring, troubleshooting, and management through a convenient desktop interface.

## Requirements

- Python 3.10+
- Cisco Catalyst Center
- Claude Desktop application 


## Installation

1. Clone this repository:
```bash
git clone https://github.com/CozmaSerban/MCP-CatC.git
```


2. Let’s install *uv* and set up our Python project and environment:
```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

3. Let's create the project
```bash

# Create a new directory for our project
uv init MCP-Server
cd MCP-Server

# Create virtual environment and activate it
uv venv
source .venv/bin/activate

# Install dependencies
uv add "mcp[cli]" httpx

# Create our server file
cp ../MCP-CatC/main.py ./main.py
```

3.Adding MCP to Claude Desktop App
  - Open Claude Desktop App
  - Go to Settings
  - Navigate to the MCP section
  - Click "Developer" on the left hand side
  - Click "Edit Config"
  - Create/Edit a file entering the following details:
  ```bash
{
  "mcpServers": {
    "MCP-CatC": {
      "command": "/Users/scozma/.local/bin/uv",
      "args": [
        "--directory",
        "/PATH/TO/MCP-Server",
        "run",
        "main.py"
      ]
    }
  }
```
Restart app

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
