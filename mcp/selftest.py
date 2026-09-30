#!/usr/bin/env python3
"""SecForge MCP 自检 —— 用真实 MCP 协议(stdio)连一次服务器, 验证 Hermes 能不能接上。

用法: <工具箱路径>/.venv/bin/python <工具箱路径>/mcp/selftest.py
"""
import asyncio
import os
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = os.path.join(ROOT, ".venv", "bin", "python")
SERVER = os.path.join(ROOT, "mcp", "server.py")


async def main():
    params = StdioServerParameters(command=PY, args=[SERVER], env={})
    async with stdio_client(params) as (r, w):
        async with ClientSession(r, w) as s:
            init = await s.initialize()
            print(f"MCP 握手成功: {init.serverInfo.name} v{init.serverInfo.version}")
            tools = await s.list_tools()
            print(f"Hermes 会看到 {len(tools.tools)} 个工具:")
            for t in tools.tools:
                print(f"  {t.name:<24} {(t.description or '').splitlines()[0][:70]}")
            print("\n--- 实调一个: sec_overview ---")
            res = await s.call_tool("sec_overview", {})
            for c in res.content:
                print(getattr(c, "text", c))


asyncio.run(main())
