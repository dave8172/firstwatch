"""firstwatch in a LangChain agent (create_agent, which runs on LangGraph).

    pip install firstwatch langchain langchain-anthropic   # or your model's package
    python examples/agents/langchain_agent.py

Your own LangGraph graph: give the same function to ToolNode,
`ToolNode(tools, wrap_tool_call=guarded(guard))`.
"""

import os
import urllib.request

from langchain.agents import create_agent
from langchain.agents.middleware import wrap_tool_call
from langchain.messages import ToolMessage
from langchain.tools import tool

from firstwatch_guard import Guard


@tool
def fetch_page(url: str) -> str:
    """Fetch a web page and return its HTML."""
    with urllib.request.urlopen(url, timeout=15) as res:
        return res.read(2_000_000).decode("utf-8", errors="replace")


@tool
def send_email(to: str, body: str) -> str:
    """Send an email."""
    return f"(demo) sent to {to}"


def guarded(guard):
    """Runs around every tool call: asks before it if needed, scans what it returns."""
    def wrapper(request, handler):
        call = request.tool_call
        if not guard.allow(call["name"], call["args"]):
            return ToolMessage("The user declined this action.", tool_call_id=call["id"], name=call["name"])
        result = handler(request)
        if isinstance(result, ToolMessage):
            result.content = guard.check(result.content, call["name"], url=call["args"].get("url"))
        return result
    return wrapper


def build_agent(model, guard):
    return create_agent(model, tools=[fetch_page, send_email], middleware=[wrap_tool_call(guarded(guard))])


if __name__ == "__main__":
    guard = Guard(read_only={"fetch_page"})  # one per conversation
    agent = build_agent(os.environ.get("MODEL", "anthropic:claude-haiku-5-5"), guard)
    out = agent.invoke({"messages": [{"role": "user", "content": "Summarise https://example.com"}]})
    print(out["messages"][-1].content)
