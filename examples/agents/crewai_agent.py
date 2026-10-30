"""firstwatch in a CrewAI crew, through CrewAI's tool call hooks.

    pip install firstwatch crewai
    python examples/agents/crewai_agent.py

CrewAI's hooks are global: they run for every agent in the process. Use one Guard
per crew run, and unregister the hooks when that run ends (shown below).
"""

import urllib.request

from crewai import Agent, Crew, Task
from crewai.hooks import (register_after_tool_call_hook, register_before_tool_call_hook,
                          unregister_after_tool_call_hook, unregister_before_tool_call_hook)
from crewai.tools import tool

from firstwatch_guard import Guard


@tool("fetch_page")
def fetch_page(url: str) -> str:
    """Fetch a web page and return its HTML."""
    with urllib.request.urlopen(url, timeout=15) as res:
        return res.read(2_000_000).decode("utf-8", errors="replace")


@tool("send_email")
def send_email(to: str, body: str) -> str:
    """Send an email."""
    return f"(demo) sent to {to}"


def add_hooks(guard):
    def before(ctx):
        return None if guard.allow(ctx.tool_name, ctx.tool_input) else False  # False = don't run it

    def after(ctx):
        return guard.check(ctx.tool_result, ctx.tool_name, url=ctx.tool_input.get("url"))

    register_before_tool_call_hook(before)
    register_after_tool_call_hook(after)
    return lambda: (unregister_before_tool_call_hook(before), unregister_after_tool_call_hook(after))


def build_crew(llm, task):
    agent = Agent(role="Assistant", goal="Help the user", backstory="A careful assistant.",
                  tools=[fetch_page, send_email], llm=llm)
    return Crew(agents=[agent], tasks=[Task(description=task, expected_output="An answer", agent=agent)])


if __name__ == "__main__":
    guard = Guard(read_only={"fetch_page"})  # one per crew run
    remove_hooks = add_hooks(guard)
    try:
        print(build_crew("anthropic/claude-haiku-5-5", "Summarise https://example.com").kickoff())
    finally:
        remove_hooks()
