"""firstwatch in an OpenAI Agents SDK agent.

A tool output guardrail scans every result. `needs_approval` holds actions after an
attack, and the SDK hands them back to you as interruptions to approve or reject.

    pip install firstwatch openai-agents
    python examples/agents/openai_agents.py
"""

import asyncio
import json
import urllib.request

from agents import Agent, Runner, ToolGuardrailFunctionOutput, function_tool, tool_output_guardrail

from firstwatch_guard import Guard


def build_agent(model, guard):
    @tool_output_guardrail
    def scan_result(data):
        url = json.loads(data.context.tool_arguments or "{}").get("url")
        warn = guard.warn(data.output, data.context.tool_name, url=url)
        if not warn:
            return ToolGuardrailFunctionOutput.allow()
        return ToolGuardrailFunctionOutput.reject_content(f"{warn}\n\n{data.output}")  # warning + content

    def guarded(fn):
        async def held(ctx, args, call_id):
            return guard.needs_approval(fn.__name__)
        return function_tool(fn, needs_approval=held, tool_output_guardrails=[scan_result])

    @guarded
    def fetch_page(url: str) -> str:
        """Fetch a web page and return its HTML."""
        with urllib.request.urlopen(url, timeout=15) as res:
            return res.read(2_000_000).decode("utf-8", errors="replace")

    @guarded
    def send_email(to: str, body: str) -> str:
        """Send an email."""
        return f"(demo) sent to {to}"

    return Agent(name="assistant", instructions="Help the user.", model=model, tools=[fetch_page, send_email])


async def run_with_approvals(agent, task, guard):
    result = await Runner.run(agent, task)
    while result.interruptions:
        state = result.to_state()
        for item in result.interruptions:
            if guard.ask(item.name, item.arguments):
                state.approve(item)
            else:
                state.reject(item, rejection_message="The user declined this action.")
        result = await Runner.run(agent, state)
    return result


if __name__ == "__main__":
    guard = Guard(read_only={"fetch_page"})  # one per conversation
    agent = build_agent(None, guard)  # None = the SDK's default model
    result = asyncio.run(run_with_approvals(agent, "Summarise https://example.com", guard))
    print(result.final_output)
