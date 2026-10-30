# Agent frameworks

firstwatch in a Python agent you build yourself: LangChain and LangGraph, the OpenAI Agents SDK, CrewAI, or your own loop. Each quickstart gives you what the Claude Code hooks give you:

- **Scan.** Every tool result is scanned. On an attack, the model gets a warning beside the content, and the evidence is saved as a capture.
- **Gate.** After an attack, every tool that doesn't only read waits for the user's OK, for the rest of that conversation.

All four use one small file, [`examples/agents/firstwatch_guard.py`](../examples/agents/firstwatch_guard.py). Copy it next to your agent. It needs only `pip install firstwatch`.

```python
from firstwatch_guard import Guard

guard = Guard(read_only={"fetch_page", "search"})  # one per conversation
```

`read_only` names the tools that only read. Everything else asks after an attack. `ask` decides how: the default asks in the terminal. In an app, pass your own function `(tool, args) -> bool`.

## Your own loop

Wherever your loop runs a tool the model asked for:

```python
def run_tool(name, args):
    if not guard.allow(name, args):
        return "The user declined this action."
    return guard.check(TOOLS[name](**args), name, url=args.get("url"))
```

Full file: [`plain_python.py`](../examples/agents/plain_python.py). Run it to see a page with a hidden attack, then the email the attack wanted, held: `python examples/agents/plain_python.py`.

## LangChain and LangGraph

One function around every tool call, used as middleware in `create_agent`:

```python
from langchain.agents import create_agent
from langchain.agents.middleware import wrap_tool_call
from langchain.messages import ToolMessage

def guarded(guard):
    def wrapper(request, handler):
        call = request.tool_call
        if not guard.allow(call["name"], call["args"]):
            return ToolMessage("The user declined this action.", tool_call_id=call["id"], name=call["name"])
        result = handler(request)
        if isinstance(result, ToolMessage):
            result.content = guard.check(result.content, call["name"], url=call["args"].get("url"))
        return result
    return wrapper

agent = create_agent(model, tools=tools, middleware=[wrap_tool_call(guarded(guard))])
```

Your own LangGraph graph: `ToolNode(tools, wrap_tool_call=guarded(guard))`.

Full file: [`langchain_agent.py`](../examples/agents/langchain_agent.py).

## OpenAI Agents SDK

A tool output guardrail scans each result. `needs_approval` holds actions after an attack, and the SDK returns them to you as interruptions:

```python
from agents import ToolGuardrailFunctionOutput, function_tool, tool_output_guardrail

@tool_output_guardrail
def scan_result(data):
    url = json.loads(data.context.tool_arguments or "{}").get("url")
    warn = guard.warn(data.output, data.context.tool_name, url=url)
    if not warn:
        return ToolGuardrailFunctionOutput.allow()
    return ToolGuardrailFunctionOutput.reject_content(f"{warn}\n\n{data.output}")

def guarded(fn):
    async def held(ctx, args, call_id):
        return guard.needs_approval(fn.__name__)
    return function_tool(fn, needs_approval=held, tool_output_guardrails=[scan_result])
```

Then approve or reject each held call:

```python
result = await Runner.run(agent, task)
while result.interruptions:
    state = result.to_state()
    for item in result.interruptions:
        if guard.ask(item.name, item.arguments):
            state.approve(item)
        else:
            state.reject(item, rejection_message="The user declined this action.")
    result = await Runner.run(agent, state)
```

`reject_content` is how a guardrail changes what the model sees. Here it passes the page on, with the warning in front.

Full file: [`openai_agents.py`](../examples/agents/openai_agents.py).

## CrewAI

CrewAI's tool call hooks. A `before` hook that returns `False` stops the call. An `after` hook that returns a string replaces the result:

```python
from crewai.hooks import register_after_tool_call_hook, register_before_tool_call_hook

def before(ctx):
    return None if guard.allow(ctx.tool_name, ctx.tool_input) else False

def after(ctx):
    return guard.check(ctx.tool_result, ctx.tool_name, url=ctx.tool_input.get("url"))

register_before_tool_call_hook(before)
register_after_tool_call_hook(after)
```

These hooks are global: they run for every agent in the process. Use one Guard per crew run, and unregister the hooks when it ends. Full file: [`crewai_agent.py`](../examples/agents/crewai_agent.py).

## Try them without a model

[`try_offline.py`](../examples/agents/try_offline.py) runs each quickstart with a scripted model that acts hijacked. It fetches a page with a hidden attack, then tries to email the user's key to the attacker. The user says no.

```bash
pip install firstwatch langchain        # or openai-agents, or crewai
cd examples/agents
python try_offline.py langchain         # or openai-agents, or crewai
```

It prints the warning the model got, what happened to the email, and where the evidence was saved. It ends with `OK` when all three happened.

**Tested** on 2026-10-30 with scripted models (no real model), on Python 3.12: langchain 1.4.7 with langgraph 1.2.18 (both `create_agent` and a `ToolNode` graph), openai-agents 0.24.0, crewai 1.15.33. In all three, the model got the warning, the email was held and refused, and the capture was saved.

## Limits

- **The model decides what to do with the warning.** The scan and the gate are code. The warning is words, measured on one model ([agent-study.md](agent-study.md)).
- **Calls in the same step.** If the model asks for a page and an outward action in one step, the action can be approved before the page is scanned. The gate applies from the next step.
- **You name the read-only tools.** A tool left out of `read_only` asks after an attack. A tool put in by mistake doesn't.
