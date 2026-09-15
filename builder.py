import argparse
import py_compile

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
    builder.add_argument("--no-compile", action="store_true",
                     help="Skip .pyc compilation and output raw source.")
    builder.add_argument("--no-print", action="store_true",
                     help="Strip all print output from the generated client.")

    cfg = parser.add_argument_group("Client configuration")
    cfg.add_argument("--server-url", default="localhost:8080",
                     help="Server URL the client should connect to.")
    cfg.add_argument("-e", "--encryption-key", default="",
                     help="AES encryption key to embed (optional).")
    cfg.add_argument("--user-agent", default=USER_AGENT,
                     help="Custom HTTP/WebSocket User-Agent string (optional).")
    cfg.add_argument("--proxy", default="",
                     help="Proxy to use (optional).")

    retry = parser.add_argument_group("Retry behavior")
    retry.add_argument("--retry-duration", type=float, default=60.0,
                       help="Total time to retry connecting.")
    retry.add_argument("--retry-attempts", type=int, default=5,
                       help="Number of retry attempts before giving up.")

    behavior = parser.add_argument_group("Behavior")
    behavior.add_argument("--exit-on-close", action="store_true", default=False,
                          help="Call sys.exit() when the client stops instead of returning.")


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

    out_path = Path(args.name)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(rendered, encoding="utf-8")

    if args.no_compile:
        print(f"[+] Wrote Python client to '{out_path}'")
    else:
        pyc_path = out_path.with_suffix(".pyc")
        try:
            py_compile.compile(
                str(out_path), cfile=str(pyc_path), doraise=True,
                dfile=out_path.name
            )
            out_path.unlink()
            print(f"[+] Compiled Python client to '{pyc_path}'")
        except py_compile.PyCompileError as e:
            print(f"[!] Compilation failed: {e}")
            print(f"[*] Source written to '{out_path}'")

    if args.proxy:
        print("[!] Warning: ws:// through an HTTP proxy may fail — aiohttp sends it in absolute form instead of using CONNECT. Use wss:// with a proxy.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(usage=argparse.SUPPRESS)
    add_arguments(parser)
    parsed_args = parser.parse_args()
    build(parsed_args)
