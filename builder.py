def add_arguments(parser):
    # --- Client configuration ---
    cfg = parser.add_argument_group("Client configuration")
    cfg.add_argument("-l", "--language",
                     choices=["python", "csharp", "node", "ruby"],
                     help="Client language to build.")
    cfg.add_argument("--server-url",
                     help="Server URL the client should connect to.")
    cfg.add_argument("-e", "--encryption-key", default=None,
                     help="AES encryption key to embed (optional).")
    cfg.add_argument("--messenger-id", default=None,
                     help="Hardcoded messenger/client ID (optional).")
    cfg.add_argument("--user-agent", default=None,
                     help="Custom HTTP/WebSocket User-Agent string (optional).")
    cfg.add_argument(
        "--remote-port-forwards",
        metavar="str",
        help=("Comma-separated LOCAL_IP:LOCAL_PORT:REMOTE_IP:REMOTE_PORT\n"
              "Example: 0.0.0.0:9001:127.0.0.1:22,10.0.0.5:8080:192.168.1.10:80")
    )

    # --- Retry behavior ---
    retry = parser.add_argument_group("Retry behavior")
    retry.add_argument("--retry-duration", type=float, default=1.0,
                       help="Seconds to wait between retry attempts.")
    retry.add_argument("--retry-attempts", type=int, default=5,
                       help="Number of retry attempts before giving up.")

    # --- Advanced ---
    adv = parser.add_argument_group("Advanced (repository)")
    adv.add_argument("--update-submodules", action="store_true",
                     help="Update git submodules before building.")
    adv.add_argument("--submodule-branch", default="main",
                     help="Branch to checkout in each submodule.")

def build(args):
    pass