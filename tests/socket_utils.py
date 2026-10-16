"""Various socket utilities for testing."""

import sys
import socket
import time
import signal


# pylint:  disable-next=invalid-name
def get_TCP() -> socket.socket:
    """Create a TCP IP4/6 socket."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("", 0))
    return sock


def main(hoard: bool = False) -> None:
    """Bind a TCP socket, print the port and hold if needed."""
    try:
        with get_TCP() as sock:
            print(sock.getsockname()[1], flush=True)
            if hoard:
                # So that if this is run on background the SIGINT is not ignored
                # due to Bash.
                signal.signal(signal.SIGINT, signal.default_int_handler)
                sock.listen()
            while hoard:
                time.sleep(1)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    if len(sys.argv) not in (1, 2):
        print(sys.stderr, "Run with: python socket_utils.py [hoard]")
        sys.exit(1)
    if len(sys.argv) == 2:
        assert sys.argv[1] == "hoard"
        main(True)
    else:
        main()
