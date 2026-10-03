"""Minimal syslog receiver standing in for a SIEM in the demo: prints every event it gets on UDP and TCP 5514."""

import socketserver
import sys
import threading


class Udp(socketserver.BaseRequestHandler):
    def handle(self):
        print(self.request[0].decode("utf-8", "replace").strip(), flush=True)


class Tcp(socketserver.StreamRequestHandler):
    def handle(self):
        for line in self.rfile:
            print(line.decode("utf-8", "replace").strip(), flush=True)


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5514
    tcp = socketserver.ThreadingTCPServer(("0.0.0.0", port), Tcp)
    threading.Thread(target=tcp.serve_forever, daemon=True).start()
    print(f"SIEM receiver listening on udp/tcp {port}", flush=True)
    socketserver.UDPServer(("0.0.0.0", port), Udp).serve_forever()
