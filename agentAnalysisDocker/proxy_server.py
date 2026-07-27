"""Minimal HTTPS CONNECT proxy with a hostname allowlist.

Runs INSIDE the egress-gateway container (started by network_rules.py). The
agent container can reach only this proxy (it sits on a Docker --internal
network with no other route out), and this proxy only tunnels to the
allowlisted hosts. So the agent can talk to the model API and nothing else on
the internet.

The allowlist comes from the ALLOWED_HOSTS env var (comma-separated). Only the
CONNECT method (HTTPS tunnelling) is served; plain HTTP is refused. The proxy
never decrypts the TLS — it decides purely on the CONNECT target hostname.
"""
import os
import select
import socket
import threading

ALLOWED = {h.strip().lower() for h in os.environ.get('ALLOWED_HOSTS', '').split(',') if h.strip()}
LISTEN_PORT = int(os.environ.get('PROXY_PORT', '8888'))


def host_allowed(host):
    """True if host is an allowlisted host or a subdomain of one."""
    host = host.lower()
    return any(host == a or host.endswith('.' + a) for a in ALLOWED)


def _pipe(a, b):
    """Relay bytes both ways between two sockets until either side closes."""
    a.settimeout(None)
    b.settimeout(None)
    socks = [a, b]
    while True:
        readable, _, errored = select.select(socks, [], socks, 60)
        if errored or not readable:
            break
        for s in readable:
            other = b if s is a else a
            try:
                data = s.recv(65536)
            except OSError:
                return
            if not data:
                return
            other.sendall(data)


def handle(client):
    """Serve one CONNECT request: check the allowlist, then tunnel."""
    upstream = None
    try:
        client.settimeout(30)
        req = b''
        while b'\r\n\r\n' not in req:
            chunk = client.recv(4096)
            if not chunk:
                return
            req += chunk

        line = req.split(b'\r\n', 1)[0].decode('latin1')
        parts = line.split(' ')
        if len(parts) < 2 or parts[0].upper() != 'CONNECT':
            client.sendall(b'HTTP/1.1 405 Method Not Allowed\r\n\r\n')
            return

        host, _, port = parts[1].partition(':')
        port = int(port or '443')
        if not host_allowed(host):
            client.sendall(b'HTTP/1.1 403 Forbidden\r\n\r\n')
            return

        try:
            upstream = socket.create_connection((host, port), timeout=30)
        except OSError:
            client.sendall(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
            return

        client.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
        _pipe(client, upstream)
    except Exception:
        pass
    finally:
        client.close()
        if upstream is not None:
            upstream.close()


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('0.0.0.0', LISTEN_PORT))
    srv.listen(128)
    print(f'egress proxy listening on :{LISTEN_PORT}, allow={sorted(ALLOWED)}', flush=True)
    while True:
        client, _ = srv.accept()
        threading.Thread(target=handle, args=(client,), daemon=True).start()


if __name__ == '__main__':
    main()
