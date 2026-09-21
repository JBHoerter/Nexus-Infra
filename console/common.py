"""Small, bounded HTTP primitives shared by the console and host agents."""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn


class HTTPError(Exception):
    def __init__(self, status, message):
        self.status, self.message = status, message


class Server(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    slots = threading.BoundedSemaphore(24)

    def get_request(self):
        sock, address = super().get_request()
        sock.settimeout(10)
        return sock, address

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            request.close()
            return
        try:
            super().process_request(request, address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()


class Handler(BaseHTTPRequestHandler):
    server_version = 'Nexus'
    sys_version = ''

    def log_message(self, *_):
        pass  # Never log passwords, cookies, URLs with queries or request bodies.

    def send(self, status, data, content_type='application/json', headers=None):
        if content_type == 'application/json':
            data = json.dumps(data, allow_nan=False).encode()
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)

    def body(self, keys, limit=2048):
        if self.headers.get('Transfer-Encoding') or self.headers.get_content_type() != 'application/json':
            raise HTTPError(415, 'A JSON body is required')
        try:
            size = int(self.headers.get('Content-Length', '-1'))
            if not 0 <= size <= limit:
                raise ValueError()
            value = json.loads(self.rfile.read(size))
            if not isinstance(value, dict) or set(value) != set(keys):
                raise ValueError()
            return value
        except (ValueError, UnicodeError):
            raise HTTPError(400, 'Invalid request')

    def do_GET(self):
        self.dispatch('GET')

    def do_POST(self):
        self.dispatch('POST')

    def dispatch(self, method):
        try:
            self.route(method)
        except HTTPError as error:
            self.send(error.status, {'error': error.message})
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            pass
        except Exception as error:
            print(json.dumps({'event': 'request-error', 'type': type(error).__name__}), flush=True)
            self.send(500, {'error': 'Internal service error'})
