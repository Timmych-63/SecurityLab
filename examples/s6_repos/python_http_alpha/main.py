"""Small HTTP fixture; requires only Python standard library."""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

class API(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/health':
            body = json.dumps({'status': 'ok'}).encode()
            self.send_response(200)
        elif self.path == '/v1/items':
            body = b'[]'
            self.send_response(200)
        else:
            body = b'not found'
            self.send_response(404)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

ThreadingHTTPServer(('0.0.0.0', 8000), API).serve_forever()
