"""Second project has different entry and endpoints, same execution profile."""
from http.server import BaseHTTPRequestHandler, HTTPServer

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/ready':
            self.send_response(204)
        elif self.path == '/metrics':
            self.send_response(200)
        else:
            self.send_response(404)
        self.send_header('Content-Length', '0')
        self.end_headers()

HTTPServer(('0.0.0.0', 8000), Handler).serve_forever()
