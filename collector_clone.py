from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from datetime import datetime
import os

class SimpleCollector(BaseHTTPRequestHandler):
    def do_POST(self):
        # Define a mapping from path to log file
        path_map = {
            "/log/clone": "clone.log",
            "/log/event": "event.log",
            "/log/seq": "seq.log",
        }

        # If path is not recognized, return 404
        if self.path not in path_map:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Endpoint not found")
            return

        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)

        try:
            log = json.loads(post_data.decode('utf-8'))
        except json.JSONDecodeError:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"Invalid JSON")
            return

        # Get current timestamp and log line
        timestamp = datetime.utcnow().isoformat()
        log_line = f"[{timestamp}] {log}"

        print(log_line)

        # Write to corresponding log file
        log_filename = path_map[self.path]
        with open(log_filename, "a") as f:
            f.write(log_line + "\n")

        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"Log received")

if __name__ == "__main__":
    server_address = ('0.0.0.0', 5000)
    httpd = HTTPServer(server_address, SimpleCollector)
    print("Collector server running on port 5000...")
    httpd.serve_forever()
