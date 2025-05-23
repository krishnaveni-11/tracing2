from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from datetime import datetime

class SimpleCollector(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/log":
            self.send_response(404)
            self.end_headers()
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

        timestamp = datetime.utcnow().isoformat()
        log_line = f"[{timestamp}] {log}"
        print(log_line)

        with open("collector_logs.log", "a") as f:
            f.write(log_line + "\n")

        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"Log received")

if __name__ == "__main__":
    server_address = ('0.0.0.0', 5000)
    httpd = HTTPServer(server_address, SimpleCollector)
    print("Collector server running on port 5000...")
    httpd.serve_forever()
