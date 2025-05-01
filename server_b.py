from http.server import HTTPServer, BaseHTTPRequestHandler

class ServerBHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.end_headers()
        self.wfile.write(b"Response from Server B!\n")

if __name__ == "__main__":
    server_b = HTTPServer(('', 8082), ServerBHandler)
    print("Server B running on port 8082 (single-threaded)...")
    server_b.serve_forever()
