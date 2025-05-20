from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

class ServerBHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"  # <-- Set protocol version to HTTP/1.1

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.send_header("Content-Length", str(len("Response from Server B!\n")))  # Needed for HTTP/1.1
        self.end_headers()
        self.wfile.write(b"Response from Server B!\n")

if __name__ == "__main__":
    server_b = ThreadingHTTPServer(('', 8082), ServerBHandler)
    print("Server B running on port 8082 (HTTP/1.1, multithreaded)...")
    server_b.serve_forever()
