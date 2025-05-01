from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

class ServerBHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.end_headers()
        self.wfile.write(b"Response from Server B!\n")

if __name__ == "__main__":
    server_b = ThreadingHTTPServer(('', 8082), ServerBHandler)
    print("Server B running on port 8082 (multithreaded)...")
    server_b.serve_forever()
