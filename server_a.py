from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import threading
import http.client

class ServerAHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    # We override handle() to setup per-connection attributes
    def handle(self):
        # Setup one persistent connection and lock per client connection thread
        self.conn_to_b = http.client.HTTPConnection("localhost", 8082, timeout=5)
        self.conn_to_b.connect()
        self.conn_lock = threading.Lock()

        # Call parent handle() to process requests in this connection
        super().handle()

        # Close Server B connection when client disconnects
        self.conn_to_b.close()

    def do_GET(self):
        thread_id = threading.get_ident()
        print(f"Server A connection thread: {thread_id} received a request")

        # Dictionary to hold Server B's response from worker thread
        server_b_response = {}

        # Worker thread function to call Server B
        def call_server_b():
            with self.conn_lock:
                try:
                    self.conn_to_b.request("GET", "/")
                    resp = self.conn_to_b.getresponse()
                    data = resp.read().decode()
                    server_b_response['data'] = data
                except Exception as e:
                    server_b_response['data'] = f"Error: {e}"

        # Spawn a child worker thread to issue request to Server B
        worker_thread = threading.Thread(target=call_server_b)
        worker_thread.start()
        worker_thread.join(timeout=5)

        message = (
            f"Server A (connection thread {thread_id}) processed this request\n"
            f"Server B says: {server_b_response.get('data', 'No response')}"
        ).encode()

        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.send_header("Content-Length", str(len(message)))
        self.end_headers()
        self.wfile.write(message)


if __name__ == "__main__":
    server_a = ThreadingHTTPServer(('', 8081), ServerAHandler)
    print("Server A running on port 8081 (HTTP/1.1, multithreaded with per-connection persistent connection)...")
    server_a.serve_forever()
