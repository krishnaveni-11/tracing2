from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import threading
import http.client

class ServerAHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def handle(self):
        # Persistent connections to Server B and Server C
        self.conn_to_b = http.client.HTTPConnection("localhost", 8082, timeout=5)
        self.conn_to_b.connect()

        self.conn_to_c = http.client.HTTPConnection("localhost", 8083, timeout=5)
        self.conn_to_c.connect()

        # Locks for each connection
        self.conn_b_lock = threading.Lock()
        self.conn_c_lock = threading.Lock()

        super().handle()

        # Close both connections when done
        self.conn_to_b.close()
        self.conn_to_c.close()

    def do_GET(self):
        thread_id = threading.get_ident()
        print(f"Server A connection thread: {thread_id} received a request")

        # Shared dictionaries to hold responses
        server_b_response = {}
        server_c_response = {}

        # First worker: query Server B
        def call_server_b():
            with self.conn_b_lock:
                try:
                    self.conn_to_b.request("GET", "/")
                    resp = self.conn_to_b.getresponse()
                    data = resp.read().decode()
                    server_b_response['data'] = data
                except Exception as e:
                    server_b_response['data'] = f"Error from B: {e}"

        # Second worker: query Server C
        def call_server_c():
            with self.conn_c_lock:
                try:
                    self.conn_to_c.request("GET", "/")
                    resp = self.conn_to_c.getresponse()
                    data = resp.read().decode()
                    server_c_response['data'] = data
                except Exception as e:
                    server_c_response['data'] = f"Error from C: {e}"

        # Step 1: call Server B
        worker_b = threading.Thread(target=call_server_b)
        worker_b.start()
        worker_b.join(timeout=5)

        # Step 2: call Server C after Server B response
        worker_c = threading.Thread(target=call_server_c)
        worker_c.start()
        worker_c.join(timeout=5)

        # Combine the responses
        message = (
            f"Server A (connection thread {thread_id}) processed this request\n"
            f"Server B says: {server_b_response.get('data', 'No response from B')}\n"
            f"Server C says: {server_c_response.get('data', 'No response from C')}"
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
