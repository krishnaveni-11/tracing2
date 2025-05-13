from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import threading
import http.client

# Global persistent connection to Server B (localhost:8082)
conn_lock = threading.Lock()
persistent_conn = http.client.HTTPConnection("localhost", 8082, timeout=5)
persistent_conn.connect()  # Establish TCP connection early

class ServerAHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"  # Use HTTP/1.1

    def do_GET(self):
        thread_id = threading.get_ident()
        print(f"\nServer A handling request in thread: {thread_id}")

        # Dictionary to hold Server B's response
        server_b_response = {}

        def call_server_b():
            with conn_lock:
                try:
                    persistent_conn.request("GET", "/")
                    resp = persistent_conn.getresponse()
                    data = resp.read().decode()
                    server_b_response['data'] = data
                except Exception as e:
                    server_b_response['data'] = f"Error: {e}"

        # Launch a thread to perform the request to Server B
        worker_thread = threading.Thread(target=call_server_b)
        worker_thread.start()
        worker_thread.join(timeout=5)

        message = (
            f"Server A (Thread {thread_id}) processed this request\n"
            f"Server B says: {server_b_response.get('data', 'No response')}"
        ).encode()

        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.send_header("Content-Length", str(len(message)))
        self.end_headers()
        self.wfile.write(message)

if __name__ == "__main__":
    server_a = ThreadingHTTPServer(('', 8081), ServerAHandler)
    print("Server A running on port 8081 (HTTP/1.1, multithreaded with connection reuse)...")
    try:
        server_a.serve_forever()
    finally:
        persistent_conn.close()
