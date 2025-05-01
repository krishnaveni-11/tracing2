from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import threading
import http.client

class ServerAHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        thread_id = threading.get_ident()
        print(f"\nServer A handling request in thread: {thread_id}")

        response_event = threading.Event()
        server_b_response = {}

        def call_server_b():
            conn = http.client.HTTPConnection("localhost", 8082, timeout=5)
            try:
                conn.request("GET", "/")
                resp = conn.getresponse()
                server_b_response['data'] = resp.read().decode()
            except Exception as e:
                server_b_response['data'] = f"Error: {e}"
            finally:
                conn.close()
                response_event.set()

        # Start background thread to call Server B
        threading.Thread(target=call_server_b).start()

        # Wait for Server B to respond
        response_event.wait(timeout=5)  # Wait max 5 seconds

        # Respond to client
        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.end_headers()

        message = (
            f"Server A (Thread {thread_id}) processed this request\n"
            f"Server B says: {server_b_response.get('data', 'No response')}"
        )
        self.wfile.write(message.encode())

if __name__ == "__main__":
    server_a = ThreadingHTTPServer(('', 8081), ServerAHandler)
    print("Server A running on port 8081 (multithreaded)...")
    server_a.serve_forever()
