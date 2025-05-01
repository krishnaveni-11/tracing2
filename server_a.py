from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
import http.client  # Built-in alternative to requests

class ServerAHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # 1. Print thread ID (will be same for all requests)
        thread_id = threading.get_ident()
        print(f"\nServer A handling request in thread: {thread_id}")
        
        # 2. Call Server B
        conn = http.client.HTTPConnection("localhost:8082")
        try:
            conn.request("GET", "/")
            response = conn.getresponse()
            server_b_response = response.read().decode()
            print("Received from Server B:", server_b_response.strip())
        except Exception as e:
            server_b_response = f"Error: {str(e)}"
            print("Failed to contact Server B:", server_b_response)
        finally:
            conn.close()

        # 3. Respond to client
        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.end_headers()
        message = (
            f"Server A (Thread {thread_id}) processed this request\n"
            f"Server B says: {server_b_response}"
        )
        self.wfile.write(message.encode())

if __name__ == "__main__":
    server_a = HTTPServer(('', 8081), ServerAHandler)
    print("Server A running on port 8081 (single-threaded)...")
    server_a.serve_forever()
