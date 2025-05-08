import asyncio
from aiohttp import web
import http.client
from concurrent.futures import ThreadPoolExecutor

executor = ThreadPoolExecutor()

# Blocking call to Server B using http.client
def call_server_b():
    conn = http.client.HTTPConnection("localhost", 8082, timeout=5)
    try:
        conn.request("GET", "/")
        resp = conn.getresponse()
        return resp.read().decode()
    except Exception as e:
        return f"Error: {e}"
    finally:
        conn.close()

async def handle(request):
    loop = asyncio.get_running_loop()
    task_id = id(asyncio.current_task())
    print(f"\nServer A handling request in async task: {task_id}")

    # Run blocking call in a thread
    server_b_response = await loop.run_in_executor(executor, call_server_b)

    message = (
        f"Server A (Task {task_id}) processed this request\n"
        f"Server B says: {server_b_response}"
    )

    return web.Response(text=message, content_type='text/plain')

app = web.Application()
app.router.add_get('/', handle)

if __name__ == "__main__":
    print("Server A running on port 8081 (event-driven + multithreaded)...")
    web.run_app(app, port=8081)
