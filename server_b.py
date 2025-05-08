from aiohttp import web
import asyncio
from concurrent.futures import ThreadPoolExecutor
import time

executor = ThreadPoolExecutor()

# Simulate a blocking task that runs in a separate thread
def blocking_response():
    # Simulate processing delay
    time.sleep(0.1)
    return "Response from Server B!\n"

async def handle(request):
    loop = asyncio.get_running_loop()
    response_text = await loop.run_in_executor(executor, blocking_response)
    return web.Response(text=response_text, content_type='text/plain')

app = web.Application()
app.router.add_get('/', handle)

if __name__ == "__main__":
    print("Server B running on port 8082 (event-driven + multithreaded)...")
    web.run_app(app, port=8082)
