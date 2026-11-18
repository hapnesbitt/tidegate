"""Stand-in for Docker's port publishing on a real server: 127.0.0.1:2525 inside the edge -> Tidegate's mta:25.
While it isn't running, connections to 127.0.0.1:2525 are refused, as on a server whose Tidegate container is down."""
import asyncio
import os

UPSTREAM = ("172.31.241.25", 25)


async def pipe(reader, writer):
    try:
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
    except ConnectionError:
        pass
    finally:
        writer.close()


async def handle(client_r, client_w):
    try:
        up_r, up_w = await asyncio.open_connection(*UPSTREAM)
    except OSError:
        client_w.close()
        return
    await asyncio.gather(pipe(client_r, up_w), pipe(up_r, client_w))


async def main():
    server = await asyncio.start_server(handle, "127.0.0.1", 2525)
    with open("/run/forward.pid", "w") as fh:
        fh.write(str(os.getpid()))
    async with server:
        await server.serve_forever()

asyncio.run(main())
