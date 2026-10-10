import { connect, createServer, type Socket } from "node:net";
import { once } from "node:events";
import assert from "node:assert/strict";
export async function wireServer(reply: Uint8Array | string) {
  const records: Buffer[] = [];
  const sockets = new Set<Socket>();
  const server = createServer((socket) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
    let buffer = Buffer.alloc(0), recorded = false;
    socket.on("data", (chunk) => {
      if (recorded) return;
      buffer = Buffer.concat([buffer, Buffer.from(chunk)]);
      const end = buffer.indexOf("\r\n\r\n");
      if (end < 0) return;
      const match = /\r\ncontent-length:\s*(\d+)/i.exec(
        buffer.subarray(0, end).toString("latin1"),
      );
      let complete = end + 4 + (match ? Number(match[1]) : 0);
      if (
        /\r\ntransfer-encoding:\s*chunked/i.test(
          buffer.subarray(0, end).toString("latin1"),
        )
      ) {
        let offset = end + 4;
        for (;;) {
          const line = buffer.indexOf("\r\n", offset);
          if (line < 0) return;
          const size = Number.parseInt(
            buffer.subarray(offset, line).toString().split(";")[0]!,
            16,
          );
          assert.ok(
            Number.isSafeInteger(size) && size >= 0,
            "valid chunk size",
          );
          offset = line + 2;
          if (size === 0) {
            if (buffer.subarray(offset, offset + 2).toString() === "\r\n") {
              complete = offset + 2;
            } else {
              const trailers = buffer.indexOf("\r\n\r\n", offset);
              if (trailers < 0) return;
              complete = trailers + 4;
            }
            break;
          }
          if (buffer.length < offset + size + 2) return;
          assert.equal(
            buffer.subarray(offset + size, offset + size + 2).toString(),
            "\r\n",
          );
          offset += size + 2;
        }
      }
      if (buffer.length < complete) return;
      recorded = true;
      records.push(buffer);
      socket.end(reply);
    });
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return {
    port: addr.port,
    records,
    async close() {
      server.close();
      for (const s of sockets) s.destroy();
    },
  };
}
export async function rawRequest(
  port: number,
  request: string,
): Promise<string> {
  const socket = connect(port, "127.0.0.1");
  const chunks: Buffer[] = [];
  socket.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
  await once(socket, "connect");
  socket.write(Buffer.from(request, "latin1"));
  await once(socket, "close");
  return Buffer.concat(chunks).toString("latin1");
}
