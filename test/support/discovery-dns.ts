import { createSocket } from "node:dgram";
import assert from "node:assert/strict";
export async function dnsPublisher() {
  const socket = createSocket("udp4");
  let a = "127.0.0.1",
    aaaa = "::1",
    rebind = false,
    copies = 1,
    rcode = 0;
  const queries: number[] = [];
  socket.on("message", (query, remote) => {
    let end = 12;
    while (query[end] !== 0) {
      end += query[end]! + 1;
      if (end >= query.length) return;
    }
    end += 5;
    const type = query.readUInt16BE(end - 4);
    queries.push(type);
    const ip = type === 1 ? a : type === 28 ? aaaa : "";
    let data: Buffer | undefined;
    if (ip && type === 1) data = Buffer.from(ip.split(".").map(Number));
    if (ip && type === 28) {
      assert.equal(ip, "::1");
      data = Buffer.alloc(16);
      data[15] = 1;
    }
    const head = Buffer.alloc(12);
    query.copy(head, 0, 0, 2);
    // Authoritative answer with the selected response code: 0 NOERROR,
    // 2 SERVFAIL, 3 NXDOMAIN.
    head.writeUInt16BE(0x8580 | rcode, 2);
    head.writeUInt16BE(1, 4);
    const answers = data && rcode === 0 ? (type === 1 ? copies : 1) : 0;
    head.writeUInt16BE(answers, 6);
    const rr = Buffer.alloc(12);
    rr.writeUInt16BE(0xc00c, 0);
    rr.writeUInt16BE(type, 2);
    rr.writeUInt16BE(1, 4);
    rr.writeUInt32BE(0, 6);
    rr.writeUInt16BE(data?.length ?? 0, 10);
    const response = Buffer.concat([
      head,
      query.subarray(12, end),
      ...Array.from({ length: answers }, () => [rr, data!]).flat(),
    ]);
    socket.send(response, remote.port, remote.address);
    if (rebind && queries.length % 2 === 0) a = "169.254.169.254";
  });
  await new Promise<void>((done, fail) => {
    socket.once("error", fail);
    socket.bind(0, "127.0.0.1", done);
  });
  const port = socket.address().port;
  return {
    server: `127.0.0.1:${port}`,
    queries,
    set(ip: string, v6 = "") {
      a = ip;
      aaaa = v6;
    },
    /** Repeat the A answer; resolvers return every record, duplicates included. */
    repeat(n: number) {
      copies = n;
    },
    /** Answer every query with the selected DNS response code and no records. */
    fail(code: number) {
      rcode = code;
    },
    rebind() {
      a = "127.0.0.1";
      aaaa = "::1";
      rebind = true;
    },
    close: () => new Promise<void>((done) => socket.close(() => done())),
  };
}
