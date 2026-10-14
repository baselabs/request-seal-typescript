import { createServer, type Server } from "node:https";
import type { RequestListener } from "node:http";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import type { Socket } from "node:net";
import assert from "node:assert/strict";
export type Peer = {
  server: Server;
  tlsOptions: {key: Uint8Array; cert: Uint8Array; ca: Uint8Array};
  port: number;
  ca: Uint8Array;
  address: string;
  requests: number;
  connections: number;
  close: () => Promise<void>;
};
export async function peer(
  listener: RequestListener,
  address = "127.0.0.1",
  altNames = "DNS:localhost,DNS:directory.test,IP:127.0.0.1,IP:::1",
): Promise<Peer> {
  const root = await mkdtemp(resolve("test/.tmp-discovery-tls-"));
  let server: Server | undefined;
  try {
    const run = (args: string[]) =>
      execFileSync("openssl", args, {
        cwd: root,
        stdio: "ignore",
        timeout: 10000,
      });
    run([
      "req",
      "-x509",
      "-newkey",
      "rsa:2048",
      "-nodes",
      "-keyout",
      "ca.key",
      "-out",
      "ca.pem",
      "-days",
      "1",
      "-subj",
      // A unique name per peer: tests trust several peers' CAs at once, and with two same-named CAs
      // a leaf without an authority key identifier (OpenSSL 4 and LibreSSL add none by default)
      // can be checked against the wrong CA (CERT_SIGNATURE_FAILURE).
      `/CN=Discovery Test CA ${randomUUID()}`,
      "-addext",
      "basicConstraints=critical,CA:TRUE",
    ]);
    run([
      "req",
      "-newkey",
      "rsa:2048",
      "-nodes",
      "-keyout",
      "leaf.key",
      "-out",
      "leaf.csr",
      "-subj",
      "/CN=localhost",
    ]);
    await writeFile(
      join(root, "ext.cnf"),
      `subjectAltName=${altNames}\nbasicConstraints=critical,CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n`,
    );
    run([
      "x509",
      "-req",
      "-in",
      "leaf.csr",
      "-CA",
      "ca.pem",
      "-CAkey",
      "ca.key",
      "-CAcreateserial",
      "-out",
      "leaf.pem",
      "-days",
      "1",
      "-extfile",
      "ext.cnf",
    ]);
    run(["x509", "-in", "ca.pem", "-outform", "DER", "-out", "ca.der"]);
    const [key, cert, ca] = await Promise.all([
      readFile(join(root, "leaf.key")),
      readFile(join(root, "leaf.pem")),
      readFile(join(root, "ca.der")),
    ]);
    server = createServer({ key, cert }, (req, res) => {
      result.requests++;
      listener(req, res);
    });
    const sockets = new Set<Socket>();
    const result: Peer = {
      server,
      tlsOptions: {key: new Uint8Array(key), cert: new Uint8Array(cert), ca: new Uint8Array(ca)},
      port: 0,
      ca: new Uint8Array(ca),
      address,
      requests: 0,
      connections: 0,
      async close() {
        for (const socket of sockets) socket.destroy();
        await new Promise<void>((done) => server!.close(() => done()));
      },
    };
    server.on("connection", (socket) => {
      result.connections++;
      sockets.add(socket);
      socket.on("close", () => sockets.delete(socket));
    });
    await new Promise<void>((done, fail) => {
      server!.once("error", fail);
      server!.listen(0, address, () => {
        server!.removeListener("error", fail);
        done();
      });
    });
    const bound = server.address();
    assert.ok(bound && typeof bound === "object");
    result.port = bound.port;
    return result;
  } catch (error) {
    server?.close();
    throw error;
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}
export const jwk = Object.freeze({
  kty: "OKP",
  crv: "Ed25519",
  x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
});
export const kid = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k";
export const jwks = () => JSON.stringify({ keys: [jwk] });
