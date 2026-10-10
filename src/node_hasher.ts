import { createHash } from "node:crypto";
import { digestError } from "./errors/types.ts";
import { ok, err, type Result } from "./result.ts";
import type { IncrementalHasher } from "./digest.ts";
/** SHA-2 streaming capability for Node-compatible runtimes; retains no chunks. */
export function createNodeHasher(): Result<IncrementalHasher> {
  try {
    return ok(
      Object.freeze({
        create(algorithm: "sha-256" | "sha-512") {
          if (algorithm !== "sha-256" && algorithm !== "sha-512")
            throw new TypeError("Invalid digest algorithm");
          const hash = createHash(
            algorithm === "sha-256" ? "sha256" : "sha512",
          );
          return Object.freeze({
            update(chunk: Uint8Array) {
              hash.update(chunk);
            },
            finish() {
              return new Uint8Array(hash.digest());
            },
          });
        },
      }),
    );
  } catch {
    return err(digestError("invalid_state"));
  }
}
