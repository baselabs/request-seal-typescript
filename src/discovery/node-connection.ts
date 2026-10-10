import { discoveryError } from "../errors/types.ts";
import { addressAllowed, sameAddress } from "./address.ts";
import { ensure, unwrap } from "./support.ts";

/** Validate the observed endpoint after TLS and before writing HTTP bytes. */
export function checkPeer(
  observed: {address: string | undefined; port: number | undefined},
  address: string,
  port: number,
  permittedAddresses: readonly string[],
): void {
  ensure(
    sameAddress(observed.address, address) && observed.port === port &&
      unwrap(addressAllowed(observed.address, permittedAddresses), "address_denied"),
    "address_denied",
  );
}

/** A connected peer denial terminates the address loop. */
export function allowConnectionRetry(error: unknown): void {
  if (error && typeof error === "object" && "reason" in error && error.reason === "address_denied") throw error;
}
