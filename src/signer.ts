import {run, type Context} from './context.ts';
import {SIGNATURE_MAX_BYTES} from './constants.ts';
import {custodyError, isRequestSealError} from './errors/types.ts';
import {ok, err, type Result} from './result.ts';
import { isKeyHandle, type KeyHandle } from "./key_handle.ts";

export type SigningCapability = KeyHandle | ((...args: never[]) => unknown);

export function validSigner(signer: unknown): signer is SigningCapability {
  return typeof signer === "function" || isKeyHandle(signer);
}

/** The HTTP boundary is stricter than the general custody signature bound. */
export async function custodySign(handle: KeyHandle, algorithm: unknown, base: Uint8Array, context: Context): Promise<Result<Uint8Array>> {
  const result = await run(context, c => handle.sign(algorithm, base, c));
  if (!result.ok) return err(isRequestSealError(result.error) && result.error.kind === 'custody' ? result.error : custodyError('custodian_failure'));
  return result.value instanceof Uint8Array && result.value.length >= 1 && result.value.length <= SIGNATURE_MAX_BYTES
    ? ok(new Uint8Array(result.value)) : err(custodyError('invalid_signing_output'));
}
