import {discoveryError} from '../errors/types.ts';

/** Classify OS trust permission failures without changing other errors. */
export function systemCertificateError(error: unknown): never {
  const deno = (globalThis as {Deno?: {errors?: {NotCapable?: new (...args: never[]) => Error}}}).Deno;
  const PermissionError = deno?.errors?.NotCapable;
  if (PermissionError && error instanceof PermissionError)
    throw discoveryError('transport_unavailable');
  throw error;
}
