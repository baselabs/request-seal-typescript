import { isRequestSealError, type RequestSealError } from './errors/types.ts';
/** A success value or a branded, bounded error. */
export type Result<T> = { readonly ok: true; readonly value: T } | { readonly ok: false; readonly error: RequestSealError };
/** Freeze a successful result containing the supplied value. */
export const ok = <T>(value: T): Result<T> => Object.freeze({ ok: true, value });
/** Freeze a failed result after checking its error brand. */
export const err = <T = never>(error: RequestSealError): Result<T> => {
  if (!isRequestSealError(error)) throw new TypeError('Unbranded Result error');
  return Object.freeze({ ok: false, error });
};
