import { isRequestSealError, type RequestSealError } from './errors/types.ts';
export type Result<T> = { readonly ok: true; readonly value: T } | { readonly ok: false; readonly error: RequestSealError };
export const ok = <T>(value: T): Result<T> => Object.freeze({ ok: true, value });
export const err = <T = never>(error: RequestSealError): Result<T> => {
  if (!isRequestSealError(error)) throw new TypeError('Unbranded Result error');
  return Object.freeze({ ok: false, error });
};
