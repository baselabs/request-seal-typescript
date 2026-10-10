import {snapshotOptions} from './brand.ts';
import {
  withDeadline,
  isContext,
  remainingMs,
  run,
  type Context,
} from './context.ts';
import {SIGNATURE_MAX_BYTES, CUSTODY_SIGNATURE_MAX_BYTES} from './constants.ts';
import {custodyError, isRequestSealError} from './errors/types.ts';
import {ok, err, type Result} from './result.ts';
import {
  resolveAlgorithm,
  selection,
  type CustodyAlgorithm,
  type Spec,
} from './crypto/algorithm.ts';
import {dataBytes} from './crypto/primitive.ts';
import {isPublicKey, type PublicKey} from './public_key.ts';
import {isKeyIdentity, type KeyIdentity} from './key_identity.ts';
import {isUnwrappedKey, type UnwrappedKey} from './custody/content_key.ts';
export type KeyHandle = Readonly<{
  algorithm: CustodyAlgorithm;
  capabilities: readonly ('sign' | 'verify' | 'unwrap')[];
  sign: (
    algorithm: unknown,
    data: unknown,
    context: Context,
  ) => Promise<Result<Uint8Array<ArrayBuffer>>>;
  verify: (
    algorithm: unknown,
    signature: unknown,
    data: unknown,
    context: Context,
  ) => Promise<Result<true>>;
  publicKey: (context?: Context) => Promise<Result<PublicKey>>;
  identity: (context?: Context) => Promise<Result<KeyIdentity>>;
  unwrap: (
    algorithm: unknown,
    wrappedKey: unknown,
    context: Context,
    options?: unknown,
  ) => Promise<Result<UnwrappedKey>>;
  release: () => Promise<Result<true>>;
}>;
export type Custodian = Pick<
  KeyHandle,
  'sign' | 'verify' | 'publicKey' | 'identity' | 'unwrap' | 'release'
>;
const handles = new WeakSet<object>();
const token = Object.freeze({});
export function isKeyHandle(value: unknown): value is KeyHandle {
  return typeof value === 'object' && value !== null && handles.has(value);
}
class ManagedHandle implements KeyHandle {
  readonly algorithm: CustodyAlgorithm;
  readonly capabilities: readonly ('sign' | 'verify' | 'unwrap')[];
  #port: Custodian | undefined;
  #spec: Spec;
  constructor(
    t: object,
    spec: Spec,
    port: Custodian,
    capabilities: KeyHandle['capabilities'],
  ) {
    if (t !== token) throw new TypeError('Invalid handle construction');
    this.algorithm = selection(spec);
    this.capabilities = Object.freeze([...capabilities]);
    this.#spec = spec;
    this.#port = port;
    handles.add(this);
    Object.freeze(this);
  }
  async #invoke<T>(
    op: 'sign' | 'verify' | 'unwrap' | 'publicKey' | 'identity',
    context: Context | undefined,
    work: (port: Custodian, c: Context) => Promise<Result<T>>,
    valid: (v: unknown) => v is T,
  ): Promise<Result<T>> {
    if (!this.#port) return err(custodyError('key_not_found'));
    if (
      ['sign', 'verify', 'unwrap'].includes(op) &&
      !this.capabilities.includes(op as 'sign' | 'verify' | 'unwrap')
    )
      return err(custodyError('unsupported_operation'));
    const c =
      context === undefined
        ? withDeadline()
        : isContext(context)
          ? ok(context)
          : err(custodyError('invalid_options'));
    if (!c.ok) return c;
    const port = this.#port;
    return run(c.value, async () => {
      const result = await work(port, c.value);
      if (!this.#port || remainingMs(c.value) <= 0) {
        if (result.ok && result.value instanceof Uint8Array)
          result.value.fill(0);
        if (result.ok && isUnwrappedKey(result.value))
          await result.value.release();
        return err(
          custodyError(this.#port ? 'deadline_exceeded' : 'key_not_found'),
        );
      }
      if (!result || typeof result !== 'object')
        return err(custodyError('custodian_failure'));
      if (!result.ok) {
        if (!isRequestSealError(result.error))
          return err(custodyError('custodian_failure'));
        if (result.error.kind === 'custody' || result.error.kind === 'crypto')
          return err(custodyError(result.error.reason));
        return err(custodyError('custodian_failure'));
      }
      if (!valid(result.value)) return err(custodyError(op === 'sign' ? 'invalid_signing_output' : 'custodian_failure'));
      return ok(
        result.value instanceof Uint8Array
          ? new Uint8Array(result.value)
          : result.value,
      ) as Result<T>;
    });
  }
  #matches(algorithm: unknown): boolean {
    const resolved = resolveAlgorithm(algorithm, true);
    return resolved.ok && resolved.value.id === this.#spec.id;
  }
  async sign(
    algorithm: unknown,
    data: unknown,
    context: Context,
  ): Promise<Result<Uint8Array<ArrayBuffer>>> {
    try {
      if (!this.#port) return err(custodyError('key_not_found'));
      if (!isContext(context)) return err(custodyError('invalid_options'));
      if (!this.#matches(algorithm)) return err(custodyError('key_mismatch'));
      if (!this.capabilities.includes('sign')) return err(custodyError('unsupported_operation'));
      const bytes = dataBytes(data);
      if (!bytes.ok) return err(custodyError('invalid_data'));
      return this.#invoke(
        'sign',
        context,
        async (p, c) => {
          try {
            return await p.sign(this.algorithm, bytes.value, c);
          } finally {
            bytes.value.fill(0);
          }
        },
        (v): v is Uint8Array<ArrayBuffer> =>
          v instanceof Uint8Array &&
          v.length > 0 &&
          v.length <= CUSTODY_SIGNATURE_MAX_BYTES,
      );
    } catch {
      return err(custodyError('invalid_data'));
    }
  }
  async verify(
    algorithm: unknown,
    signature: unknown,
    data: unknown,
    context: Context,
  ): Promise<Result<true>> {
    try {
      if (!this.#port) return err(custodyError('key_not_found'));
      if (!isContext(context)) return err(custodyError('invalid_options'));
      if (!this.#matches(algorithm)) return err(custodyError('key_mismatch'));
      if (!this.capabilities.includes('verify')) return err(custodyError('unsupported_operation'));
      const bytes = dataBytes(data);
      if (!bytes.ok) return err(custodyError('invalid_data'));
      if (!(signature instanceof Uint8Array))
        return err(custodyError('invalid_signature'));
      if (signature.length > CUSTODY_SIGNATURE_MAX_BYTES)
        return err(custodyError('limit'));
      const copied = new Uint8Array(signature);
      return this.#invoke(
        'verify',
        context,
        async (p, c) => {
          try {
            return await p.verify(this.algorithm, copied, bytes.value, c);
          } finally {
            copied.fill(0);
            bytes.value.fill(0);
          }
        },
        (v): v is true => v === true,
      );
    } catch {
      return err(custodyError('invalid_signature'));
    }
  }
  async publicKey(context?: Context): Promise<Result<PublicKey>> {
    return this.#invoke(
      'publicKey',
      context,
      (p, c) => p.publicKey(c),
      isPublicKey,
    );
  }
  async identity(context?: Context): Promise<Result<KeyIdentity>> {
    return this.#invoke(
      'identity',
      context,
      (p, c) => p.identity(c),
      isKeyIdentity,
    );
  }
  async unwrap(
    algorithm: unknown,
    wrappedKey: unknown,
    context: Context,
    options: unknown = {},
  ): Promise<Result<UnwrappedKey>> {
    try {
      if (!this.#port) return err(custodyError('key_not_found'));
      if (!isContext(context)) return err(custodyError('invalid_options'));
      if (!this.#matches(algorithm)) return err(custodyError('key_mismatch'));
      if (!this.capabilities.includes('unwrap')) return err(custodyError('unsupported_operation'));
      if (
        !(wrappedKey instanceof Uint8Array) ||
        wrappedKey.length === 0 ||
        wrappedKey.length > SIGNATURE_MAX_BYTES
      )
        return err(custodyError('invalid_data'));
      const opts = snapshotOptions(options, ['length']);
      if (
        !opts.ok ||
        (Object.hasOwn(opts.value, 'length') &&
          opts.value.length !== 128 &&
          opts.value.length !== 256)
      )
        return err(custodyError('invalid_options'));
      const copied = new Uint8Array(wrappedKey);
      return this.#invoke(
        'unwrap',
        context,
        async (p, c) => {
          try {
            return await p.unwrap(this.algorithm, copied, c, opts.value);
          } finally {
            copied.fill(0);
          }
        },
        isUnwrappedKey,
      );
    } catch {
      return err(custodyError('invalid_data'));
    }
  }
  async release(): Promise<Result<true>> {
    const port = this.#port;
    this.#port = undefined;
    if (!port) return ok(true);
    try {
      const r = await port.release();
      return r.ok && r.value === true
        ? ok(true)
        : err(custodyError('custodian_failure'));
    } catch {
      return err(custodyError('custodian_failure'));
    }
  }
  toJSON(): Readonly<{
    kind: string;
    algorithm: CustodyAlgorithm;
    capabilities: KeyHandle['capabilities'];
  }> {
    return Object.freeze({
      kind: 'KeyHandle',
      algorithm: this.algorithm,
      capabilities: this.capabilities,
    });
  }
  [Symbol.for('nodejs.util.inspect.custom')](): unknown {
    return this.toJSON();
  }
  [Symbol.for('Deno.customInspect')](): unknown {
    return this.toJSON();
  }
}
/** Wrap trusted custodian code under deadline, result validation, and fault containment. */
export function createKeyHandle(
  algorithm: unknown,
  port: Custodian,
  capabilities?: KeyHandle['capabilities'],
): Result<KeyHandle> {
  try {
    const resolved = resolveAlgorithm(algorithm, true);
    if (!resolved.ok) return err(custodyError('unsupported_algorithm'));
    const spec = resolved.value,
      allowed: KeyHandle['capabilities'] = spec.unwrap
        ? ['unwrap']
        : ['sign', 'verify'];
    const input = capabilities ?? allowed;
    if (!Array.isArray(input)) return err(custodyError('invalid_handle'));
    const length = input.length;
    if (!Number.isInteger(length) || length < 1 || length > allowed.length)
      return err(custodyError('invalid_handle'));
    const snapshot = Object.create(null) as Record<number, KeyHandle['capabilities'][number]>;
    for (let i = 0; i < length; i++) {
      if (!Object.hasOwn(input, i)) return err(custodyError('invalid_handle'));
      snapshot[i] = input[i]!;
    }
    const selected = Array.from({length}, (_, i) => snapshot[i]!);
    if (
      !Array.isArray(selected) ||
      !selected.length ||
      new Set(selected).size !== selected.length ||
      selected.some((v) => !allowed.includes(v))
    )
      return err(custodyError('invalid_handle'));
    const methods = [
      'sign',
      'verify',
      'publicKey',
      'identity',
      'unwrap',
      'release',
    ] as const;
    const captured = Object.create(null) as Custodian;
    for (const name of methods) {
      const method = port[name];
      if (typeof method !== 'function')
        return err(custodyError('invalid_handle'));
      Object.defineProperty(captured, name, {value: method.bind(port)});
    }
    return ok(
      new ManagedHandle(token, spec, Object.freeze(captured), selected),
    );
  } catch {
    return err(custodyError('invalid_handle'));
  }
}

Object.freeze(ManagedHandle.prototype);
Object.freeze(ManagedHandle);
const managedVerify = Function.prototype.call.bind(ManagedHandle.prototype.verify);
export function verifyHandle(
  key: KeyHandle,
  algorithm: unknown,
  signature: unknown,
  data: unknown,
  context: Context,
): Promise<Result<true>> {
  return managedVerify(key, algorithm, signature, data, context);
}
