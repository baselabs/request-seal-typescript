import {publicMetadata} from '../../src/custody/jwk.ts';
import {sourcePlain} from './wire.ts';
import type {BatchItem, BatchCheck} from './batch.ts';
import {encodeBase64Url} from '../../src/bytes.ts';
import {ruleId} from '../../src/errors/types.ts';
import {
  Crypto,
  Custody,
  PublicKey,
  decodeBase64Url,
  decodeJson,
  ok,
  type KeyHandle,
} from '../../src/index.ts';
import type {
  Surface,
  SurfaceResult,
  CorpusResources,
  CorpusCase,
} from './loader.ts';
const invalid = (): SurfaceResult => ({
  ok: false,
  loaderReason: 'invalid_manifest',
});
function record(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}
function material(value: unknown, resources: CorpusResources): unknown {
  if (record(value) && Object.hasOwn(value, 'ref')) {
    const r = resources.reference(value);
    if (!r.ok) throw new Error('Invalid source');
    return sourcePlain(r.value);
  }
  if (
    record(value) &&
    Object.keys(value).join(',') === 'file' &&
    typeof value.file === 'string'
  ) {
    const r = resources.read(value.file);
    if (!r.ok) throw new Error('Invalid source');
    return r.value;
  }
  if (record(value) && Object.keys(value).join(',') === 'b64') {
    const r = decodeBase64Url(value.b64);
    if (!r.ok) throw new Error('Invalid bytes');
    return r.value;
  }
  if (
    record(value) &&
    Object.keys(value).join(',') === 'pairs' &&
    Array.isArray(value.pairs)
  ) {
    const out = Object.create(null) as Record<string, unknown>;
    for (const pair of value.pairs) {
      if (
        !Array.isArray(pair) ||
        pair.length !== 2 ||
        typeof pair[0] !== 'string' ||
        Object.hasOwn(out, pair[0])
      )
        throw new Error('Invalid pairs');
      out[pair[0]] = pair[1];
    }
    return out;
  }
  return value;
}
function byteValue(value: unknown, resources: CorpusResources): Uint8Array {
  const v = material(value, resources);
  if (!(v instanceof Uint8Array)) throw new Error('Invalid bytes');
  return v;
}
function keyReference(
  manifest: CorpusCase,
  resources: CorpusResources,
): Uint8Array {
  const key = manifest.keys?.find((k) => k.name === manifest.inputs.key);
  if (!key || typeof key.file !== 'string')
    throw new Error('Invalid key reference');
  const r = resources.read(key.file);
  if (!r.ok) throw new Error('Invalid key file');
  return r.value;
}
export const cryptoVerify: Surface = async (m, r) => {
  try {
    if (
      !Object.keys(m.inputs).every((k) =>
        ['algorithm', 'key', 'data', 'signature', 'format'].includes(k),
      )
    )
      return invalid();
    const format = m.inputs.format ?? 'pem';
    let key: PublicKey | KeyHandle;
    if (record(m.inputs.key)) {
      const descriptor = m.inputs.key;
      let imported;
      if (Object.keys(descriptor).join(',') === 'file') {
        const raw = byteValue(descriptor, r);
        imported = await PublicKey.import(new TextDecoder('utf-8', {fatal: true}).decode(raw), 'pem');
      } else if (Object.keys(descriptor).sort().join(',') === 'curve,raw') {
        const raw = byteValue(descriptor.raw, r);
        if (descriptor.curve === 'Ed25519' && raw.length === 32) {
          imported = await PublicKey.import({kty: 'OKP', crv: 'Ed25519', x: encodeBase64Url(raw)});
        } else if (['P-256','P-384'].includes(descriptor.curve as string) && raw[0] === 4 && raw.length === (descriptor.curve === 'P-256' ? 65 : 97)) {
          const width = (raw.length - 1) / 2;
          imported = await PublicKey.import({kty: 'EC', crv: descriptor.curve, x: encodeBase64Url(raw.slice(1, 1 + width)), y: encodeBase64Url(raw.slice(1 + width))});
        } else return invalid();
      } else return invalid();
      if (!imported.ok) return imported;
      key = imported.value;
    } else {
      const raw = keyReference(m, r);
      if (format === 'hmac') {
        const imported = await Custody.local(m.inputs.algorithm, {hmac: raw});
        if (!imported.ok) return imported;
        key = imported.value;
      } else {
        if (!['pem','spki'].includes(format as string)) return invalid();
        const imported = await PublicKey.import(format === 'pem' ? new TextDecoder('utf-8', {fatal: true}).decode(raw) : raw, format as 'pem' | 'spki');
        if (!imported.ok) return imported;
        key = imported.value;
      }
    }
    try {
      const v = await Crypto.verify(
        m.inputs.algorithm,
        key,
        byteValue(m.inputs.signature, r),
        byteValue(m.inputs.data, r),
      );
      return v.ok ? ok({valid: true}) : v;
    } finally {
      if ('release' in key) await key.release();
    }
  } catch {
    return invalid();
  }
};
export const keyImport: Surface = async (m, r) => {
  try {
    if (
      !Object.keys(m.inputs).every((k) =>
        ['algorithm', 'material', 'format', 'mode', 'options', 'public_only'].includes(k),
      )
    )
      return invalid();
    const format = m.inputs.format;
    if (!['pem', 'pkcs8', 'spki', 'jwk'].includes(format as string))
      return invalid();
    if (m.inputs.options !== undefined && !record(m.inputs.options))
      return invalid();
    if (m.inputs.public_only !== undefined && typeof m.inputs.public_only !== 'boolean') return invalid();
    if (m.inputs.public_only !== undefined && m.inputs.mode !== undefined && (m.inputs.mode === 'public') !== m.inputs.public_only) return invalid();
    const raw = material(m.inputs.material, r);
    let input =
      format === 'pem' && raw instanceof Uint8Array
        ? new TextDecoder('utf-8', {fatal: true}).decode(raw)
        : raw;
    if (format === 'jwk' && input instanceof Uint8Array) {
      const parsed = decodeJson(input);
      if (!parsed.ok || parsed.value.duplicates.length) return invalid();
      input = sourcePlain(parsed.value.node);
    }
    let publicKey: PublicKey;
    let h: KeyHandle | undefined;
    try {
      if (m.inputs.mode === 'public' || m.inputs.public_only === true) {
        // RFC 7638 Section 3.2.1: private JWK thumbprints use the corresponding public key.
        if (m.inputs.public_only === true && format === 'jwk' && record(input)) input = publicMetadata(input);
        const imported = await PublicKey.import(
          input,
          format as 'pem' | 'spki' | 'jwk',
        );
        if (!imported.ok) return imported;
        publicKey = imported.value;
        if (m.inputs.algorithm !== undefined) {
          const bound = publicKey.bind(m.inputs.algorithm);
          if (!bound.ok) return bound;
        }
      } else {
        if (m.inputs.mode !== undefined && m.inputs.mode !== 'private')
          return invalid();
        const imported = await Custody.local(m.inputs.algorithm, input, {
          ...(record(m.inputs.options) ? m.inputs.options : {}),
          format,
        });
        if (!imported.ok) return imported;
        h = imported.value;
        const p = await h.publicKey();
        if (!p.ok) return p;
        publicKey = p.value;
      }
      if (!Object.hasOwn(m.expected, 'public')) return ok({valid: true});
      if (
        !record(m.expected.public) ||
        !Object.keys(m.expected.public).length ||
        !Object.keys(m.expected.public).every((k) =>
          ['jwk', 'thumbprint'].includes(k),
        )
      )
        return invalid();
      const facts: Record<string, unknown> = Object.create(null);
      if (Object.hasOwn(m.expected.public, 'jwk')) {
        const jwk = publicKey.jwk();
        if (!jwk.ok) return jwk;
        facts.jwk = jwk.value;
      }
      if (Object.hasOwn(m.expected.public, 'thumbprint')) {
        const thumbprint = await publicKey.thumbprint();
        if (!thumbprint.ok) return thumbprint;
        facts.thumbprint = thumbprint.value;
      }
      return ok({valid: true, facts: {public: facts}});
    } finally {
      if (h) await h.release();
    }
  } catch {
    return invalid();
  }
};
function fromHex(input: unknown): Uint8Array {
  if (typeof input !== 'string' || !/^(?:[0-9a-fA-F]{2})*$/.test(input))
    throw new Error('Invalid hex');
  return new Uint8Array(input.match(/../g)?.map((s) => parseInt(s, 16)) ?? []);
}
/** The batch registry owns enumeration and overrides; this adapter executes one item. */
export const cryptoBatchItem = async (item: BatchItem, manifest: Record<string, any>): Promise<BatchCheck> => {
  const format = manifest.batch.item_format;
  const algorithm = format === 'wycheproof-ed25519/1' ? 'ed25519' : 'ecdsa-p256-sha256';
  const groupType = format === 'wycheproof-ed25519/1' ? 'EddsaVerify' : 'EcdsaP1363Verify';
  const override = manifest.overrides?.[item.id];
  const expected = override?.outcome === 'reject' ? {rule_id: override.rule_id} : item.value.result;
  try {
    const group = item.parent;
    if (!group || group.type !== groupType || typeof group.publicKeyPem !== 'string' || (algorithm === 'ecdsa-p256-sha256' && group.sha !== 'SHA-256')) throw new Error('Invalid group');
    const signature = fromHex(item.value.sig), data = fromHex(item.value.msg);
    const imported = await PublicKey.import(group.publicKeyPem, 'pem');
    const result = imported.ok ? await Crypto.verify(algorithm, imported.value, signature, data) : imported;
    const actual = result.ok ? 'valid' : {rule_id: ruleId(result.error)};
    const matches = override?.outcome === 'reject'
      ? !result.ok && result.error.kind === 'crypto' && ruleId(result.error) === override.rule_id
      : item.value.result === 'valid' ? result.ok : item.value.result === 'invalid' && !result.ok && result.error.kind === 'crypto';
    return {ok: matches, expected, actual};
  } catch {return {ok: false, expected, actual: 'unexpected_item_shape'};}
};
