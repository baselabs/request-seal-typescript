import { readDer, type DerNode } from "../custody/der.ts";
import { ensure } from "./support.ts";

function algorithm(node: DerNode | undefined): boolean {
  return (
    !!node &&
    node.tag === 48 &&
    node.children.length >= 1 &&
    node.children.length <= 2 &&
    node.children[0]!.tag === 6
  );
}
function name(node: DerNode | undefined): boolean {
  return (
    !!node &&
    node.tag === 48 &&
    node.children.every(
      (set) =>
        set.tag === 49 &&
        set.children.length >= 1 &&
        set.children.every(
          (attr) =>
            attr.tag === 48 &&
            attr.children.length === 2 &&
            attr.children[0]!.tag === 6,
        ),
    )
  );
}
function time(node: DerNode): boolean {
  const value = String.fromCharCode(...node.bytes);
  return node.tag === 23
    ? /^[0-9]{12}Z$/.test(value)
    : node.tag === 24 && /^[0-9]{14}Z$/.test(value);
}
/** Validate the X.509 envelope using the existing owned DER decoder. Trust,
 * validity, hostname and signature checks remain the TLS substrate's work. */
export function certificate(der: unknown): Uint8Array {
  ensure(
    der instanceof Uint8Array && der.length >= 1 && der.length <= 16384,
    "invalid_source",
  );
  const parsed = readDer(der);
  ensure(
    parsed.ok && parsed.value.tag === 48 && parsed.value.children.length === 3,
    "invalid_source",
  );
  const [tbs, signatureAlgorithm, signature] = parsed.value.children;
  ensure(
    tbs!.tag === 48 &&
      algorithm(signatureAlgorithm) &&
      signature!.tag === 3 &&
      signature!.bytes.length > 1 &&
      signature!.bytes[0] === 0,
    "invalid_source",
  );
  const nodes = [...tbs!.children];
  let version = 0;
  if (nodes[0]?.tag === 160) {
    const explicit = nodes.shift()!;
    ensure(
      explicit.children.length === 1 &&
        explicit.children[0]!.tag === 2 &&
        explicit.children[0]!.bytes.length === 1,
      "invalid_source",
    );
    version = explicit.children[0]!.bytes[0]!;
    ensure(version <= 2, "invalid_source");
  }
  const [serial, alg, issuer, validity, subject, spki] = nodes.splice(0, 6);
  ensure(
    serial?.tag === 2 && algorithm(alg) && name(issuer) && name(subject),
    "invalid_source",
  );
  ensure(
    validity?.tag === 48 &&
      validity.children.length === 2 &&
      validity.children.every(time),
    "invalid_source",
  );
  ensure(
    spki?.tag === 48 &&
      spki.children.length === 2 &&
      algorithm(spki.children[0]) &&
      spki.children[1]!.tag === 3 &&
      spki.children[1]!.bytes.length > 1 &&
      spki.children[1]!.bytes[0] === 0,
    "invalid_source",
  );
  let last = 0;
  for (const optional of nodes) {
    const order = [129, 130, 163].indexOf(optional.tag) + 1;
    ensure(order > last && version >= (order === 3 ? 2 : 1), "invalid_source");
    last = order;
    if (order === 3) {
      ensure(
        optional.children.length === 1 && optional.children[0]!.tag === 48,
        "invalid_source",
      );
      for (const extension of optional.children[0]!.children) {
        const children = extension.children;
        ensure(
          extension.tag === 48 &&
            (children.length === 2 || children.length === 3) &&
            children[0]!.tag === 6 &&
            children.at(-1)!.tag === 4,
          "invalid_source",
        );
        if (children.length === 3)
          ensure(
            children[1]!.tag === 1 &&
              children[1]!.bytes.length === 1 &&
              [0, 255].includes(children[1]!.bytes[0]!),
            "invalid_source",
          );
      }
    } else
      ensure(
        optional.bytes.length >= 1 && optional.bytes[0]! <= 7,
        "invalid_source",
      );
  }
  return new Uint8Array(der);
}
