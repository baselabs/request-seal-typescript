import { Profile, PublicKey, Policy, ok, err, type Result } from "../../src/index.ts";
import { isRequestSealError } from "../../src/errors/types.ts";
import { sourcePlain } from "./wire.ts";
import { built } from "./sign-surfaces.ts";
import type { CorpusResources, Surface } from "./loader.ts";
function value<T>(r: Result<T>): T { if (!r.ok) throw r.error; return r.value; }
function source(resources: CorpusResources, path: string): any {
  return sourcePlain(value(resources.reference({ref:{file:path,pointer:""}})));
}
/** Mirror the tagged profile_name runner against the published B.2.6 bytes. */
export const profileSurface: Surface = async (manifest, resources) => {
  try {
    const inputs = manifest.inputs;
    if (!Object.keys(inputs).every(k => ["name", "metadata"].includes(k))) return {ok:false,loaderReason:"invalid_manifest"};
    const vector = source(resources, "sources/rfc9421/verification/rfc9421.json").find((v: {label: string}) => v.label === "sig-b26");
    const base = source(resources, "sources/rfc9421/rfc9421.json").find((v: {section: string}) => v.section === "B.2.6");
    const selectedMessage = value(built({...manifest, inputs:{message:base.message,append_fields:[["Signature-Input",vector.signature_input],["Signature",vector.signature]]}}, resources));
    const [entries, signatures] = value(Profile.dictionaries(selectedMessage, 16));
    const publicKey = value(await PublicKey.import(new TextDecoder().decode(value(resources.read("sources/rfc9421/keys/ed25519_public.pem"))), "pem"));
    const policy = value(Policy.create({
      algorithms:["ed25519"],components:"()",keyResolver:()=>ok({algorithm:"ed25519",key:publicKey}),
      freshness:"not_evaluated",content:"not_required",replay:"not_required",
    }));
    const stamp = Object.assign(Object.create(null), {name:inputs.name}, inputs.metadata ?? {});
    const result = await Profile.verifyLabel(selectedMessage, policy, vector.label, new Map(entries).get(vector.label), signatures[vector.label], stamp);
    return result.ok ? ok({valid:true}) : result;
  } catch (e) { return isRequestSealError(e) ? err(e) : {ok:false,loaderReason:"invalid_manifest"}; }
};
