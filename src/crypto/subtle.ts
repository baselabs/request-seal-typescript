// Capture the runtime boundary before caller code can replace global methods.
const subtle = globalThis.crypto.subtle;
export const sign = subtle.sign.bind(subtle);
export const verify = subtle.verify.bind(subtle);
export const importKey = subtle.importKey.bind(subtle);
export const exportKey = subtle.exportKey.bind(subtle);
export const generateKey = subtle.generateKey.bind(subtle);
export const digest = subtle.digest.bind(subtle);
export const encrypt = subtle.encrypt.bind(subtle);
export const decrypt = subtle.decrypt.bind(subtle);
export const wrapKey = subtle.wrapKey.bind(subtle);
export const unwrapKey = subtle.unwrapKey.bind(subtle);
export const random = globalThis.crypto.getRandomValues.bind(globalThis.crypto);
