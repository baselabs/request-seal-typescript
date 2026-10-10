// Capture constructors and methods before caller code can replace runtime globals.
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', {ignoreBOM: true});
const fatalDecoder = new TextDecoder('utf-8', {fatal: true, ignoreBOM: true});
const fatalBomDecoder = new TextDecoder('utf-8', {fatal: true});
export const encodeUtf8 = encoder.encode.bind(encoder);
export const decodeUtf8 = decoder.decode.bind(decoder);
export const decodeUtf8Fatal = fatalDecoder.decode.bind(fatalDecoder);
export const decodeUtf8FatalBom = fatalBomDecoder.decode.bind(fatalBomDecoder);
export const now = performance.now.bind(performance);

const deno = (globalThis as {Deno?: {unrefTimer?: (id: number) => void}}).Deno;
const unrefNumericTimer = typeof deno?.unrefTimer === 'function' ? deno.unrefTimer.bind(deno) : undefined;
const apply = Reflect.apply;
/** Best effort: a replaced or throwing method leaves the timer referenced until it fires. */
export function unrefTimer(timer: unknown): void {
  try {
    if (typeof timer === 'number') unrefNumericTimer?.(timer);
    else if (typeof timer === 'object' && timer !== null && 'unref' in timer && typeof timer.unref === 'function') apply(timer.unref, timer, []);
  } catch { /* The timer stays referenced; it still fires at the deadline. */ }
}
