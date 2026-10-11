import { register } from "node:module";

// TypeScript 7 exposes a native compiler API. TypeDoc still uses the JavaScript
// compiler API, so documentation alone uses the separately pinned compiler.
register("./typedoc-loader.mjs", import.meta.url);
