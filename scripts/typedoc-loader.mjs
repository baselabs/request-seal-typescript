/** Resolve TypeDoc's compiler API without changing the project's compiler. */
export function resolve(specifier, context, nextResolve) {
  if (specifier === "typescript" && context.parentURL?.includes("/typedoc/")) {
    return nextResolve("typescript-docs", context);
  }
  return nextResolve(specifier, context);
}
