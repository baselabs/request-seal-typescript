export function limitRecords(entries: readonly {id: string; observed: string}[]): {id: string; observed: string}[] {
  return entries.map(({id, observed}) => ({id, observed})).sort((a, b) => a.id < b.id ? -1 : a.id > b.id ? 1 : a.observed < b.observed ? -1 : a.observed > b.observed ? 1 : 0);
}
