import test from 'node:test';
import assert from 'node:assert/strict';
import * as api from '../src/index.ts';

const predicateNames = [
  'isStructuredFieldsValue', 'isStructuredFieldsSchema', 'isMessage',
  'isFieldOccurrence', 'isBody', 'isTransportFacts',
] as const;
type PredicateName = typeof predicateNames[number];
function predicates(): Record<PredicateName, (value: unknown) => boolean> {
  const exports = api as unknown as Record<string, unknown>;
  for (const name of predicateNames) assert.equal(typeof exports[name], 'function', name);
  return exports as Record<PredicateName, (value: unknown) => boolean>;
}

test('wire predicates accept frozen owned values and reject same-shape forgeries', async () => {
  const checks = predicates();
  const parsed = api.StructuredFields.parse('dictionary', 'x=(1;a=2);b=3, y=4', { schema: { revision: 'rfc8941', type: 'dictionary', itemTypes: ['integer'], innerLists: true } });
  assert.ok(parsed.ok && parsed.value.kind === 'dictionary');
  const schema = api.createSchema({ revision: 'rfc8941', type: 'item', itemTypes: ['integer'] });
  const field = api.FieldOccurrence.create({ name: 'x', value: '1', section: 'headers' });
  const body = api.Body.create({ state: 'retained', bytes: 'body' });
  const transport = api.TransportFacts.create({});
  const message = await api.Message.request('GET', 'https://example.com/', [['x', '1']], null);
  const response = await api.Message.response(200, [], null, { request: message.ok ? message.value : null });
  assert.ok(schema.ok && field.ok && body.ok && transport.ok && message.ok && response.ok);
  const members = parsed.value.value.map(([, member]) => member);
  const inner = members[0];
  assert.ok(inner?.kind === 'inner_list');
  const values: [PredicateName, object][] = [
    ['isStructuredFieldsValue', parsed.value],
    ...members.map(member => ['isStructuredFieldsValue', member] as [PredicateName, object]),
    ['isStructuredFieldsValue', inner.value[0]!],
    ['isStructuredFieldsSchema', schema.value],
    ['isFieldOccurrence', field.value], ['isBody', body.value],
    ['isTransportFacts', transport.value], ['isMessage', message.value],
    ['isMessage', response.value], ['isMessage', response.value.relatedRequest!],
    ['isFieldOccurrence', message.value.fields[0]!],
    ['isBody', message.value.body], ['isTransportFacts', message.value.transport],
  ];
  for (const [name, value] of values) {
    assert.equal(checks[name](value), true, name);
    assert.ok(Object.isFrozen(value));
    const forged = { ...value };
    assert.deepEqual(forged, value);
    assert.equal(checks[name](forged), false, `${name}: plain forgery`);
    assert.equal(checks[name](Object.freeze(forged)), false, `${name}: frozen forgery`);
    for (const other of predicateNames)
      assert.equal(checks[other](value), other === name, `${name} must not carry ${other}`);
  }
  for (const result of [parsed, schema, field, body, transport, message, response])
    assert.ok(Object.isFrozen(result));
  for (const type of ['item', 'list', 'dictionary'] as const) {
    const result = api.StructuredFields.parse(type, type === 'dictionary' ? 'a=1' : '1', { schema: 'rfc8941' });
    assert.ok(result.ok);
    assert.equal(checks.isStructuredFieldsValue(result.value), true);
    assert.equal(checks.isStructuredFieldsValue({ ...result.value }), false);
  }
  for (const name of predicateNames)
    for (const value of [null, undefined, 1, 'x', [], {}, () => {}, new Proxy({}, { get() { throw new Error('predicate must not read properties'); } })])
      assert.equal(checks[name](value), false, name);
});

test('every wire validation path produces its own type brand', async () => {
  const checks = predicates();
  for (const [name, result] of [
    ['isFieldOccurrence', api.FieldOccurrence.validate({ name: 'x', value: '', section: 'headers' })],
    ['isBody', api.Body.validate({ state: 'unavailable' })],
    ['isTransportFacts', api.TransportFacts.validate({})],
  ] as const) {
    assert.ok(result.ok);
    assert.equal(checks[name](result.value), true);
  }
  const request = await api.Message.request('GET', 'https://example.com/', [], null);
  assert.ok(request.ok);
  for (const create of [api.createMessage, api.validateMessage, api.Message.validate]) {
    const result = create({ ...request.value });
    assert.ok(result.ok);
    assert.equal(checks.isMessage(result.value), true);
  }
});
