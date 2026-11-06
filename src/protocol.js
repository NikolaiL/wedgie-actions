export function encodeAction(app, fields) {
  if (typeof app !== 'string' || !/^[a-z][a-z0-9_]{1,19}$/.test(app)) throw new Error('Invalid app namespace.');
  if (!fields || typeof fields !== 'object' || Array.isArray(fields)) throw new Error('Action fields must be an object.');
  const entries = Object.entries(fields);
  if (!entries.length) throw new Error('An action needs fields.');
  const lines = entries.map(([name, value]) => {
    if (!/^[a-z][a-z0-9_]{0,31}$/.test(name)) throw new Error('Invalid field name.');
    if (typeof value !== 'string' && !(typeof value === 'number' && Number.isSafeInteger(value))) throw new Error('Fields must be strings or safe integers.');
    const text = String(value);
    if (!text || !/^[\x20-\x7e]+$/.test(text)) throw new Error('Fields must contain nonempty, printable ASCII without newlines.');
    return `${name}=${text}`;
  });
  const text = [`${app}/v1`, ...lines].join('\n');
  if (text.length > 1024) throw new Error('Action exceeds the device limit.');
  return text;
}
