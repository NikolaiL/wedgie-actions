# Action protocol v1

The application namespace is its Wedgie module name (`mygame` below). The library handles framing and cryptography; the app defines its ordered field schema and semantic validation.

## USB JSON lines

```json
{"id":1,"type":"mygame_hello"}
{"id":1,"type":"mygame_identity","protocol":"mygame/v1","cert":"<DER hex>"}
{"id":2,"type":"mygame_sign","text":"mygame/v1\naction=open\nnonce=<server challenge>"}
{"id":2,"type":"mygame_signature","r":"<64 hex>","s":"<64 hex>"}
```

This is a formatting example, not a complete authorization schema. Refusals return `{"id":2,"type":"refused"}`. Errors return `{"id":2,"type":"error","error":"reason"}`. The factory key must sign SHA-256 of the exact UTF-8 text; allowed text is ASCII, so there is no encoding conversion. P-256 signatures are raw integer scalars, not DER-encoded signature blobs. Serial speed is 115200 baud.

## Text envelope

- Header `<app>/v1`, then `name=value` lines, no final newline.
- Names match `[a-z][a-z0-9_]{0,31}`; namespace matches `[a-z][a-z0-9_]{1,19}`.
- Values are nonempty printable ASCII; the JS encoder also converts safe integers to their decimal representation. No floats, nested objects, newlines, nulls or booleans.
- The ordered schema belongs to the application. `encodeAction` preserves insertion order. Build fields in that fixed order; `decode_fields` rejects missing, added or reordered fields. Use identical test vectors on the server and MicroPython.
- Total text is at most 1024 bytes. Application schemas may impose tighter limits.

The complete text, including namespace, is hashed with SHA-256 and signed with `optiga.FACTORY_KEY`. Verify against the key in the manufacturer-certified device certificate. An ordinary app key endorsed by arbitrary host-controlled firmware is not equivalent to directly proving possession of the certified factory key.

## Application responsibilities

Issue an unpredictable challenge and store its exact text server-side. Bind the device fingerprint, user/session, action, all relevant parameters, origin and domain, expiry and nonce/sequence. Revalidate current permissions and state at commit, verify the exact stored text, and atomically consume the pending challenge before applying it. A valid signature is not itself permission to perform an action.

The device must decode and validate its known action schema, compute its own certificate fingerprint, check the requested chip, and derive readable prompts from the signed fields. Do not accept host-supplied labels as a substitute for interpreting the action. Decline must produce no signature.

## Compatibility

Starproof retains its original `starproof/v1` namespace and ordered game fields. Its already-installed original app remains wire-compatible with this library. The generic library owns no star systems, fuel costs, action names, HTTP routes, sessions or gameplay policy.
