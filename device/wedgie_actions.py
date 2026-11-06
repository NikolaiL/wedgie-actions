"""Vendorable MicroPython helpers. Never creates, replaces or locks a key."""


def decode_fields(text, app, names):
    if not isinstance(app, str) or not 2 <= len(app) <= 20 or not "a" <= app[0] <= "z" or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789_" for c in app):
        raise ValueError("invalid app namespace")
    if not isinstance(text, str) or len(text) > 1024 or any(ord(c) > 126 or (ord(c) < 32 and c != "\n") for c in text):
        raise ValueError("not an action envelope")
    lines = text.split("\n")
    if len(lines) != len(names) + 1 or lines[0] != app + "/v1":
        raise ValueError("wrong action format")
    fields = {}
    for name, line in zip(names, lines[1:]):
        if not line.startswith(name + "=") or not line[len(name) + 1:]:
            raise ValueError("wrong action fields")
        fields[name] = line[len(name) + 1:]
    return fields


def certificate_der(blob):
    for offset in range(min(17, len(blob) - 4)):
        if blob[offset] != 0x30:
            continue
        first = blob[offset + 1]
        count = (first & 127) if first & 128 else 0
        if count > 3 or offset + 2 + count > len(blob):
            continue
        length = first if not count else 0
        for i in range(count):
            length = length * 256 + blob[offset + 2 + i]
        end = offset + 2 + count + length
        if length >= 200 and end <= len(blob):
            return blob[offset:end]
    raise ValueError("cannot read chip certificate")


class _Cancelled(Exception):
    pass


class _CancellableKeys:
    def __init__(self, cancelled):
        import lcd
        self.keys = lcd.Keys(physical=True)
        self.cancelled = cancelled

    def pressed(self):
        if self.cancelled():
            raise _Cancelled()
        return self.keys.pressed()


def confirm_action(chip, display, text, question, lines, cancelled=None):
    """Call only after your app validates text and derives question/lines from its decoded fields."""
    import ui
    try:
        options = {} if cancelled is None else {"keys": _CancellableKeys(cancelled)}
        approved = ui.ask(display, question, lines, yes="sign", no="decline", ms=60000, **options)
    except _Cancelled:
        return None
    if not approved or (cancelled is not None and cancelled()):
        return None
    ui.progress("Signing action", "in the Trust M", bar=False)
    import hashlib
    import optiga
    r, s = chip.sign(optiga.FACTORY_KEY, hashlib.sha256(text.encode()).digest())
    return {"r": "%064x" % r, "s": "%064x" % s}
