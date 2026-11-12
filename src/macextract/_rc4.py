"""RC4 (ARCFOUR), the stream cipher StuffIt 5 encrypts its forks with.

The algorithm is the published one: a 256-byte permutation shuffled by
the key (KSA), then one byte of keystream per output byte (PRGA).  The
key schedule runs from byte 0 of the keystream; no bytes are dropped.
The same routine decrypts, because RC4 is XOR.
"""


def rc4(data, key):
    """XOR ``data`` with the RC4 keystream of ``key``; returns bytes.

    Raises CorruptError if the key is empty (never the case for the
    format's own 10-byte keys; a guard against a mis-built one).
    """
    if not key:
        raise ValueError("RC4: empty key")
    state = list(range(256))
    j = 0
    for i in range(256):
        j = (j + state[i] + key[i % len(key)]) & 0xFF
        state[i], state[j] = state[j], state[i]
    out = bytearray(len(data))
    i = j = 0
    for index, byte in enumerate(data):
        i = (i + 1) & 0xFF
        j = (j + state[i]) & 0xFF
        state[i], state[j] = state[j], state[i]
        out[index] = byte ^ state[(state[i] + state[j]) & 0xFF]
    return bytes(out)
