"""EIP-1014 CREATE2 address derivation in pure Python.

CREATE2 lets a contract's address be known *before* it is deployed::

    address = keccak256(0xff ++ deployer ++ salt ++ keccak256(init_code))[12:]

The ``0xff`` prefix keeps CREATE2 addresses distinct from plain CREATE
addresses (which derive from the deployer address and its nonce). Because
the result depends only on the deployer, the salt and the init code --
never on chain state -- the same inputs give the same address on every
EVM chain, which is what makes counterfactual deployment possible: fund
an address, or sign for it, before anything exists there.

This module is dependency-free: it ships its own Keccak-256 (the
pre-NIST Keccak sponge Ethereum uses, *not* ``hashlib.sha3_256``).

>>> create2_address("0x0000000000000000000000000000000000000000",
...                 "0x" + "00" * 32, "0x00")
'0x4D1A2e2bB4F88F0250f26Ffff098B0b30B26BF38'
>>> create2_address("0xdeadbeef00000000000000000000000000000000",
...                 "0x" + "00" * 28 + "cafebabe", "0x00")
'0xD4D3c32Fe5cc6427A900D5f431321131B5a010b4'
>>> create2_address("0xdeadbeef00000000000000000000000000000000",
...                 "0x" + "00" * 28 + "cafebabe", "0xdeadbeef")
'0x565CB4e6f772b47c0E82ADA3FA77Df7E08fB0868'
>>> # Same inputs always give the same address, on any chain.
>>> create2_address("0x0000000000000000000000000000000000000000",
...                 "0x" + "00" * 32, "0x00") == \\
...     create2_address("0x0000000000000000000000000000000000000000",
...                     "0x" + "00" * 32, "0x00")
True
>>> # A different salt (or a different init code) moves the address.
>>> create2_address("0x0000000000000000000000000000000000000000",
...                 "0x" + "00" * 31 + "01", "0x00") != \\
...     create2_address("0x0000000000000000000000000000000000000000",
...                     "0x" + "00" * 32, "0x00")
True
"""

import argparse
import sys

__all__ = [
    "keccak256",
    "checksum_address",
    "create2_address",
    "create2_address_from_hash",
    "salt_from_int",
    "find_salt",
]

_MASK64 = (1 << 64) - 1

_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]

# Rotation offsets, indexed [x][y].
_R = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]


def _rol(x, n):
    return ((x << n) | (x >> (64 - n))) & _MASK64 if n else x


def _keccak_f(state):
    """Keccak-f[1600] permutation, in place, over 25 lanes."""
    for rnd in range(24):
        # Theta.
        c = [state[x] ^ state[x + 5] ^ state[x + 10]
             ^ state[x + 15] ^ state[x + 20] for x in range(5)]
        d = [c[(x + 4) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] ^= d[x]
        # Rho + Pi.
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rol(state[x + 5 * y],
                                                       _R[x][y])
        # Chi.
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] = (b[x + 5 * y]
                                    ^ ((~b[(x + 1) % 5 + 5 * y])
                                       & b[(x + 2) % 5 + 5 * y]))
        # Iota.
        state[0] ^= _RC[rnd]
    return state


def keccak256(data):
    """Keccak-256 digest of ``data`` (bytes), as bytes.

    >>> keccak256(b"").hex()
    'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470'
    >>> keccak256(b"abc").hex()
    '4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45'
    """
    rate = 136  # bytes per block for a 256-bit output
    padded = data + b"\x01"
    while len(padded) % rate != rate - 1:
        padded += b"\x00"
    padded += b"\x80"
    state = [0] * 25
    for off in range(0, len(padded), rate):
        block = padded[off:off + rate]
        for j in range(rate // 8):
            state[j] ^= int.from_bytes(block[j * 8:(j + 1) * 8], "little")
        _keccak_f(state)
    return b"".join(state[j].to_bytes(8, "little") for j in range(4))


def checksum_address(address):
    """EIP-55 checksummed form of a 20-byte address (bytes or hex).

    >>> checksum_address("0x4d1a2e2bb4f88f0250f26ffff098b0b30b26bf38")
    '0x4D1A2e2bB4F88F0250f26Ffff098B0b30B26BF38'
    >>> checksum_address("0x0000000000000000000000000000000000000000")
    '0x0000000000000000000000000000000000000000'
    """
    raw = _to_bytes(address, 20, "address") if not isinstance(address, bytes) \
        else address
    if isinstance(address, bytes) and len(address) != 20:
        raise ValueError(f"address must be 20 bytes, got {len(address)}")
    low = raw.hex()
    digest = keccak256(low.encode("ascii")).hex()
    return "0x" + "".join(
        c.upper() if int(digest[i], 16) >= 8 else c
        for i, c in enumerate(low))


def _to_bytes(value, length, what):
    """Accept ``bytes`` or a ``0x``-prefixed hex string of ``length`` bytes."""
    if isinstance(value, bytes):
        raw = value
    elif isinstance(value, str):
        text = value[2:] if value.startswith(("0x", "0X")) else value
        if len(text) % 2:
            text = "0" + text
        try:
            raw = bytes.fromhex(text)
        except ValueError:
            raise ValueError(f"{what} is not valid hex: {value!r}")
    else:
        raise TypeError(f"{what} must be bytes or a hex string")
    if len(raw) != length:
        raise ValueError(f"{what} must be {length} bytes, got {len(raw)}")
    return raw


def _to_init_code(value):
    """Accept init code as bytes or a ``0x`` hex string of any length."""
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        text = value[2:] if value.startswith(("0x", "0X")) else value
        if len(text) % 2:
            text = "0" + text
        try:
            return bytes.fromhex(text)
        except ValueError:
            raise ValueError(f"init code is not valid hex: {value!r}")
    raise TypeError("init code must be bytes or a hex string")


def create2_address_from_hash(deployer, salt, init_code_hash):
    """CREATE2 address from a precomputed init-code hash.

    >>> create2_address_from_hash(
    ...     "0x0000000000000000000000000000000000000000",
    ...     "0x" + "00" * 32, keccak256(b"\\x00")).lower()
    '0x4d1a2e2bb4f88f0250f26ffff098b0b30b26bf38'
    >>> create2_address_from_hash("0x123456", "0x" + "00" * 32,
    ...                           keccak256(b""))
    Traceback (most recent call last):
    ...
    ValueError: deployer must be 20 bytes, got 3
    """
    deployer_b = _to_bytes(deployer, 20, "deployer")
    salt_b = _to_bytes(salt, 32, "salt")
    code_hash = _to_bytes(init_code_hash, 32, "init code hash")
    digest = keccak256(b"\xff" + deployer_b + salt_b + code_hash)
    return checksum_address(digest[12:])


def create2_address(deployer, salt, init_code):
    """Predict the address CREATE2 deploys to.

    ``deployer`` is the factory address (20 bytes), ``salt`` is any
    32-byte value, and ``init_code`` is the contract creation bytecode.
    The result is returned in EIP-55 checksummed form.

    >>> create2_address("0x0000000000000000000000000000000000000000",
    ...                 "0x" + "00" * 32, b"\\x00")
    '0x4D1A2e2bB4F88F0250f26Ffff098B0b30B26BF38'
    >>> create2_address("0x0000000000000000000000000000000000000000",
    ...                 0, b"\\x00")  # int salt counts from zero
    '0x4D1A2e2bB4F88F0250f26Ffff098B0b30B26BF38'
    """
    if isinstance(salt, int):
        if salt < 0 or salt >= (1 << 256):
            raise ValueError("int salt must fit in 32 bytes")
        salt_b = salt.to_bytes(32, "big")
        deployer_b = _to_bytes(deployer, 20, "deployer")
        code_hash = keccak256(_to_init_code(init_code))
        digest = keccak256(b"\xff" + deployer_b + salt_b + code_hash)
        return checksum_address(digest[12:])
    return create2_address_from_hash(deployer, salt,
                                     keccak256(_to_init_code(init_code)))


def salt_from_int(n):
    """Encode an integer counter as a 32-byte salt (hex string).

    >>> salt_from_int(0)
    '0x0000000000000000000000000000000000000000000000000000000000000000'
    >>> salt_from_int(1)[-2:]
    '01'
    """
    if n < 0 or n >= (1 << 256):
        raise ValueError("salt counter must fit in 32 bytes")
    return "0x" + n.to_bytes(32, "big").hex()


def find_salt(deployer, init_code, prefix, limit=100000):
    """Find the smallest counter salt whose address starts with ``prefix``.

    ``prefix`` is hex without ``0x`` (case-insensitive), e.g. ``"00"``
    for a vanity address starting in ``0x00...``. Returns
    ``(salt_int, address)`` or ``None`` if nothing is found within
    ``limit`` tries. Factories use exactly this trick to mine vanity
    CREATE2 addresses before deploying.

    >>> salt, addr = find_salt(
    ...     "0x0000000000000000000000000000000000000000", b"\\x00", "4d")
    >>> addr.startswith("0x4D") or addr.startswith("0x4d")
    True
    >>> salt >= 0
    True
    """
    want = prefix[2:] if prefix.startswith(("0x", "0X")) else prefix
    want = want.lower()
    if not want or any(c not in "0123456789abcdef" for c in want):
        raise ValueError("prefix must be non-empty hex")
    for n in range(limit):
        addr = create2_address(deployer, salt_from_int(n), init_code)
        if addr[2:2 + len(want)].lower() == want:
            return n, addr
    return None


def _demo():
    deployer = "0x0000000000000000000000000000000000000000"
    salt = "0x" + "00" * 32
    init_code = "0x00"
    print("CREATE2 address prediction (EIP-1014)")
    print(f"  deployer : {deployer}")
    print(f"  salt     : {salt}")
    print(f"  init code: {init_code}")
    print(f"  -> address: {create2_address(deployer, salt, init_code)}")
    print()
    print("Vanity search: smallest salt giving an address starting 0x00...")
    found = find_salt(deployer, init_code, "00", limit=100000)
    if found:
        n, addr = found
        print(f"  salt counter {n} ({salt_from_int(n)}) -> {addr}")
    else:
        print("  (none found in the search limit)")


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Predict EIP-1014 CREATE2 deployment addresses.")
    parser.add_argument("--demo", action="store_true",
                        help="run the worked example")
    parser.add_argument("--test", action="store_true",
                        help="run the doctests")
    args = parser.parse_args(argv)
    if args.test:
        import doctest
        result = doctest.testmod(verbose=False)
        print(f"{result.attempted} doctests, {result.failed} failures")
        return 1 if result.failed else 0
    _demo()
    return 0


if __name__ == "__main__":
    sys.exit(main())
