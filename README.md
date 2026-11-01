# create2-addresses

EIP-1014 CREATE2 address derivation in pure Python — no dependencies.

CREATE2 lets a contract's address be known *before* it is deployed:

```
address = keccak256(0xff ++ deployer ++ salt ++ keccak256(init_code))[12:]
```

Because the result depends only on the deployer, the salt and the init
code — never on chain state — the same inputs give the same address on
every EVM chain. That is what makes counterfactual deployment possible:
fund an address, or sign for it, before anything exists there.

## What's inside

- `create2.py` — a self-contained Keccak-256 (the pre-NIST Keccak sponge
  Ethereum uses, *not* `hashlib.sha3_256`), EIP-55 checksumming,
  `create2_address()` / `create2_address_from_hash()`, `salt_from_int()`,
  and `find_salt()` — a vanity-address search that finds the smallest
  counter salt whose predicted address starts with a chosen hex prefix.

## Usage

```sh
python3 create2.py --demo   # worked example + vanity search
python3 create2.py --test   # doctests
```

```python
from create2 import create2_address, find_salt

create2_address(
    "0x0000000000000000000000000000000000000000",
    "0x" + "00" * 32,
    "0x00",
)
# '0x4D1A2e2bB4F88F0250f26Ffff098B0b30B26BF38'

find_salt("0x0000000000000000000000000000000000000000", b"\x00", "00")
# (213, '0x00C4148847a76e12955b1864941a10abbdcb48Ff')
```

The Keccak implementation is cross-checked against a reference Keccak
library (empty-string and `abc` vectors, plus the CREATE2 addresses
above); all doctests pass.
