#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Daniel Campos Ramos
# SPDX-License-Identifier: ISC
"""Write the JSON vector files of the tests from the independent oracle.

    python3 make_vectors.py negative > ed521-negative.json
    python3 make_vectors.py pure > ed521-pure.json
    python3 make_vectors.py ph > ed521-ph.json

The oracle (oracle.py) follows RFC 8032 section 5.2 and ITI DOC-ICP-01.01
section 2 and shares no code with the Go package. The keys come from public
TEST seeds printed in the file: they are fixtures, never anyone's key. Each
vector names the rule it breaks.
"""
import hashlib
import json
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, __file__.rpartition('/')[0] or '.')
from oracle import ED521 as C  # noqa: E402


def seed(number):
    return hashlib.shake_256(f'Sparky CA Ed521 TEST key {number}: public seed, never for real use'.encode()).digest(C.size)


def message(size, tag=0):
    return hashlib.shake_256(f'Sparky CA Ed521 TEST message {size}/{tag}'.encode()).digest(size)


def negative():
    keys = [seed(n) for n in range(2)]
    publics = [C.public_key(k) for k in keys]
    data = message(100, 7)
    good = C.sign(keys[0], data)
    vectors = []

    def add(name, public, text, signature, rule):
        assert not C.verify(public, text, signature), name
        vectors.append({'name': name, 'public': public.hex(), 'message': text.hex(),
                        'signature': signature.hex(), 'rule': rule})

    add('wrong-key', publics[1], data, good, 'a signature by another key')
    add('altered-message', publics[0], data[:-1] + bytes([data[-1] ^ 1]), good, 'the message is bound by the challenge')
    add('domain-SigEd448', publics[0], data, C.sign(keys[0], data, dom=b'SigEd448\x00\x00'),
        'dom5 starts with "SigEd521" (DOC-ICP-01.01 2.3)')
    add('domain-absent', publics[0], data, C.sign(keys[0], data, dom=b''),
        'Ed521 always hashes dom5 (DOC-ICP-01.01 2: H(x) = SHAKE256(dom5(phflag,context)||x, 132))')
    add('domain-without-octets', publics[0], data, C.sign(keys[0], data, dom=b'SigEd521'),
        'dom5 carries octet(phflag) and octet(OLEN(context)) (DOC-ICP-01.01 2.3)')
    add('domain-phflag-1', publics[0], data, C.sign(keys[0], data, phflag=1),
        'phflag 1 is Ed521ph; PureEd521 uses 0')
    add('domain-context', publics[0], data, C.sign(keys[0], data, context=b'ctx'),
        'a signature under a context the verifier did not ask for (PureEd521 here has the empty context)')
    add('challenge-truncated-66', publics[0], data, C.sign(keys[0], data, challenge_bytes=66),
        'the challenge is all 132 octets of SHAKE256 (DOC-ICP-01.01 2), not the first 66')
    r_part, s_part = good[:C.size], int.from_bytes(good[C.size:], 'little')
    add('s-plus-L', publics[0], data, r_part + (s_part + C.L).to_bytes(C.size, 'little'),
        'S must be below L (RFC 8032 5.2.7 step 1)')
    add('s-all-ones', publics[0], data, r_part + b'\xff' * C.size, 'S out of range')
    add('signature-zero', publics[0], data, bytes(2 * C.size), 'R = 0 does not decode')
    y = 2
    while C.decode_point(y.to_bytes(C.size, 'little')) is not None:
        y += 1
    add('r-not-on-curve', publics[0], data, y.to_bytes(C.size, 'little') + good[C.size:],
        'R must decode (RFC 8032 5.2.3 step 3)')
    add('r-y-equals-p', publics[0], data, C.p.to_bytes(C.size, 'little') + good[C.size:],
        'y >= p does not decode (RFC 8032 5.2.3 step 1)')
    add('r-negative-zero-x', publics[0], data, (1 | 1 << 527).to_bytes(C.size, 'little') + good[C.size:],
        'x = 0 with sign bit 1 does not decode (RFC 8032 5.2.3 step 4)')
    add('signature-131-octets', publics[0], data, good[:-1], 'a signature has 132 octets')
    add('signature-133-octets', publics[0], data, good + b'\x00', 'a signature has 132 octets')
    # A public key that cannot be decoded: the test expects DecompressPoint to refuse it.
    keyvectors = [
        {'name': 'key-not-on-curve', 'public': y.to_bytes(C.size, 'little').hex(),
         'rule': 'a public key must decode (RFC 8032 5.2.3 step 3)'},
    ]
    for entry in keyvectors:
        assert C.decode_point(bytes.fromhex(entry['public'])) is None, entry['name']
    return {'comment': 'Ed521 negative vectors from testdata/oracle.py; public TEST seeds, never real keys.',
            'seeds': [k.hex() for k in keys], 'signatures': vectors, 'keys': keyvectors}


def pure():
    """PureEd521: phflag 0, empty context, the message signed as it is (DOC-ICP-01.01 2)."""
    keys = [seed(n) for n in range(3)]
    vectors = []
    for number, size in [(0, s) for s in (0, 1, 2, 11, 64, 65, 66, 67, 131, 132, 133, 256, 1023)] + [(1, 41), (2, 41)]:
        data = message(size, number if size == 41 else 0)
        public, signature = C.public_key(keys[number]), C.sign(keys[number], data)
        assert C.verify(public, data, signature), (number, size)
        vectors.append({'name': f'pure-key{number}-{size}-octets', 'public': public.hex(),
                        'message': data.hex(), 'signature': signature.hex()})
    return {'comment': 'PureEd521 vectors from testdata/oracle.py; public TEST seeds, never real keys.',
            'seeds': [k.hex() for k in keys], 'vectors': vectors}


def ph():
    """Ed521ph: phflag 1 and PH = SHAKE256(x, 64) or SHA3-512 (DOC-ICP-01.01 2.2), dom5 with a context (2.3)."""
    key = seed(0)
    public = C.public_key(key)
    prehashes = {'SHAKE256-64': lambda m: hashlib.shake_256(m).digest(64), 'SHA3-512': lambda m: hashlib.sha3_512(m).digest()}
    vectors = []
    for kind, function in prehashes.items():
        for size in (0, 3, 100):
            for label, context in (('empty', b''), ('foo', b'foo'), ('255', bytes(range(255)))):
                data = message(size, 3)
                signature = C.sign(key, function(data), context=context, phflag=1)
                assert C.verify(public, function(data), signature, context=context, phflag=1)
                assert not C.verify(public, function(data), signature, context=context, phflag=0)
                assert not C.verify(public, data, signature, context=context, phflag=1)
                vectors.append({'name': f'ph-{kind}-{size}-octets-context-{label}', 'prehash': kind, 'public': public.hex(),
                                'context': context.hex(), 'message': data.hex(), 'signature': signature.hex()})
    return {'comment': 'Ed521ph vectors from testdata/oracle.py; public TEST seed, never a real key. The signed message is PH(message).',
            'seeds': [key.hex()], 'vectors': vectors}


if __name__ == '__main__':
    modes = {'negative': negative, 'pure': pure, 'ph': ph}
    if len(sys.argv) != 2 or sys.argv[1] not in modes:
        sys.exit('usage: make_vectors.py ' + '|'.join(modes))
    print(json.dumps(modes[sys.argv[1]](), indent=1))
