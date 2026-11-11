#!/usr/bin/env python3
# e521.py
# Pure Python implementation of ED521 (E-521 curve), byte-compatible with
# the Go implementation at github.com/pedroalbanese/e521.
#
# Note: mirrors the Go code exactly. It does NOT perform RFC 8032 §5.2.5
# seed expansion; the private scalar D is used directly, and the "prefix"
# used during signing is SHAKE256(dom5 || D_le_bytes, 132).

import os
import sys
import base64
import argparse
from hashlib import shake_256
from typing import Tuple, Optional

# ====================================================================
# E-521 curve parameters
# ====================================================================

P = int("6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151")
N = int("1716199415032652428745475199770348304317358825035826352348615864796385795849413675475876651663657849636693659065234142604319282948702542317993421293670108523")
D_RAW = int("-376014")
D = D_RAW % P  # normalize to non-negative

Gx = int("1571054894184995387535939749894317568645297350402905821437625181152304994381188529632591196067604100772673927915114267193389905003276673749012051148356041324")
Gy = 12
H = 4

BIT_SIZE = 521
BYTE_LEN = (BIT_SIZE + 7) // 8  # 66

# OID 1.3.6.1.4.1.44588.2.1
OID = (1, 3, 6, 1, 4, 1, 44588, 2, 1)
OID_DER = bytes([0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xdc, 0x2c, 0x02, 0x01])


# ====================================================================
# Byte helpers
# ====================================================================

def bytes_to_little_int(b: bytes) -> int:
    return int.from_bytes(bytes(reversed(b)), 'big')


def little_int_to_bytes(n: int, length: int) -> bytes:
    if n < 0:
        raise ValueError("negative not supported")
    if n == 0:
        return b'\x00' * length
    n_bytes = (n.bit_length() + 7) // 8
    if n_bytes > length:
        raise ValueError(f"integer too large for {length} bytes")
    be = n.to_bytes(n_bytes, 'big')
    be = b'\x00' * (length - len(be)) + be
    return bytes(reversed(be))


def hex_to_bytes(h: str) -> bytes:
    h = h.strip().replace(" ", "").replace("\n", "").replace("\r", "")
    if len(h) % 2:
        raise ValueError("odd hex length")
    return bytes.fromhex(h)


def bytes_to_hex(b: bytes) -> str:
    return b.hex()


# ====================================================================
# Square root modulo p
#
# E-521: p = 2^521 - 1.  p mod 8 = 7, so we use the p ≡ 7 (mod 8) formula:
#
#     x = a^((p+1)/4) mod p
#
# This returns a square root of a when a is a quadratic residue, or None
# when a is a non-residue.
# ====================================================================

def sqrt_mod_p(a: int, p: int) -> Optional[int]:
    """Square root modulo p when p ≡ 7 (mod 8)."""
    a %= p
    if a == 0:
        return 0
    x = pow(a, (p + 1) // 4, p)
    if (x * x) % p == a:
        return x
    return None


# ====================================================================
# Curve operations (Edwards form, matching Go exactly)
# ====================================================================

def is_on_curve(x: int, y: int) -> bool:
    return (x * x + y * y) % P == (1 + D * x * x * y * y) % P


def add_points(x1: int, y1: int, x2: int, y2: int) -> Tuple[int, int]:
    # Go treats (0,0) as neutral (non-canonical, but that's what the Go code does)
    if x1 == 0 and y1 == 0:
        return x2, y2
    if x2 == 0 and y2 == 0:
        return x1, y1

    x1y2 = (x1 * y2) % P
    y1x2 = (y1 * x2) % P
    numerator_x = (x1y2 + y1x2) % P

    y1y2 = (y1 * y2) % P
    x1x2 = (x1 * x2) % P
    numerator_y = (y1y2 - x1x2) % P

    dx1x2y1y2 = (D * x1x2 * y1y2) % P

    denominator_x = (1 + dx1x2y1y2) % P
    denominator_y = (1 - dx1x2y1y2) % P

    inv_x = pow(denominator_x, -1, P)
    inv_y = pow(denominator_y, -1, P)

    x3 = (numerator_x * inv_x) % P
    y3 = (numerator_y * inv_y) % P
    return x3, y3


def double_point(x: int, y: int) -> Tuple[int, int]:
    return add_points(x, y, x, y)


def scalar_mult(x: int, y: int, k_bytes: bytes) -> Tuple[int, int]:
    scalar = bytes_to_little_int(k_bytes) % N
    result_x, result_y = 0, 1
    temp_x, temp_y = x, y
    while scalar > 0:
        if scalar & 1:
            result_x, result_y = add_points(result_x, result_y, temp_x, temp_y)
        temp_x, temp_y = double_point(temp_x, temp_y)
        scalar >>= 1
    return result_x, result_y


def scalar_base_mult(k_bytes: bytes) -> Tuple[int, int]:
    return scalar_mult(Gx, Gy, k_bytes)


# ====================================================================
# Compression / decompression (RFC 8032 style, Go-compatible)
# ====================================================================

def compress_point(x: int, y: int) -> bytes:
    y_bytes = little_int_to_bytes(y, BYTE_LEN)
    x_bytes = little_int_to_bytes(x, BYTE_LEN)
    sign_bit = x_bytes[0] & 1
    buf = bytearray(y_bytes)
    buf[-1] |= (sign_bit << 7)
    return bytes(buf)


def decompress_point(data: bytes) -> Tuple[Optional[int], Optional[int]]:
    if len(data) != BYTE_LEN:
        return None, None

    sign_bit = (data[-1] >> 7) & 1
    y_buf = bytearray(data)
    y_buf[-1] &= 0x7F
    y = bytes_to_little_int(bytes(y_buf))

    if y >= P:
        return None, None

    y2 = (y * y) % P
    numerator = (1 - y2) % P
    denominator = (1 - D * y2) % P

    try:
        inv_den = pow(denominator, -1, P)
    except ValueError:
        return None, None

    x2 = (numerator * inv_den) % P
    x = sqrt_mod_p(x2, P)
    if x is None:
        return None, None

    if x == 0 and sign_bit == 1:
        return None, None

    x_bytes = little_int_to_bytes(x, BYTE_LEN)
    if (x_bytes[0] & 1) != sign_bit:
        x = (-x) % P

    return x, y


# ====================================================================
# dom5 / hash_e521
# ====================================================================

def dom5(phflag: int, context: bytes) -> bytes:
    if len(context) > 255:
        raise ValueError("context too long for dom5")
    return b"SigEd521" + bytes([phflag, len(context)]) + context


def hash_e521(phflag: int, context: bytes, x: bytes) -> bytes:
    h = shake_256()
    h.update(dom5(phflag, context))
    h.update(x)
    return h.digest(132)


# ====================================================================
# Key generation (Go-compatible: D used directly)
# ====================================================================

def rand_little_int(max_val: int) -> int:
    byte_len = (max_val.bit_length() + 7) // 8
    while True:
        buf = os.urandom(byte_len)
        num = bytes_to_little_int(buf)
        if num < max_val:
            return num


def generate_private_key() -> int:
    return rand_little_int(N)


def get_public_key(priv: int) -> Tuple[int, int]:
    return scalar_base_mult(little_int_to_bytes(priv, BYTE_LEN))


# ====================================================================
# Pure EdDSA over E-521 (Go-compatible)
# ====================================================================

def sign(priv: int, message: bytes) -> bytes:
    # 1. prefix = SHAKE256(dom5 || D_le, 132)
    prefix = hash_e521(0x00, b'', little_int_to_bytes(priv, BYTE_LEN))

    # 2. r = SHAKE256(dom5 || prefix || message, 132) mod N
    r_bytes = hash_e521(0x00, b'', prefix + message)
    r = bytes_to_little_int(r_bytes) % N

    # 3. R = r*G
    Rx, Ry = scalar_base_mult(little_int_to_bytes(r, BYTE_LEN))
    R_comp = compress_point(Rx, Ry)

    # 4. A = D*G
    Ax, Ay = scalar_base_mult(little_int_to_bytes(priv, BYTE_LEN))
    A_comp = compress_point(Ax, Ay)

    # 5. h = SHAKE256(dom5 || R || A || message, 132) mod N
    h_hash = hash_e521(0x00, b'', R_comp + A_comp + message)
    h = bytes_to_little_int(h_hash) % N

    # 6. s = (h*D + r) mod N
    s = (h * priv + r) % N

    return R_comp + little_int_to_bytes(s, BYTE_LEN)


def verify(pub_x: int, pub_y: int, message: bytes, signature: bytes) -> bool:
    if len(signature) != 2 * BYTE_LEN:
        return False

    R_comp = signature[:BYTE_LEN]
    s = bytes_to_little_int(signature[BYTE_LEN:])
    if s >= N:
        return False

    Rx, Ry = decompress_point(R_comp)
    if Rx is None or Ry is None:
        return False

    A_comp = compress_point(pub_x, pub_y)
    h_hash = hash_e521(0x00, b'', R_comp + A_comp + message)
    h = bytes_to_little_int(h_hash) % N

    sGx, sGy = scalar_base_mult(little_int_to_bytes(s, BYTE_LEN))
    hAx, hAy = scalar_mult(pub_x, pub_y, little_int_to_bytes(h, BYTE_LEN))
    rha_x, rha_y = add_points(Rx, Ry, hAx, hAy)

    return sGx == rha_x and sGy == rha_y


# ====================================================================
# ZKP of knowledge (Schnorr / Fiat–Shamir), Go-compatible
# (Note: Go truncates c to byteLen bytes here, unlike sign/verify)
# ====================================================================

def prove_knowledge(priv: int) -> bytes:
    r = rand_little_int(N)
    Rx, Ry = scalar_base_mult(little_int_to_bytes(r, BYTE_LEN))
    R_comp = compress_point(Rx, Ry)

    Ax, Ay = scalar_base_mult(little_int_to_bytes(priv, BYTE_LEN))
    A_comp = compress_point(Ax, Ay)

    c_bytes = hash_e521(0x00, b'', R_comp + A_comp)
    c = bytes_to_little_int(c_bytes[:BYTE_LEN]) % N

    s = (c * priv + r) % N
    return R_comp + little_int_to_bytes(s, BYTE_LEN)


def verify_knowledge(pub_x: int, pub_y: int, proof: bytes) -> bool:
    if len(proof) != 2 * BYTE_LEN:
        return False

    R_comp = proof[:BYTE_LEN]
    s = bytes_to_little_int(proof[BYTE_LEN:])

    Rx, Ry = decompress_point(R_comp)
    if Rx is None or Ry is None:
        return False

    A_comp = compress_point(pub_x, pub_y)
    c_bytes = hash_e521(0x00, b'', R_comp + A_comp)
    c = bytes_to_little_int(c_bytes[:BYTE_LEN]) % N

    sGx, sGy = scalar_base_mult(little_int_to_bytes(s, BYTE_LEN))
    cAx, cAy = scalar_mult(pub_x, pub_y, little_int_to_bytes(c, BYTE_LEN))
    rca_x, rca_y = add_points(Rx, Ry, cAx, cAy)

    return sGx == rca_x and sGy == rca_y


# ====================================================================
# Minimal DER encoder / decoder
# ====================================================================

def der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(b)]) + b


def der_seq(content: bytes) -> bytes:
    return b'\x30' + der_len(len(content)) + content


def der_int(n: int) -> bytes:
    if n == 0:
        return b'\x02\x01\x00'
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    if b[0] & 0x80:
        b = b'\x00' + b
    return b'\x02' + der_len(len(b)) + b


def der_octet_string(b: bytes) -> bytes:
    return b'\x04' + der_len(len(b)) + b


def der_bit_string(b: bytes, unused_bits: int = 0) -> bytes:
    content = bytes([unused_bits]) + b
    return b'\x03' + der_len(len(content)) + content


def der_read_tlv(data: bytes, idx: int) -> Tuple[int, bytes, int]:
    """Returns (tag, value, next_idx)."""
    if idx >= len(data):
        raise ValueError("DER: unexpected end")
    tag = data[idx]
    idx += 1
    if idx >= len(data):
        raise ValueError("DER: unexpected end (length)")
    first = data[idx]
    idx += 1
    if first & 0x80:
        n = first & 0x7F
        if n == 0:
            raise ValueError("DER: indefinite length not supported")
        if idx + n > len(data):
            raise ValueError("DER: truncated length")
        length = int.from_bytes(data[idx:idx + n], 'big')
        idx += n
    else:
        length = first
    if idx + length > len(data):
        raise ValueError("DER: truncated value")
    value = data[idx:idx + length]
    return tag, value, idx + length


# ====================================================================
# PKCS#8 private key (Go-compatible: Parameters = 06 00)
# ====================================================================

def private_key_to_pem(priv: int) -> str:
    priv_bytes = little_int_to_bytes(priv, BYTE_LEN)

    # AlgorithmIdentifier: SEQUENCE { OID, OID(empty) }
    #   Parameters = asn1.RawValue{Tag: TagOID} -> 06 00
    alg_id = der_seq(OID_DER + b'\x06\x00')

    version = der_int(0)
    priv_field = der_octet_string(priv_bytes)

    pkcs8 = der_seq(version + alg_id + priv_field)

    b64 = base64.b64encode(pkcs8).decode('ascii')
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    return ("-----BEGIN E-521 PRIVATE KEY-----\n"
            + "\n".join(lines)
            + "\n-----END E-521 PRIVATE KEY-----\n")


def public_key_to_pem(pub_x: int, pub_y: int) -> str:
    compressed = compress_point(pub_x, pub_y)

    alg_id = der_seq(OID_DER + b'\x06\x00')
    bit_str = der_bit_string(compressed, 0)

    spki = der_seq(alg_id + bit_str)

    b64 = base64.b64encode(spki).decode('ascii')
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    return ("-----BEGIN E-521 PUBLIC KEY-----\n"
            + "\n".join(lines)
            + "\n-----END E-521 PUBLIC KEY-----\n")


# ====================================================================
# PEM parsing
# ====================================================================

def _load_pem_b64(path: str, expected_label: str) -> bytes:
    with open(path, 'r') as f:
        text = f.read()
    lines = text.strip().splitlines()
    body = []
    in_block = False
    found = False
    for line in lines:
        if line.startswith("-----BEGIN "):
            if expected_label in line:
                in_block = True
                found = True
            else:
                in_block = False
        elif line.startswith("-----END "):
            in_block = False
        elif in_block:
            body.append(line.strip())
    if not found:
        raise ValueError(f"PEM: no '{expected_label}' block found in {path}")
    return base64.b64decode("".join(body))


def read_private_key_from_pem(path: str) -> int:
    der = _load_pem_b64(path, "PRIVATE KEY")
    tag, content, _ = der_read_tlv(der, 0)
    if tag != 0x30:
        raise ValueError("PKCS#8: expected SEQUENCE")

    idx = 0
    tag, _version_bytes, idx = der_read_tlv(content, idx)
    if tag != 0x02:
        raise ValueError("PKCS#8: expected INTEGER (version)")

    tag, _alg, idx = der_read_tlv(content, idx)
    if tag != 0x30:
        raise ValueError("PKCS#8: expected AlgorithmIdentifier")

    tag, key_bytes, idx = der_read_tlv(content, idx)
    if tag != 0x04:
        raise ValueError("PKCS#8: expected OCTET STRING")

    if len(key_bytes) != BYTE_LEN:
        raise ValueError(f"PKCS#8: unexpected private key length {len(key_bytes)}")

    return bytes_to_little_int(key_bytes)


def read_public_key_from_pem(path: str) -> Tuple[int, int]:
    der = _load_pem_b64(path, "PUBLIC KEY")
    tag, content, _ = der_read_tlv(der, 0)
    if tag != 0x30:
        raise ValueError("SPKI: expected SEQUENCE")

    idx = 0
    tag, _alg, idx = der_read_tlv(content, idx)
    if tag != 0x30:
        raise ValueError("SPKI: expected AlgorithmIdentifier")

    tag, bs, idx = der_read_tlv(content, idx)
    if tag != 0x03:
        raise ValueError("SPKI: expected BIT STRING")

    if len(bs) < 1:
        raise ValueError("SPKI: empty BIT STRING")
    unused = bs[0]
    if unused != 0:
        raise ValueError(f"SPKI: unsupported unused bits ({unused})")

    compressed = bs[1:]
    if len(compressed) != BYTE_LEN:
        raise ValueError(f"SPKI: unexpected key length {len(compressed)}")

    x, y = decompress_point(compressed)
    if x is None or y is None:
        raise ValueError("SPKI: failed to decompress public key")
    return x, y


# ====================================================================
# Self-tests
# ====================================================================

def test_core():
    print("Testing ED521 (E-521) — Go-compatible variant")
    print("=" * 70)

    priv = generate_private_key()
    pub_x, pub_y = get_public_key(priv)
    print("1. Key generation: OK")

    compressed = compress_point(pub_x, pub_y)
    dx, dy = decompress_point(compressed)
    if dx is not None and dy is not None and dx == pub_x and dy == pub_y:
        print("2. Compress/decompress: OK")
    else:
        print("2. Compress/decompress: FAILED")

    msg = b"Test message"
    sig = sign(priv, msg)
    print(f"3. Sign/verify: {'VALID' if verify(pub_x, pub_y, msg, sig) else 'INVALID'}")

    other = b"Another message"
    print(f"4. Tampered message rejected: {'VALID' if not verify(pub_x, pub_y, other, sig) else 'INVALID'}")

    proof = prove_knowledge(priv)
    print(f"5. ZKP: {'VALID' if verify_knowledge(pub_x, pub_y, proof) else 'INVALID'}")

    print("=" * 70)


def test_shake256():
    print(f'SHAKE256("test", 132) = {shake_256(b"test").hexdigest(132)}')
    print(f'SHAKE256("", 132)     = {shake_256(b"").hexdigest(132)}')


# ====================================================================
# CLI
# ====================================================================

def cmd_generate(args):
    priv = generate_private_key()
    pub_x, pub_y = get_public_key(priv)
    base = args.output or "ed521"
    priv_path = f"{base}_private.pem"
    pub_path = f"{base}_public.pem"
    with open(priv_path, "w") as f:
        f.write(private_key_to_pem(priv))
    with open(pub_path, "w") as f:
        f.write(public_key_to_pem(pub_x, pub_y))
    print(f"keys written to {priv_path} and {pub_path}")


def _read_message(args) -> bytes:
    if args.msg is not None and args.file is not None:
        sys.exit("error: use --msg OR --file, not both")
    if args.msg is not None:
        return args.msg.encode()
    if args.file is not None:
        if args.file == "-":
            return sys.stdin.buffer.read()
        with open(args.file, "rb") as f:
            return f.read()
    sys.exit("error: provide --msg or --file")


def _read_hex_arg(arg: str) -> bytes:
    if arg.startswith("@"):
        with open(arg[1:], "r") as f:
            return hex_to_bytes(f.read())
    return hex_to_bytes(arg)


def cmd_sign(args):
    if not args.priv:
        sys.exit("error: sign requires --priv")
    if args.pub or args.sig or args.proof:
        sys.exit("error: sign accepts only --priv, --msg/--file, --output")
    priv = read_private_key_from_pem(args.priv)
    msg = _read_message(args)
    sig_hex = bytes_to_hex(sign(priv, msg))
    if args.output:
        with open(args.output, "w") as f:
            f.write(sig_hex + "\n")
        print(f"signature written to: {args.output}")
    else:
        print(sig_hex)


def cmd_verify(args):
    if not args.pub:
        sys.exit("error: verify requires --pub")
    if not args.sig:
        sys.exit("error: verify requires --sig")
    if args.priv or args.proof:
        sys.exit("error: verify accepts only --pub, --sig, --msg/--file")
    pub_x, pub_y = read_public_key_from_pem(args.pub)
    msg = _read_message(args)
    sig = _read_hex_arg(args.sig)
    if verify(pub_x, pub_y, msg, sig):
        print("signature valid")
        sys.exit(0)
    print("signature invalid")
    sys.exit(1)


def cmd_prove(args):
    if not args.priv:
        sys.exit("error: prove requires --priv")
    if args.pub or args.sig or args.proof:
        sys.exit("error: prove accepts only --priv, --output")
    priv = read_private_key_from_pem(args.priv)
    proof_hex = bytes_to_hex(prove_knowledge(priv))
    if args.output:
        with open(args.output, "w") as f:
            f.write(proof_hex + "\n")
        print(f"proof written to: {args.output}")
    else:
        print(proof_hex)


def cmd_verify_proof(args):
    if not args.pub:
        sys.exit("error: verify-proof requires --pub")
    if not args.proof:
        sys.exit("error: verify-proof requires --proof")
    if args.priv or args.sig:
        sys.exit("error: verify-proof accepts only --pub, --proof")
    pub_x, pub_y = read_public_key_from_pem(args.pub)
    proof = _read_hex_arg(args.proof)
    if verify_knowledge(pub_x, pub_y, proof):
        print("proof valid")
        sys.exit(0)
    print("proof invalid")
    sys.exit(1)


def cmd_test(args):
    test_core()


def cmd_test_shake(args):
    test_shake256()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ed521",
        description="E-521 pure EdDSA (Go-compatible)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  ed521 generate --output mykey\n"
            "  ed521 sign --priv mykey_private.pem --file msg.txt\n"
            "  ed521 verify --pub mykey_public.pem --file msg.txt --sig @sig.hex\n"
        ),
    )
    sub = p.add_subparsers(dest="command", required=True)

    def add_common(sp, priv=True, pub=True, msg=True, sig=False, proof=False, output=True):
        if priv:
            sp.add_argument("--priv", metavar="FILE", help="PEM private key")
        if pub:
            sp.add_argument("--pub", metavar="FILE", help="PEM public key")
        if msg:
            sp.add_argument("--msg", help="message text")
            sp.add_argument("--file", metavar="FILE", help="message file ('-' = stdin)")
        if sig:
            sp.add_argument("--sig", metavar="HEX|@FILE", help="signature hex or @file")
        if proof:
            sp.add_argument("--proof", metavar="HEX|@FILE", help="proof hex or @file")
        if output:
            sp.add_argument("--output", metavar="FILE", help="output file")

    sp = sub.add_parser("generate", help="generate key pair")
    add_common(sp, priv=False, pub=False, msg=False, output=True)
    sp.set_defaults(func=cmd_generate)

    sp = sub.add_parser("sign", help="sign a message")
    add_common(sp, priv=True, pub=False, msg=True, output=True)
    sp.set_defaults(func=cmd_sign)

    sp = sub.add_parser("verify", help="verify a signature")
    add_common(sp, priv=False, pub=True, msg=True, sig=True, output=False)
    sp.set_defaults(func=cmd_verify)

    sp = sub.add_parser("prove", help="generate ZKP of knowledge")
    add_common(sp, priv=True, pub=False, msg=False, output=True)
    sp.set_defaults(func=cmd_prove)

    sp = sub.add_parser("verify-proof", help="verify ZKP of knowledge")
    add_common(sp, priv=False, pub=True, msg=False, proof=True, output=False)
    sp.set_defaults(func=cmd_verify_proof)

    sp = sub.add_parser("test", help="run core self-tests")
    sp.set_defaults(func=cmd_test)

    sp = sub.add_parser("test-shake", help="print SHAKE256 vectors")
    sp.set_defaults(func=cmd_test_shake)

    return p


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
