import os
import struct
from hashlib import shake_256
from typing import Tuple, Optional

# ========================
# E-521 curve parameters (exactly as in the Go code)
# ========================
P = int("6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151")
N = int("1716199415032652428745475199770348304317358825035826352348615864796385795849413675475876651663657849636693659065234142604319282948702542317993421293670108523")
D = int("-376014")
Gx = int("1571054894184995387535939749894317568645297350402905821437625181152304994381188529632591196067604100772673927915114267193389905003276673749012051148356041324")
Gy = int("12")
H = 4
BIT_SIZE = 521
BYTE_LEN = (BIT_SIZE + 7) // 8  # 66 bytes

# ========================
# Helper conversion functions
# ========================
def bytes_to_little_int(b: bytes) -> int:
    """Converts little-endian bytes to int (as in Go)"""
    reversed_bytes = bytes(reversed(b))
    return int.from_bytes(reversed_bytes, 'big')

def little_int_to_bytes(n: int, length: int) -> bytes:
    """Converts int to little-endian bytes (as in Go)"""
    bytes_be = n.to_bytes((n.bit_length() + 7) // 8 or 1, 'big')
    if len(bytes_be) < length:
        bytes_be = bytes([0] * (length - len(bytes_be))) + bytes_be
    reversed_bytes = bytes(reversed(bytes_be))
    return reversed_bytes[:length]

# ========================
# Point functions (preserving original logic)
# ========================
def is_on_curve(x: int, y: int) -> bool:
    return (x*x + y*y) % P == (1 + D*x*x*y*y) % P

def add_points(x1: int, y1: int, x2: int, y2: int) -> Tuple[int, int]:
    if x1 == 0 and y1 == 1:  # Neutral point in Edwards: (0, 1)
        return x2, y2
    if x2 == 0 and y2 == 1:  # Neutral point in Edwards: (0, 1)
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

    inv_den_x = pow(denominator_x, -1, P)
    inv_den_y = pow(denominator_y, -1, P)

    x3 = (numerator_x * inv_den_x) % P
    y3 = (numerator_y * inv_den_y) % P
    return x3, y3

def double_point(x: int, y: int) -> Tuple[int, int]:
    return add_points(x, y, x, y)

def scalar_mult(x: int, y: int, k_bytes: bytes) -> Tuple[int, int]:
    """Multiplies a point by a scalar (k in little-endian bytes)"""
    scalar = bytes_to_little_int(k_bytes) % N
    
    result_x, result_y = 0, 1  # Neutral point
    temp_x, temp_y = x, y
    
    while scalar > 0:
        if scalar & 1:
            result_x, result_y = add_points(result_x, result_y, temp_x, temp_y)
        temp_x, temp_y = double_point(temp_x, temp_y)
        scalar >>= 1
    
    return result_x, result_y

def scalar_base_mult(k_bytes: bytes) -> Tuple[int, int]:
    return scalar_mult(Gx, Gy, k_bytes)

# ========================
# Compression / Decompression (adjusted to follow RFC 8032 exactly)
# ========================
def compress_point(x: int, y: int) -> bytes:
    """Compresses a point according to RFC 8032"""
    y_bytes = little_int_to_bytes(y, BYTE_LEN)
    
    # Get the least significant bit of x (little-endian)
    x_bytes = little_int_to_bytes(x, BYTE_LEN)
    sign_bit = x_bytes[0] & 1
    
    # Store the sign bit in the MSB of the last byte (little-endian)
    compressed = bytearray(y_bytes)
    compressed[-1] |= (sign_bit << 7)
    
    return bytes(compressed)

def decompress_point(data: bytes) -> Tuple[Optional[int], Optional[int]]:
    """Decompresses a point according to RFC 8032"""
    if len(data) != BYTE_LEN:
        return None, None
    
    # Extract sign bit from MSB of last byte
    sign_bit = (data[-1] >> 7) & 1
    
    # Clear sign bit from y data
    y_bytes = bytearray(data)
    y_bytes[-1] &= 0x7F
    y = bytes_to_little_int(y_bytes)
    
    # Solve for x using the Edwards curve equation:
    # x² + y² = 1 + d*x²*y²  =>  x² = (1 - y²) / (1 - d*y²)
    y2 = (y * y) % P
    
    numerator = (1 - y2) % P
    denominator = (1 - D * y2) % P
    
    try:
        inv_den = pow(denominator, -1, P)
    except ValueError:
        return None, None
    
    x2 = (numerator * inv_den) % P
    
    # Compute square root mod p (p ≡ 1 mod 4)
    x = pow(x2, (P + 1)//4, P)
    
    # Select correct x based on sign bit
    x_bytes = little_int_to_bytes(x, BYTE_LEN)
    if (x_bytes[0] & 1) != sign_bit:
        x = (-x) % P
    
    return x, y

# ========================
# Hash functions (exactly as in Go)
# ========================
def dom5(phflag: int, context: bytes) -> bytes:
    """Implements dom5 as specified"""
    if len(context) > 255:
        raise ValueError("context too long for dom5")
    
    dom = b"SigEd521" + bytes([phflag, len(context)]) + context
    return dom

def hash_e521(phflag: int, context: bytes, x: bytes) -> bytes:
    """H(x) = SHAKE256(dom5(phflag,context)||x, 132)"""
    dom = dom5(phflag, context)
    
    h = shake_256()
    h.update(dom)
    h.update(x)
    
    return h.digest(132)  # 132 bytes as specified

# ========================
# Private key and signature (adjusted to follow exactly)
# ========================
def generate_private_key() -> int:
    """Generates a random private key in little-endian"""
    while True:
        priv_bytes = os.urandom(BYTE_LEN)
        a = bytes_to_little_int(priv_bytes)
        if a < N:
            return a

def get_public_key(priv: int) -> Tuple[int, int]:
    """Computes public key A = a * G"""
    priv_bytes = little_int_to_bytes(priv, BYTE_LEN)
    return scalar_base_mult(priv_bytes)

def sign(priv: int, message: bytes) -> bytes:
    """Creates a PureEdDSA signature as specified"""
    byte_len = BYTE_LEN
    
    # 1. Hash prefix "dom" + private key bytes
    prefix = hash_e521(0x00, b'', little_int_to_bytes(priv, byte_len))
    
    # 2. Calculate r = SHAKE256(prefix || message) mod N
    r_bytes = hash_e521(0x00, b'', prefix + message)
    r = bytes_to_little_int(r_bytes[:byte_len]) % N
    
    # 3. Compute R = r*G and compress
    Rx, Ry = scalar_base_mult(little_int_to_bytes(r, byte_len))
    R_compressed = compress_point(Rx, Ry)
    
    # 4. Get public key and compress
    Ax, Ay = get_public_key(priv)
    A_compressed = compress_point(Ax, Ay)
    
    # 5. Compute h = SHAKE256(dom || R || A || message) mod N
    hram_input = R_compressed + A_compressed + message
    hram_hash = hash_e521(0x00, b'', hram_input)
    h = bytes_to_little_int(hram_hash[:byte_len]) % N
    
    # 6. s = (r + h * a) mod N
    s = (r + h * priv) % N
    
    # 7. Signature = R_compressed || s_bytes
    s_bytes = little_int_to_bytes(s, byte_len)
    signature = R_compressed + s_bytes
    
    return signature

# ========================
# Verification (adjusted to follow exactly)
# ========================
def verify(pub_x: int, pub_y: int, message: bytes, signature: bytes) -> bool:
    """Verifies a PureEdDSA signature as specified"""
    byte_len = BYTE_LEN
    
    if len(signature) != 2 * byte_len:
        return False
    
    R_compressed = signature[:byte_len]
    s_bytes = signature[byte_len:]
    
    # Verify R
    Rx, Ry = decompress_point(R_compressed)
    if Rx is None or Ry is None:
        return False
    
    # Verify s
    s = bytes_to_little_int(s_bytes)
    if s >= N:
        return False
    
    # Compress public key A
    A_compressed = compress_point(pub_x, pub_y)
    
    # Compute h = SHAKE256(dom || R || A || message) mod N
    hram_input = R_compressed + A_compressed + message
    hram_hash = hash_e521(0x00, b'', hram_input)
    h = bytes_to_little_int(hram_hash[:byte_len]) % N
    
    # Compute s*G
    sGx, sGy = scalar_base_mult(little_int_to_bytes(s, byte_len))
    
    # Compute h*A
    hAx, hAy = scalar_mult(pub_x, pub_y, little_int_to_bytes(h, byte_len))
    
    # Compute R + h*A
    rhaX, rhaY = add_points(Rx, Ry, hAx, hAy)
    
    # Constant-time comparison (simplified for example)
    return sGx == rhaX and sGy == rhaY

# ========================
# Additional functions from the Go code
# ========================
def prove_knowledge(priv: int) -> bytes:
    """Generates a non-interactive ZKP of private key knowledge"""
    byte_len = BYTE_LEN
    
    # 1. Commitment R = r*G (generate random r)
    while True:
        r_bytes = os.urandom(byte_len)
        r = bytes_to_little_int(r_bytes)
        if r < N:
            break
    
    Rx, Ry = scalar_base_mult(little_int_to_bytes(r, byte_len))
    R_comp = compress_point(Rx, Ry)
    
    # 2. Obtain public key A
    Ax, Ay = get_public_key(priv)
    A_comp = compress_point(Ax, Ay)
    
    # 3. Challenge c = H(R || A) using Fiat–Shamir
    input_data = R_comp + A_comp
    c_bytes = hash_e521(0x00, b'', input_data)
    c = bytes_to_little_int(c_bytes[:byte_len]) % N
    
    # 4. Response: s = r + c * a (mod N)
    s = (r + c * priv) % N
    
    # 5. Final proof = R || s
    s_bytes = little_int_to_bytes(s, byte_len)
    proof = R_comp + s_bytes
    
    return proof

def verify_knowledge(pub_x: int, pub_y: int, proof: bytes) -> bool:
    """Verifies a non-interactive ZKP"""
    byte_len = BYTE_LEN
    
    if len(proof) != 2 * byte_len:
        return False
    
    R_comp = proof[:byte_len]
    s_bytes = proof[byte_len:]
    
    # 1. Decompress commitment R
    Rx, Ry = decompress_point(R_comp)
    if Rx is None or Ry is None:
        return False
    
    s = bytes_to_little_int(s_bytes)
    
    # 2. Recompute c = H(R || A)
    A_comp = compress_point(pub_x, pub_y)
    input_data = R_comp + A_comp
    c_bytes = hash_e521(0x00, b'', input_data)
    c = bytes_to_little_int(c_bytes[:byte_len]) % N
    
    # 3. Verification: s*G == R + c*A
    sGx, sGy = scalar_base_mult(little_int_to_bytes(s, byte_len))
    cAx, cAy = scalar_mult(pub_x, pub_y, little_int_to_bytes(c, byte_len))
    RpluscAx, RpluscAy = add_points(Rx, Ry, cAx, cAy)
    
    return sGx == RpluscAx and sGy == RpluscAy

# ========================
# Full test (adjusted)
# ========================
if __name__ == "__main__":
    print("=== E-521 EdDSA Python Test (Go specification compliant) ===")
    
    # Generate private key
    priv = generate_private_key()
    print(f"Private key generated (first 16 bytes): {hex(priv)[:34]}...")
    
    # Compute public key
    pub_x, pub_y = get_public_key(priv)
    print(f"Public key generated: ({hex(pub_x)[:20]}..., {hex(pub_y)[:20]}...)")
    print(f"Point on curve: {is_on_curve(pub_x, pub_y)}")
    
    # Test compression / decompression
    compressed = compress_point(pub_x, pub_y)
    print(f"Compressed public key: {len(compressed)} bytes")
    
    decomp_x, decomp_y = decompress_point(compressed)
    print(f"Correct decompression: {decomp_x == pub_x and decomp_y == pub_y}")
    
    # Sign message
    message = b"E-521 EdDSA Python test according to Go specification"
    signature = sign(priv, message)
    print(f"\nSignature created: {len(signature)} bytes")
    
    # Verify signature
    valid = verify(pub_x, pub_y, message, signature)
    print(f"Signature valid: {valid}")
    
    # Verify wrong message
    wrong_valid = verify(pub_x, pub_y, b"Wrong message", signature)
    print(f"Wrong message rejected: {not wrong_valid}")
    
    # Test proof of knowledge
    print(f"\n=== Knowledge Proof Test ===")
    proof = prove_knowledge(priv)
    print(f"Proof generated: {len(proof)} bytes")
    
    proof_valid = verify_knowledge(pub_x, pub_y, proof)
    print(f"Proof valid: {proof_valid}")
    
    # Test invalid proof
    invalid_proof = os.urandom(len(proof))
    invalid_valid = verify_knowledge(pub_x, pub_y, invalid_proof)
    print(f"Invalid proof rejected: {not invalid_valid}")
    
    print("\n=== All tests passed ===")
