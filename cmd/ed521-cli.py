#!/usr/bin/env python3
"""
EDGE Crypto Toolbox - Pure Python Version
ED521, PKCS8 com Curupira-192-CBC
"""

import argparse
import sys
import os
import hashlib
import base64
import binascii
import getpass
from typing import Tuple, Optional

# =========================
# ED521 IMPLEMENTATION
# =========================

P = int("6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151")
N = int("1716199415032652428745475199770348304317358825035826352348615864796385795849413675475876651663657849636693659065234142604319282948702542317993421293670108523")
D = int("-376014")
Gx = int("1571054894184995387535939749894317568645297350402905821437625181152304994381188529632591196067604100772673927915114267193389905003276673749012051148356041324")
Gy = int("12")
H = 4
BIT_SIZE = 521
ED521_BYTE_LEN = (BIT_SIZE + 7) // 8

ED521_OID = b'\x06\x0a\x2b\x06\x01\x04\x01\x83\xa6\x7a\x02\x01'

def bytes_to_little_int(b: bytes) -> int:
    """Converte bytes little-endian para int (como no Go)"""
    reversed_bytes = bytes(reversed(b))
    return int.from_bytes(reversed_bytes, 'big')

def little_int_to_bytes(n: int, length: int) -> bytes:
    """Converte int para bytes little-endian (como no Go)"""
    bytes_be = n.to_bytes((n.bit_length() + 7) // 8 or 1, 'big')
    if len(bytes_be) < length:
        bytes_be = bytes([0] * (length - len(bytes_be))) + bytes_be
    reversed_bytes = bytes(reversed(bytes_be))
    return reversed_bytes[:length]

def ed521_is_on_curve(x: int, y: int) -> bool:
    return (x*x + y*y) % P == (1 + D*x*x*y*y) % P

def ed521_add_points(x1: int, y1: int, x2: int, y2: int) -> Tuple[int, int]:
    if x1 == 0 and y1 == 1:
        return x2, y2
    if x2 == 0 and y2 == 1:
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

def ed521_double_point(x: int, y: int) -> Tuple[int, int]:
    return ed521_add_points(x, y, x, y)

def ed521_scalar_mult(x: int, y: int, k_bytes: bytes) -> Tuple[int, int]:
    """Multiplica ponto por escalar (k em bytes little-endian)"""
    scalar = bytes_to_little_int(k_bytes) % N
    
    result_x, result_y = 0, 1
    temp_x, temp_y = x, y
    
    while scalar > 0:
        if scalar & 1:
            result_x, result_y = ed521_add_points(result_x, result_y, temp_x, temp_y)
        temp_x, temp_y = ed521_double_point(temp_x, temp_y)
        scalar >>= 1
    
    return result_x, result_y

def ed521_scalar_base_mult(k_bytes: bytes) -> Tuple[int, int]:
    return ed521_scalar_mult(Gx, Gy, k_bytes)

def ed521_compress_point(x: int, y: int) -> bytes:
    """Comprime ponto conforme RFC 8032"""
    y_bytes = little_int_to_bytes(y, ED521_BYTE_LEN)
    
    x_bytes = little_int_to_bytes(x, ED521_BYTE_LEN)
    sign_bit = x_bytes[0] & 1
    
    compressed = bytearray(y_bytes)
    compressed[-1] |= (sign_bit << 7)
    
    return bytes(compressed)

def ed521_decompress_point(data: bytes) -> Tuple[Optional[int], Optional[int]]:
    """Descomprime ponto conforme RFC 8032"""
    if len(data) != ED521_BYTE_LEN:
        return None, None
    
    sign_bit = (data[-1] >> 7) & 1
    
    y_bytes = bytearray(data)
    y_bytes[-1] &= 0x7F
    y = bytes_to_little_int(y_bytes)
    
    y2 = (y * y) % P
    
    numerator = (1 - y2) % P
    denominator = (1 - D * y2) % P
    
    try:
        inv_den = pow(denominator, -1, P)
    except ValueError:
        return None, None
    
    x2 = (numerator * inv_den) % P
    
    x = pow(x2, (P + 1)//4, P)
    
    x_bytes = little_int_to_bytes(x, ED521_BYTE_LEN)
    if (x_bytes[0] & 1) != sign_bit:
        x = (-x) % P
    
    return x, y

def ed521_dom5(phflag: int, context: bytes) -> bytes:
    """Implementa dom5 conforme especificação"""
    if len(context) > 255:
        raise ValueError("context too long for dom5")
    
    dom = b"SigEd521" + bytes([phflag, len(context)]) + context
    return dom

def ed521_hash(phflag: int, context: bytes, x: bytes) -> bytes:
    """H(x) = SHAKE256(dom5(phflag,context)||x, 132)"""
    from hashlib import shake_256
    
    dom = ed521_dom5(phflag, context)
    
    h = shake_256()
    h.update(dom)
    h.update(x)
    
    return h.digest(132)

def ed521_generate_private_key() -> int:
    """Gera chave privada aleatória em little-endian"""
    while True:
        priv_bytes = os.urandom(ED521_BYTE_LEN)
        a = bytes_to_little_int(priv_bytes)
        if a < N:
            return a

def ed521_get_public_key(priv: int) -> Tuple[int, int]:
    """Calcula chave pública A = a * G"""
    priv_bytes = little_int_to_bytes(priv, ED521_BYTE_LEN)
    return ed521_scalar_base_mult(priv_bytes)

def ed521_sign(private_key: int, message: bytes) -> bytes:
    """Cria assinatura PureEdDSA conforme especificação"""
    byte_len = ED521_BYTE_LEN
    
    prefix = ed521_hash(0x00, b'', little_int_to_bytes(private_key, byte_len))
    
    r_bytes = ed521_hash(0x00, b'', prefix + message)
    r = bytes_to_little_int(r_bytes[:byte_len]) % N
    
    Rx, Ry = ed521_scalar_base_mult(little_int_to_bytes(r, byte_len))
    R_compressed = ed521_compress_point(Rx, Ry)
    
    Ax, Ay = ed521_get_public_key(private_key)
    A_compressed = ed521_compress_point(Ax, Ay)
    
    hram_input = R_compressed + A_compressed + message
    hram_hash = ed521_hash(0x00, b'', hram_input)
    h = bytes_to_little_int(hram_hash[:byte_len]) % N
    
    s = (r + h * private_key) % N
    
    s_bytes = little_int_to_bytes(s, byte_len)
    signature = R_compressed + s_bytes
    
    return signature

def ed521_verify(pub_x: int, pub_y: int, message: bytes, signature: bytes) -> bool:
    """Verifica assinatura PureEdDSA conforme especificação"""
    byte_len = ED521_BYTE_LEN
    
    if len(signature) != 2 * byte_len:
        return False
    
    R_compressed = signature[:byte_len]
    s_bytes = signature[byte_len:]
    
    Rx, Ry = ed521_decompress_point(R_compressed)
    if Rx is None or Ry is None:
        return False
    
    s = bytes_to_little_int(s_bytes)
    if s >= N:
        return False
    
    A_compressed = ed521_compress_point(pub_x, pub_y)
    
    hram_input = R_compressed + A_compressed + message
    hram_hash = ed521_hash(0x00, b'', hram_input)
    h = bytes_to_little_int(hram_hash[:byte_len]) % N
    
    sGx, sGy = ed521_scalar_base_mult(little_int_to_bytes(s, byte_len))
    
    hAx, hAy = ed521_scalar_mult(pub_x, pub_y, little_int_to_bytes(h, byte_len))
    
    rhaX, rhaY = ed521_add_points(Rx, Ry, hAx, hAy)
    
    return sGx == rhaX and sGy == rhaY

def ed521_prove_knowledge(priv: int) -> bytes:
    """
    Generate non-interactive ZKP proof of private key knowledge
    Based on the Go implementation
    """
    byte_len = ED521_BYTE_LEN
    
    while True:
        r_bytes = os.urandom(byte_len)
        r = bytes_to_little_int(r_bytes)
        if r < N:
            break
    
    Rx, Ry = ed521_scalar_base_mult(little_int_to_bytes(r, byte_len))
    R_comp = ed521_compress_point(Rx, Ry)
    
    Ax, Ay = ed521_get_public_key(priv)
    A_comp = ed521_compress_point(Ax, Ay)
    
    input_data = R_comp + A_comp
    c_bytes = ed521_hash(0x00, b'', input_data)
    c = bytes_to_little_int(c_bytes[:byte_len]) % N
    
    s = (r + c * priv) % N
    
    s_bytes = little_int_to_bytes(s, byte_len)
    proof = R_comp + s_bytes
    
    return proof

def ed521_verify_knowledge(pub_x: int, pub_y: int, proof: bytes) -> bool:
    """
    Verify ZKP non-interactive proof
    Based on the Go implementation
    """
    byte_len = ED521_BYTE_LEN
    
    if len(proof) != 2 * byte_len:
        return False
    
    R_comp = proof[:byte_len]
    s_bytes = proof[byte_len:]
    
    Rx, Ry = ed521_decompress_point(R_comp)
    if Rx is None or Ry is None:
        return False
    
    s = bytes_to_little_int(s_bytes)
    
    A_comp = ed521_compress_point(pub_x, pub_y)
    input_data = R_comp + A_comp
    c_bytes = ed521_hash(0x00, b'', input_data)
    c = bytes_to_little_int(c_bytes[:byte_len]) % N
    
    sGx, sGy = ed521_scalar_base_mult(little_int_to_bytes(s, byte_len))
    cAx, cAy = ed521_scalar_mult(pub_x, pub_y, little_int_to_bytes(c, byte_len))
    RpluscAx, RpluscAy = ed521_add_points(Rx, Ry, cAx, cAy)
    
    return sGx == RpluscAx and sGy == RpluscAy

# =========================
# CURUPIRA BLOCK CIPHER FOR CBC MODE
# =========================

class KeySizeError(Exception):
    def __init__(self, size: int):
        self.size = size
        super().__init__(f"curupira1: invalid key size {size}")

class Curupira1:
    BLOCK_SIZE = 12
    
    def __init__(self, key: bytes):
        self.key = key
        self.key_size = len(key)
        
        if self.key_size not in [12, 18, 24]:
            raise KeySizeError(self.key_size)
        
        self._init_xtimes_table()
        self._init_sbox_table()
        self._expand_key()
    
    def _init_xtimes_table(self):
        """Initialize xTimes table (multiplication by 2 in GF(2^8))"""
        self.xtimes_table = [0] * 256
        for u in range(256):
            d = u << 1
            if d >= 0x100:
                d = d ^ 0x14D
            self.xtimes_table[u] = d & 0xFF
    
    def _init_sbox_table(self):
        """Initialize S-Box table according to Curupira algorithm"""
        P = [0x3, 0xF, 0xE, 0x0, 0x5, 0x4, 0xB, 0xC,
             0xD, 0xA, 0x9, 0x6, 0x7, 0x8, 0x2, 0x1]
        Q = [0x9, 0xE, 0x5, 0x6, 0xA, 0x2, 0x3, 0xC,
             0xF, 0x0, 0x4, 0xD, 0x7, 0xB, 0x1, 0x8]
        
        self.sbox_table = [0] * 256
        
        for u in range(256):
            uh1 = P[(u >> 4) & 0xF]
            ul1 = Q[u & 0xF]
            uh2 = Q[((uh1 & 0xC) ^ ((ul1 >> 2) & 0x3)) & 0xF]
            ul2 = P[(((uh1 << 2) & 0xC) ^ (ul1 & 0x3)) & 0xF]
            uh1 = P[((uh2 & 0xC) ^ ((ul2 >> 2) & 0x3)) & 0xF]
            ul1 = Q[(((uh2 << 2) & 0xC) ^ (ul2 & 0x3)) & 0xF]
            
            self.sbox_table[u] = ((uh1 << 4) ^ ul1) & 0xFF
    
    def xtimes(self, u: int) -> int:
        """Multiplication by 2 in GF(2^8)"""
        return self.xtimes_table[u & 0xFF]
    
    def ctimes(self, u: int) -> int:
        """cTimes transformation as per specification"""
        return self.xtimes(
            self.xtimes(
                self.xtimes(
                    self.xtimes(u) ^ u
                ) ^ u
            )
        )
    
    def sbox(self, u: int) -> int:
        """Apply S-Box"""
        return self.sbox_table[u & 0xFF]
    
    def _dtimesa(self, a: list, j: int, b: list):
        """dTimes transformation for linear diffusion layer"""
        d = 3 * j
        v = self.xtimes(a[0 + d] ^ a[1 + d] ^ a[2 + d])
        w = self.xtimes(v)
        
        b[0 + d] = a[0 + d] ^ v
        b[1 + d] = a[1 + d] ^ w
        b[2 + d] = a[2 + d] ^ v ^ w
    
    def _etimesa(self, a: list, j: int, b: list, e: bool):
        """eTimes transformation for key expansion"""
        d = 3 * j
        v = a[0 + d] ^ a[1 + d] ^ a[2 + d]
        
        if e:
            v = self.ctimes(v)
        else:
            v = self.ctimes(v) ^ v
        
        b[0 + d] = a[0 + d] ^ v
        b[1 + d] = a[1 + d] ^ v
        b[2 + d] = a[2 + d] ^ v
    
    def _apply_nonlinear_layer(self, a: list) -> list:
        """Apply nonlinear layer (S-Box)"""
        return [self.sbox(x) for x in a]
    
    def _apply_permutation_layer(self, a: list) -> list:
        """Apply permutation layer"""
        b = [0] * 12
        
        for i in range(3):
            for j in range(4):
                b[i + 3 * j] = a[i + 3 * (i ^ j)]
        
        return b
    
    def _apply_linear_diffusion_layer(self, a: list) -> list:
        """Apply linear diffusion layer"""
        b = [0] * 12
        
        for j in range(4):
            self._dtimesa(a, j, b)
        
        return b
    
    def _apply_key_addition(self, a: list, kr: list) -> list:
        """Key addition (XOR)"""
        return [a[i] ^ kr[i] for i in range(12)]
    
    def _calculate_schedule_constant(self, s: int, key_bits: int) -> list:
        """Calculate constant for key expansion"""
        t = key_bits // 48
        q = [0] * (3 * 2 * t)
        
        if s == 0:
            return q
        
        for j in range(2 * t):
            q[3 * j] = self.sbox(2 * t * (s - 1) + j)
        
        return q
    
    def _apply_constant_addition(self, Kr: list, subkey_rank: int, 
                                 key_bits: int, t: int) -> list:
        """Constant addition in key expansion"""
        b = Kr.copy()
        q = self._calculate_schedule_constant(subkey_rank, key_bits)
        
        for i in range(3):
            for j in range(2 * t):
                idx = i + 3 * j
                b[idx] ^= q[idx]
        
        return b
    
    def _apply_cyclic_shift(self, a: list, t: int) -> list:
        """Apply cyclic shift in key expansion"""
        length = 3 * 2 * t
        b = [0] * length
        
        for j in range(2 * t):
            b[3 * j] = a[3 * j]
            b[1 + 3 * j] = a[1 + 3 * ((j + 1) % (2 * t))]
            
            if j > 0:
                b[2 + 3 * j] = a[2 + 3 * ((j - 1) % (2 * t))]
            else:
                b[2] = a[2 + 3 * (2 * t - 1)]
        
        return b
    
    def _apply_linear_diffusion(self, a: list, t: int) -> list:
        """Apply linear diffusion in key expansion"""
        length = 3 * 2 * t
        b = [0] * length
        
        for j in range(2 * t):
            self._etimesa(a, j, b, True)
        
        return b
    
    def _calculate_next_subkey(self, Kr: list, subkey_rank: int,
                              key_bits: int, t: int) -> list:
        """Calculate next subkey"""
        return self._apply_linear_diffusion(
            self._apply_cyclic_shift(
                self._apply_constant_addition(Kr, subkey_rank, key_bits, t),
                t
            ),
            t
        )
    
    def _select_round_key(self, Kr: list) -> list:
        """Select round key"""
        kr = [0] * 12
        
        for j in range(4):
            kr[3 * j] = self.sbox(Kr[3 * j])
        
        for i in range(1, 3):
            for j in range(4):
                kr[i + 3 * j] = Kr[i + 3 * j]
        
        return kr
    
    def _expand_key(self):
        """Expand key and generate encryption and decryption subkeys"""
        key_bits = self.key_size * 8
        
        if key_bits == 96:
            self.R = 10
        elif key_bits == 144:
            self.R = 14
        elif key_bits == 192:
            self.R = 18
        
        self.key_bits = key_bits
        self.t = key_bits // 48
        
        Kr = list(self.key)
        
        self.encryption_round_keys = [None] * (self.R + 1)
        self.decryption_round_keys = [None] * (self.R + 1)
        
        kr = self._select_round_key(Kr)
        self.encryption_round_keys[0] = kr
        
        for r in range(1, self.R + 1):
            Kr = self._calculate_next_subkey(Kr, r, self.key_bits, self.t)
            kr = self._select_round_key(Kr)
            
            self.encryption_round_keys[r] = kr
            self.decryption_round_keys[self.R - r] = self._apply_linear_diffusion_layer(kr)
        
        self.decryption_round_keys[0] = self.encryption_round_keys[self.R]
        self.decryption_round_keys[self.R] = self.encryption_round_keys[0]
    
    def _perform_whitening_round(self, a: list, k0: list) -> list:
        """Whitening round (only key addition)"""
        return self._apply_key_addition(a, k0)
    
    def _perform_last_round(self, a: list, kR: list) -> list:
        """Last round (without linear diffusion)"""
        return self._apply_key_addition(
            self._apply_permutation_layer(
                self._apply_nonlinear_layer(a)
            ),
            kR
        )
    
    def _perform_round(self, a: list, kr: list) -> list:
        """Normal round"""
        return self._apply_key_addition(
            self._apply_linear_diffusion_layer(
                self._apply_permutation_layer(
                    self._apply_nonlinear_layer(a)
                )
            ),
            kr
        )
    
    def _process_block(self, data: bytes, round_keys: list) -> bytes:
        """Process a block of data"""
        tmp = list(data)
        tmp = self._perform_whitening_round(tmp, round_keys[0])
        
        for r in range(1, self.R):
            tmp = self._perform_round(tmp, round_keys[r])
        
        tmp = self._perform_last_round(tmp, round_keys[self.R])
        return bytes(tmp)
    
    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt a block of 12 bytes"""
        if len(plaintext) != self.BLOCK_SIZE:
            raise ValueError(f"Plaintext must be {self.BLOCK_SIZE} bytes")
        return self._process_block(plaintext, self.encryption_round_keys)
    
    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt a block of 12 bytes"""
        if len(ciphertext) != self.BLOCK_SIZE:
            raise ValueError(f"Ciphertext must be {self.BLOCK_SIZE} bytes")
        return self._process_block(ciphertext, self.decryption_round_keys)
    
    def sct(self, data: bytes) -> bytes:
        """Square-Complete Transform (4 rounds without key)"""
        if len(data) != self.BLOCK_SIZE:
            raise ValueError(f"Data must be {self.BLOCK_SIZE} bytes")
        
        tmp = list(data)
        
        def _unkeyed_round(a: list) -> list:
            return self._apply_linear_diffusion_layer(
                self._apply_permutation_layer(
                    self._apply_nonlinear_layer(a)
                )
            )
        
        tmp = _unkeyed_round(tmp)
        for _ in range(3):
            tmp = _unkeyed_round(tmp)
        
        return bytes(tmp)

# =========================
# RFC 1423 IMPLEMENTATION FOR CURUPIRA-192-CBC
# =========================

def rfc1423_derive_key_md5(password: bytes, salt: bytes, key_size: int) -> bytes:
    """
    Derive key according to RFC 1423 section 1.1 (PBKDF1-like)
    Uses MD5 iteratively: D_i = MD5(D_{i-1} || P || S)
    """
    # Use first 8 bytes of salt for key derivation (as per RFC 1423)
    iv_salt = salt[:8]
    
    # RFC 1423 uses MD5 iteratively
    d = b''
    result = b''
    
    while len(result) < key_size:
        md5_hash = hashlib.md5()
        md5_hash.update(d)
        md5_hash.update(password)
        md5_hash.update(iv_salt)
        d = md5_hash.digest()
        result += d
    
    return result[:key_size]

def pad_pkcs7(data: bytes, block_size: int) -> bytes:
    """PKCS#7 padding"""
    padding_len = block_size - (len(data) % block_size)
    if padding_len == 0:
        padding_len = block_size
    return data + bytes([padding_len] * padding_len)

def unpad_pkcs7(data: bytes) -> bytes:
    """Remove PKCS#7 padding"""
    if len(data) == 0:
        raise ValueError("Empty data")
    
    padding_len = data[-1]
    if padding_len > len(data):
        raise ValueError("Invalid padding length")
    
    # Verify padding bytes
    for i in range(padding_len):
        if data[-i-1] != padding_len:
            raise ValueError("Invalid padding bytes")
    
    return data[:-padding_len]

def cbc_encrypt_curupira(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """Encrypt using Curupira in CBC mode"""
    cipher = Curupira1(key)
    block_size = cipher.BLOCK_SIZE
    
    # Pad plaintext
    padded_data = pad_pkcs7(plaintext, block_size)
    
    # CBC encryption
    ciphertext = b''
    prev_block = iv
    
    for i in range(0, len(padded_data), block_size):
        block = padded_data[i:i+block_size]
        # XOR with previous ciphertext (or IV for first block)
        xored_block = bytes(a ^ b for a, b in zip(block, prev_block))
        # Encrypt with Curupira
        encrypted_block = cipher.encrypt(xored_block)
        ciphertext += encrypted_block
        prev_block = encrypted_block
    
    return ciphertext

def cbc_decrypt_curupira(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """Decrypt using Curupira in CBC mode"""
    cipher = Curupira1(key)
    block_size = cipher.BLOCK_SIZE
    
    if len(ciphertext) % block_size != 0:
        raise ValueError("Ciphertext length must be multiple of block size")
    
    # CBC decryption
    plaintext = b''
    prev_block = iv
    
    for i in range(0, len(ciphertext), block_size):
        encrypted_block = ciphertext[i:i+block_size]
        # Decrypt with Curupira
        decrypted_block = cipher.decrypt(encrypted_block)
        # XOR with previous ciphertext (or IV for first block)
        plain_block = bytes(a ^ b for a, b in zip(decrypted_block, prev_block))
        plaintext += plain_block
        prev_block = encrypted_block
    
    # Remove padding
    return unpad_pkcs7(plaintext)

def encrypt_private_key_pem(data: bytes, password: str, cipher_name: str = "CURUPIRA-192-CBC") -> str:
    """
    Encrypt private key data using RFC 1423 format with specified cipher
    Returns PEM formatted encrypted data
    """
    if cipher_name != "CURUPIRA-192-CBC":
        raise ValueError(f"Unsupported cipher: {cipher_name}")
    
    # Generate random IV (12 bytes for Curupira)
    iv = os.urandom(12)
    
    # Derive key using RFC 1423 method (192-bit = 24 bytes)
    key = rfc1423_derive_key_md5(password.encode('utf-8'), iv, 24)
    
    # Encrypt data
    encrypted_data = cbc_encrypt_curupira(key, iv, data)
    
    # Combine IV and encrypted data
    full_data = encrypted_data
    
    # Encode as base64
    b64_data = base64.b64encode(full_data).decode('ascii')
    
    # Format as PEM with RFC 1423 headers
    lines = []
    lines.append("Proc-Type: 4,ENCRYPTED")
    lines.append(f"DEK-Info: {cipher_name},{iv.hex()}")
    lines.append("")
    
    # Split base64 into 64-character lines
    for i in range(0, len(b64_data), 64):
        lines.append(b64_data[i:i+64])
    
    return "\n".join(lines)

def decrypt_private_key_pem(pem_data: str, password: str) -> bytes:
    """
    Decrypt RFC 1423 formatted private key data
    """
    lines = pem_data.strip().split('\n')
    
    # Parse headers
    proc_type = None
    dek_info = None
    b64_lines = []
    
    in_headers = True
    for line in lines:
        line = line.strip()
        if not line:
            if in_headers:
                in_headers = False
            continue
            
        if line.startswith("-----"):
            continue
        
        if in_headers:
            if line.startswith("Proc-Type:"):
                proc_type = line.split(":", 1)[1].strip()
                if proc_type != "4,ENCRYPTED":
                    raise ValueError("Not an encrypted PEM block")
            elif line.startswith("DEK-Info:"):
                dek_info = line.split(":", 1)[1].strip()
            else:
                # Headers continue
                pass
        else:
            b64_lines.append(line)
    
    if not dek_info:
        raise ValueError("Missing DEK-Info header")
    
    # Parse DEK-Info
    dek_parts = dek_info.split(",", 1)
    if len(dek_parts) != 2:
        raise ValueError(f"Invalid DEK-Info format: {dek_info}")
    
    cipher_name, iv_hex = dek_parts
    cipher_name = cipher_name.strip()
    iv_hex = iv_hex.strip()
    
    if cipher_name != "CURUPIRA-192-CBC":
        raise ValueError(f"Unsupported cipher: {cipher_name}")
    
    try:
        iv = bytes.fromhex(iv_hex)
        if len(iv) != 12:
            raise ValueError(f"Invalid IV length: {len(iv)} bytes, expected 12")
    except ValueError as e:
        raise ValueError(f"Invalid IV hex: {e}")
    
    # Decode base64 data
    b64_data = ''.join(b64_lines)
    encrypted_data = base64.b64decode(b64_data)
    
    # Note: IV is included in the encrypted data, but we already have it from header
    ciphertext = encrypted_data  # Skip the IV that's also in the data
    
    # Derive key
    key = rfc1423_derive_key_md5(password.encode('utf-8'), iv, 24)
    
    try:
        # Decrypt data
        decrypted_data = cbc_decrypt_curupira(key, iv, ciphertext)
    except ValueError as e:
        raise ValueError(f"Decryption failed (wrong password?): {e}")
    
    return decrypted_data

# =========================
# PEM PKCS8 FUNCTIONS WITH ENCRYPTION SUPPORT
# =========================

def ed521_private_to_pem_pkcs8(private_key_int, password=None):
    """Convert Ed521 private key to PEM PKCS8 with optional encryption"""
    private_bytes = little_int_to_bytes(private_key_int, 66)

    # ED521 OID: 1.3.6.1.4.1.44588.2.1
    # Codificado corretamente para corresponder ao Go
    encoded_oid = bytes([
        0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xdc, 0x2c, 0x02, 0x01
    ])
    
    # AlgorithmIdentifier: SEQUENCE { OID, NULL }
    oid_der = b'\x06\x0a' + encoded_oid  # OID tag + length + value
    algorithm_id = b'\x30\x0e' + oid_der + b'\x05\x00'  # SEQUENCE (14 bytes)

    version = b'\x02\x01\x00'  # INTEGER version = 0

    # CORREÇÃO: Private key as OCTET STRING (tag 0x04) não 0x84
    # 66 bytes + tag (1) + length (1) = 68 bytes
    # 66 bytes = 0x42 em hexadecimal
    priv_field = b'\x04\x42' + private_bytes  # OCTET STRING tag (0x04), length 66 (0x42)

    content = version + algorithm_id + priv_field
    content_length = len(content)
    
    # CORREÇÃO: Usar comprimento correto para SEQUENCE
    if content_length <= 127:
        seq = b'\x30' + bytes([content_length]) + content
    else:
        # Comprimento longo (2 bytes) - 0x81 indica 1 byte de comprimento
        # Mas como content_length é 84, podemos usar forma curta
        seq = b'\x30\x81' + bytes([content_length]) + content
    
    if password:
        # Encrypt using RFC 1423 with Curupira-192-CBC
        encrypted_pem = encrypt_private_key_pem(seq, password, "CURUPIRA-192-CBC")
        return "-----BEGIN E-521 PRIVATE KEY-----\n" + encrypted_pem + "\n-----END E-521 PRIVATE KEY-----\n"
    else:
        b64 = base64.b64encode(seq).decode()
        lines = [b64[i:i+64] for i in range(0, len(b64), 64)]
        return "-----BEGIN E-521 PRIVATE KEY-----\n" + "\n".join(lines) + "\n-----END E-521 PRIVATE KEY-----\n"

def ed521_public_to_pem(public_key_x, public_key_y):
    """
    Convert Ed521 public key to EXACT edgetk-compatible format
    """
    encoded_oid = bytes([
        0x2b, 0x6, 0x1, 0x4, 0x1, 0x82, 0xdc, 0x2c, 0x2, 0x1
    ])
    oid_der = b'\x06\x0a' + encoded_oid
    algorithm_id = b'\x30\x0e' + oid_der + b'\x05\x00'

    compressed_pub = ed521_compress_point(public_key_x, public_key_y)
    
    bit_string_data = b'\x00' + compressed_pub
    bit_string_len = len(bit_string_data)
    
    if bit_string_len < 128:
        bit_string_header = b'\x03' + bytes([bit_string_len])
    else:
        len_bytes = bit_string_len.to_bytes((bit_string_len.bit_length() + 7) // 8, 'big')
        bit_string_header = b'\x03' + bytes([0x80 | len(len_bytes)]) + len_bytes
    
    bit_string = bit_string_header + bit_string_data
    
    content = algorithm_id + bit_string
    content_len = len(content)
    
    if content_len < 128:
        seq_len = bytes([content_len])
    else:
        len_bytes = content_len.to_bytes((content_len.bit_length() + 7) // 8, 'big')
        seq_len = bytes([0x80 | len(len_bytes)]) + len_bytes
    
    subject_pub_key_info = b'\x30' + seq_len + content
    
    b64_key = base64.b64encode(subject_pub_key_info).decode('ascii')
    lines = [b64_key[i:i+64] for i in range(0, len(b64_key), 64)]
    
    return (
        "-----BEGIN E-521 PUBLIC KEY-----\n" +
        "\n".join(lines) +
        "\n-----END E-521 PUBLIC KEY-----\n"
    )

# =========================
# PEM READING FUNCTIONS WITH ENCRYPTION SUPPORT
# =========================

def parse_ed521_pem_private_key(pem_data, debug=False):
    """Parse Ed521 private key from PEM PKCS8 format (compatible with edgetk Go implementation)"""
    lines = pem_data.strip().split('\n')
    
    # Check if encrypted
    is_encrypted = False
    for line in lines:
        if line.startswith("Proc-Type:") and "ENCRYPTED" in line:
            is_encrypted = True
            break
    
    if is_encrypted:
        password = getpass.getpass("Enter password to decrypt private key: ")
        try:
            der_data = decrypt_private_key_pem(pem_data, password)
        except ValueError as e:
            print(f"✖ Decryption failed: {e}")
            sys.exit(1)
    else:
        b64_data = ''.join([line.strip() for line in lines if line and not line.startswith('-----')])
        der_data = base64.b64decode(b64_data)
    
    if debug:
        print(f"DEBUG: DER data length: {len(der_data)} bytes")
        print(f"DEBUG: DER hex: {der_data.hex()}")
    
    try:
        idx = 0
        
        # SEQUENCE
        if der_data[idx] != 0x30:
            raise ValueError("Expected SEQUENCE (0x30)")
        idx += 1
        
        # Length
        seq_len = der_data[idx]
        idx += 1
        if seq_len & 0x80:  # Long form
            num_bytes = seq_len & 0x7F
            seq_len = int.from_bytes(der_data[idx:idx+num_bytes], 'big')
            idx += num_bytes
        
        # Version (INTEGER 0)
        if der_data[idx] != 0x02:
            raise ValueError(f"Expected INTEGER (0x02), got 0x{der_data[idx]:02x}")
        idx += 1
        
        ver_len = der_data[idx]
        idx += 1
        version = int.from_bytes(der_data[idx:idx+ver_len], 'big')
        if version != 0:
            raise ValueError(f"Expected version 0, got {version}")
        idx += ver_len
        
        # AlgorithmIdentifier (SEQUENCE)
        if der_data[idx] != 0x30:
            raise ValueError(f"Expected AlgorithmIdentifier SEQUENCE (0x30), got 0x{der_data[idx]:02x}")
        idx += 1
        
        algo_len = der_data[idx]
        idx += 1
        if algo_len & 0x80:  # Long form
            num_bytes = algo_len & 0x7F
            algo_len = int.from_bytes(der_data[idx:idx+num_bytes], 'big')
            idx += num_bytes
        
        # Skip AlgorithmIdentifier content
        idx += algo_len
        
        # PrivateKey (OCTET STRING)
        if der_data[idx] != 0x04:
            # Tentar formato antigo (tag 0x84) para compatibilidade
            if der_data[idx] == 0x84:
                idx += 1
                priv_len = der_data[idx]
                idx += 1
                private_key_bytes = der_data[idx:idx+priv_len]
                return bytes_to_little_int(private_key_bytes)
            raise ValueError(f"Expected OCTET STRING (0x04), got 0x{der_data[idx]:02x}")
        
        idx += 1
        priv_len = der_data[idx]
        idx += 1
        
        # Handle long length
        if priv_len == 0x81:
            priv_len = der_data[idx]
            idx += 1
        elif priv_len == 0x82:
            priv_len = (der_data[idx] << 8) | der_data[idx+1]
            idx += 2
        
        private_key_bytes = der_data[idx:idx+priv_len]
        
        if debug:
            print(f"DEBUG: Private key bytes length: {len(private_key_bytes)} bytes")
            print(f"DEBUG: Private key hex: {private_key_bytes.hex()}")
        
        # Convert to integer (little-endian)
        return bytes_to_little_int(private_key_bytes)
        
    except Exception as e:
        if debug:
            print(f"DEBUG: ASN.1 parsing failed: {e}")
        
        # Fallback: procurar por 66 bytes no DER
        if len(der_data) == 66:
            key_int = bytes_to_little_int(der_data)
            if 0 < key_int < N:
                if debug:
                    print("DEBUG: Whole data is a valid 66-byte key")
                return key_int
        
        for i in range(len(der_data) - 66 + 1):
            chunk = der_data[i:i+66]
            key_int = bytes_to_little_int(chunk)
            if 0 < key_int < N:
                if debug:
                    print(f"DEBUG: Found 66-byte key at offset {i}")
                return key_int
        
        raise ValueError(f"Cannot parse Ed521 private key: {e}")

def parse_ed521_pem_public_key(pem_data, debug=False):
    """Parse Ed521 public key from PEM SPKI format (compatible with edgetk Go implementation)"""
    lines = pem_data.strip().split('\n')
    b64_data = ''.join([line.strip() for line in lines if line and not line.startswith('-----')])
    
    der_data = base64.b64decode(b64_data)
    
    if debug:
        print(f"DEBUG: Public key DER length: {len(der_data)} bytes")
        print(f"DEBUG: Public key DER hex: {der_data.hex()}")
    
    try:
        idx = 0
        
        if der_data[idx] != 0x30:
            raise ValueError("Expected SEQUENCE (0x30)")
        idx += 1
        
        if idx >= len(der_data):
            raise ValueError("Unexpected end of data")
        
        seq_len = der_data[idx]
        idx += 1
        
        if seq_len & 0x80:
            num_bytes = seq_len & 0x7F
            if idx + num_bytes > len(der_data):
                raise ValueError("Incomplete SEQUENCE length")
            seq_len = int.from_bytes(der_data[idx:idx+num_bytes], 'big')
            idx += num_bytes
        
        if der_data[idx] != 0x30:
            raise ValueError("Expected AlgorithmIdentifier SEQUENCE (0x30)")
        idx += 1
        
        if idx >= len(der_data):
            raise ValueError("Unexpected end of data")
        
        algo_len = der_data[idx]
        idx += 1
        
        if algo_len & 0x80:
            num_bytes = algo_len & 0x7F
            if idx + num_bytes > len(der_data):
                raise ValueError("Incomplete AlgorithmIdentifier length")
            algo_len = int.from_bytes(der_data[idx:idx+num_bytes], 'big')
            idx += num_bytes
        
        algo_end = idx + algo_len
        
        if der_data[idx] != 0x06:
            raise ValueError("Expected OID (0x06)")
        idx += 1
        
        if idx >= len(der_data):
            raise ValueError("Unexpected end of data")
        
        oid_len = der_data[idx]
        idx += 1
        
        if oid_len & 0x80:
            raise ValueError("Unexpected long form for OID length")
        
        if idx + oid_len > len(der_data):
            raise ValueError("Incomplete OID")
        
        oid_bytes = der_data[idx:idx+oid_len]
        idx += oid_len
        
        if idx < algo_end and der_data[idx] == 0x05:
            idx += 1
            if idx >= len(der_data):
                raise ValueError("Unexpected end of data")
            null_len = der_data[idx]
            idx += 1
            if null_len != 0:
                raise ValueError(f"Expected NULL (0x00), got length {null_len}")
        
        idx = algo_end
        
        if der_data[idx] != 0x03:
            raise ValueError(f"Expected BIT STRING (0x03), got 0x{der_data[idx]:02x}")
        idx += 1
        
        if idx >= len(der_data):
            raise ValueError("Unexpected end of data")
        
        bitstring_len = der_data[idx]
        idx += 1
        
        if bitstring_len & 0x80:
            num_bytes = bitstring_len & 0x7F
            if idx + num_bytes > len(der_data):
                raise ValueError("Incomplete BIT STRING length")
            bitstring_len = int.from_bytes(der_data[idx:idx+num_bytes], 'big')
            idx += num_bytes
        
        if idx >= len(der_data):
            raise ValueError("Unexpected end of data")
        
        unused_bits = der_data[idx]
        idx += 1
        
        if unused_bits != 0:
            if debug:
                print(f"DEBUG: Warning: BIT STRING has {unused_bits} unused bits")
        
        compressed_pub = der_data[idx:idx + bitstring_len - 1]
        
        if debug:
            print(f"DEBUG: Compressed public key length: {len(compressed_pub)} bytes")
            print(f"DEBUG: Compressed public key hex: {compressed_pub.hex()}")
        
        pub_x, pub_y = ed521_decompress_point(compressed_pub)
        
        if pub_x is None or pub_y is None:
            raise ValueError("Failed to decompress public key")
        
        return pub_x, pub_y
        
    except Exception as e:
        if debug:
            print(f"DEBUG: ASN.1 parsing failed: {e}")
        
        if len(der_data) == ED521_BYTE_LEN:
            pub_x, pub_y = ed521_decompress_point(der_data)
            if pub_x is not None and pub_y is not None:
                if debug:
                    print("DEBUG: Found raw 66-byte compressed public key")
                return pub_x, pub_y
        
        for i in range(len(der_data) - ED521_BYTE_LEN + 1):
            chunk = der_data[i:i+ED521_BYTE_LEN]
            pub_x, pub_y = ed521_decompress_point(chunk)
            if pub_x is not None and pub_y is not None:
                if debug:
                    print(f"DEBUG: Found compressed public key at offset {i}")
                return pub_x, pub_y
        
        raise ValueError(f"Cannot parse Ed521 public key: {e}")

# =========================
# ED521 COMMANDS
# =========================

def ed521_generate(priv_path, pub_path, password=None):
    """Generate Ed521 keys and save in PEM PKCS8 format with optional encryption"""
    print("Generating Ed521 keys (521-bit curve)...")
    
    private_key = ed521_generate_private_key()
    print(f"Private key generated: {hex(private_key)[:34]}...")
    
    pub_x, pub_y = ed521_get_public_key(private_key)
    print(f"Public key generated: ({hex(pub_x)[:20]}..., {hex(pub_y)[:20]}...)")
    
    if not ed521_is_on_curve(pub_x, pub_y):
        print("✖ Generated public key is not on the curve!", file=sys.stderr)
        sys.exit(1)
    
    private_pem = ed521_private_to_pem_pkcs8(private_key, password)
    public_pem = ed521_public_to_pem(pub_x, pub_y)
    
    with open(priv_path, "w") as f:
        f.write(private_pem)
    print(f"✔ Private key saved in {priv_path} (PEM PKCS8{' - ENCRYPTED' if password else ''})")
    
    with open(pub_path, "w") as f:
        f.write(public_pem)
    print(f"✔ Public key saved in {pub_path} (PEM)")
    
    return private_key, pub_x, pub_y

def ed521_sign_file(priv_path, msg_path):
    """Sign a file with Ed521"""
    try:
        with open(priv_path, "r") as f:
            pem_data = f.read()
        
        private_key = parse_ed521_pem_private_key(pem_data)
        
        with open(msg_path, "rb") as f:
            message = f.read()
        
        signature = ed521_sign(private_key, message)
        
        print(f"{signature.hex()}")
        
        return signature
        
    except Exception as e:
        print(f"✖ Error signing with Ed521: {e}", file=sys.stderr)
        sys.exit(1)

def ed521_verify_file(pub_path, msg_path, sig_hex):
    """Verify Ed521 signature for a file"""
    try:
        with open(pub_path, "r") as f:
            pem_data = f.read()
        
        pub_x, pub_y = parse_ed521_pem_public_key(pem_data)
        
        with open(msg_path, "rb") as f:
            message = f.read()
        
        signature = bytes.fromhex(sig_hex)
        
        if ed521_verify(pub_x, pub_y, message, signature):
            print(f"✔ Valid Ed521 signature for file: {msg_path}")
            return True
        else:
            print(f"✖ Invalid Ed521 signature for file: {msg_path}")
            return False
            
    except Exception as e:
        print(f"✖ Error verifying Ed521 signature: {e}", file=sys.stderr)
        sys.exit(1)

def ed521_prove_command(priv_path: str):
    """Generate ZKP proof of private key knowledge"""
    with open(priv_path, "r") as f:
        pem_data = f.read()
    
    try:
        private_key = parse_ed521_pem_private_key(pem_data)
    except Exception as e:
        print(f"✖ Error parsing private key: {e}")
        sys.exit(1)
    
    proof = ed521_prove_knowledge(private_key)
    proof_hex = proof.hex()
    
    print(f"✔ Zero-knowledge proof generated")
    print(f"\nProof (hex): {proof_hex}")
    print(f"Proof length: {len(proof)} bytes ({(len(proof) * 8)} bits)")
    
    save = input("\nSave proof to file? (y/N): ").strip().lower()
    if save == 'y':
        filename = input("Filename [ed521_proof.hex]: ").strip() or "ed521_proof.hex"
        try:
            with open(filename, "w") as f:
                f.write(proof_hex)
            print(f"✔ Proof saved to {filename}")
        except Exception as e:
            print(f"✖ Error saving proof: {e}")
    
    return proof_hex

def ed521_verify_proof_command(pub_path: str, proof_hex: Optional[str] = None, proof_file: Optional[str] = None):
    """Verify ZKP proof for E-521 public key"""
    with open(pub_path, "r") as f:
        pem_data = f.read()
    
    try:
        pub_x, pub_y = parse_ed521_pem_public_key(pem_data)
    except Exception as e:
        print(f"✖ Error parsing public key: {e}")
        sys.exit(1)
    
    if proof_file:
        with open(proof_file, "r") as f:
            proof_hex = f.read().strip()
    
    if not proof_hex:
        print("Enter the proof (hex):")
        try:
            lines = []
            while True:
                line = sys.stdin.readline()
                if not line or line.strip() == "":
                    break
                lines.append(line.strip())
            proof_hex = "".join(lines)
        except KeyboardInterrupt:
            print("\n✖ Input cancelled")
            sys.exit(1)
    
    try:
        proof = bytes.fromhex(proof_hex)
    except binascii.Error as e:
        print(f"✖ Invalid hex: {e}")
        sys.exit(1)
    
    if ed521_verify_knowledge(pub_x, pub_y, proof):
        print("\n✔ Zero-knowledge proof valid")
        print("  The key holder proves knowledge of the private key")
        return True
    else:
        print("\n✖ Zero-knowledge proof invalid")
        print("  The key holder does NOT prove knowledge of the private key")
        return False

def ed521_test_command():
    """Run complete E-521 implementation test"""
    print("=== E-521 EdDSA Test Suite ===")
    print()
    
    print("1. Key generation test:")
    priv_key = ed521_generate_private_key()
    pub_x, pub_y = ed521_get_public_key(priv_key)
    print(f"   Private key (first 16 bytes): {hex(priv_key)[:34]}...")
    print(f"   Public key on curve: {ed521_is_on_curve(pub_x, pub_y)}")
    
    print("\n2. Point compression test:")
    compressed = ed521_compress_point(pub_x, pub_y)
    decomp_x, decomp_y = ed521_decompress_point(compressed)
    print(f"   Compression successful: {len(compressed)} bytes")
    print(f"   Decompression correct: {decomp_x == pub_x and decomp_y == pub_y}")
    
    print("\n3. Signature test:")
    message = b"Test message for E-521 EdDSA"
    signature = ed521_sign(priv_key, message)
    valid = ed521_verify(pub_x, pub_y, message, signature)
    print(f"   Signature created: {len(signature)} bytes")
    print(f"   Signature valid: {valid}")
    
    wrong_message = b"Wrong message"
    wrong_valid = ed521_verify(pub_x, pub_y, wrong_message, signature)
    print(f"   Wrong message rejected: {not wrong_valid}")
    
    print("\n4. Zero-knowledge proof test:")
    proof = ed521_prove_knowledge(priv_key)
    proof_valid = ed521_verify_knowledge(pub_x, pub_y, proof)
    print(f"   Proof generated: {len(proof)} bytes")
    print(f"   Proof valid: {proof_valid}")
    
    print("\n5. PKCS#8 serialization test:")
    public_pem = ed521_public_to_pem(pub_x, pub_y)
    private_pem = ed521_private_to_pem_pkcs8(priv_key)
    
    parsed_pub_x, parsed_pub_y = parse_ed521_pem_public_key(public_pem)
    parsed_priv = parse_ed521_pem_private_key(private_pem)
    
    print(f"   Public key serialization correct: {parsed_pub_x == pub_x and parsed_pub_y == pub_y}")
    print(f"   Private key serialization correct: {parsed_priv == priv_key}")
    
    print("\n6. Encryption test:")
    password = "testpassword"
    encrypted_pem = ed521_private_to_pem_pkcs8(priv_key, password)
    print(f"   Encryption successful: {'ENCRYPTED' in encrypted_pem}")
    
    print("\n=== All tests passed! ===")

def ed521_parse_key(key_file: str, debug: bool = False):
    """
    Parse Ed521 key file and display raw key information.
    """
    try:
        with open(key_file, 'r') as f:
            pem_data = f.read()
    except FileNotFoundError:
        print(f"✖ File not found: {key_file}")
        return None, None
    
    lines = pem_data.strip().split('\n')
    
    # Check if encrypted
    is_encrypted = False
    for line in lines:
        if line.startswith("Proc-Type:") and "ENCRYPTED" in line:
            is_encrypted = True
            break
    
    # Parse private key
    if "PRIVATE KEY" in pem_data or ("E-521" in pem_data and "PRIVATE" in pem_data):
        if is_encrypted:
            # Se estiver encriptada, pedir senha e descriptografar
            password = getpass.getpass("Enter password to decrypt private key: ")
            try:
                der_data = decrypt_private_key_pem(pem_data, password)
                print("✓ Key decrypted successfully")
                
                # Converter DER descriptografado de volta para PEM
                b64_der = base64.b64encode(der_data).decode('ascii')
                pem_lines = [b64_der[i:i+64] for i in range(0, len(b64_der), 64)]
                
                # Exibir PEM descriptografado
                print("-----BEGIN E-521 PRIVATE KEY-----")
                for line in pem_lines:
                    print(line)
                print("-----END E-521 PRIVATE KEY-----")
                
                # Agora parsear o DER descriptografado diretamente
                # (não chamar parse_ed521_pem_private_key pois ela pediria senha novamente)
                private_key = parse_ed521_private_key_from_der(der_data, debug)
                
            except Exception as e:
                print(f"✖ Decryption failed: {e}")
                return None, None
        else:
            # Se não estiver encriptada, exibir o PEM original
            print(pem_data.strip())
            
            # Parsear a chave normalmente
            try:
                private_key = parse_ed521_pem_private_key(pem_data, debug)
            except Exception as e:
                print(f"✖ Failed to parse private key: {e}")
                return None, None
        
        # Extrair bytes da chave para exibição
        if is_encrypted:
            # Para chaves encriptadas, usar bytes da chave já extraída
            key_bytes = little_int_to_bytes(private_key, 66)
        else:
            # Para chaves não-encriptadas, tentar extrair do DER
            b64_data = ''.join([line.strip() for line in lines if line and not line.startswith('-----')])
            try:
                der_data = base64.b64decode(b64_data)
                
                # Procurar pelos 66 bytes da chave no DER
                key_bytes = None
                for i in range(len(der_data) - 67):
                    if der_data[i] == 0x04 and der_data[i+1] == 0x42:
                        key_bytes = der_data[i+2:i+2+66]
                        if debug:
                            print(f"DEBUG: Found key at offset {i}: {key_bytes.hex()}")
                        break
                
                if key_bytes is None:
                    key_bytes = little_int_to_bytes(private_key, 66)
                    
            except binascii.Error:
                key_bytes = little_int_to_bytes(private_key, 66)
        
        # Inverter a ordem dos bytes para exibição no formato edgetk
        key_bytes_be = bytes(reversed(key_bytes))
        
        # REMOVER ZEROS DO INÍCIO se houver
        while len(key_bytes_be) > 0 and key_bytes_be[0] == 0:
            key_bytes_be = key_bytes_be[1:]
        
        # ADICIONAR ZEROS AO FINAL para ter 66 bytes
        if len(key_bytes_be) < 66:
            key_bytes_be = key_bytes_be + b'\x00' * (66 - len(key_bytes_be))
        
        if debug:
            print(f"DEBUG: Original bytes (little): {key_bytes.hex()}")
            print(f"DEBUG: After reverse: {bytes(reversed(key_bytes)).hex()}")
            print(f"DEBUG: Final display bytes: {key_bytes_be.hex()}")
        
        print(f"Private-Key: ({(len(key_bytes_be)*8)}-bit)")
        print("priv: ")
        hex_str = key_bytes_be.hex()
        for i in range(0, len(hex_str), 30):
            line_hex = hex_str[i:i+30]
            formatted = ':'.join(line_hex[j:j+2] for j in range(0, len(line_hex), 2))
            print(f"    {formatted}")
        
        # Calculate and show public key
        try:
            pub_x, pub_y = ed521_get_public_key(private_key)
            compressed_pub = ed521_compress_point(pub_x, pub_y)
        except Exception as e:
            print(f"✖ Failed to calculate public key: {e}")
            return None, None
        
        print("pub: ")
        hex_str = compressed_pub.hex()
        for i in range(0, len(hex_str), 30):
            line_hex = hex_str[i:i+30]
            formatted = ':'.join(line_hex[j:j+2] for j in range(0, len(line_hex), 2))
            print(f"    {formatted}")
        
        print(f"Curve: E-521")
        print(f"OID: 1.3.6.1.4.1.44588.2.1")
        
        return private_key, (pub_x, pub_y)
    
    # Parse public key
    elif "PUBLIC KEY" in pem_data or ("E-521" in pem_data and "PUBLIC" in pem_data):
        # Public keys are never encrypted
        print(pem_data.strip())
        
        # Parse public key
        try:
            pub_x, pub_y = parse_ed521_pem_public_key(pem_data, debug)
        except Exception as e:
            print(f"✖ Failed to parse public key: {e}")
            return None, None
        
        compressed_pub = ed521_compress_point(pub_x, pub_y)
        
        print(f"\nPublic-Key: ({len(compressed_pub)*8}-bit)")
        hex_str = compressed_pub.hex()
        for i in range(0, len(hex_str), 30):
            line_hex = hex_str[i:i+30]
            formatted = ':'.join(line_hex[j:j+2] for j in range(0, len(line_hex), 2))
            print(f"    {formatted}")
        
        print(f"Curve: E-521")
        print(f"OID: 1.3.6.1.4.1.44588.2.1")
        
        return None, (pub_x, pub_y)
    
    else:
        print("✖ Unknown key format")
        return None, None

def parse_ed521_private_key_from_der(der_data, debug=False):
    """Parse Ed521 private key directly from DER data"""
    if debug:
        print(f"DEBUG: Parsing DER data length: {len(der_data)} bytes")
        print(f"DEBUG: DER hex: {der_data.hex()}")
    
    try:
        idx = 0
        
        # SEQUENCE
        if der_data[idx] != 0x30:
            raise ValueError("Expected SEQUENCE (0x30)")
        idx += 1
        
        # Length
        seq_len = der_data[idx]
        idx += 1
        if seq_len & 0x80:  # Long form
            num_bytes = seq_len & 0x7F
            seq_len = int.from_bytes(der_data[idx:idx+num_bytes], 'big')
            idx += num_bytes
        
        # Version (INTEGER 0)
        if der_data[idx] != 0x02:
            raise ValueError(f"Expected INTEGER (0x02), got 0x{der_data[idx]:02x}")
        idx += 1
        
        ver_len = der_data[idx]
        idx += 1
        version = int.from_bytes(der_data[idx:idx+ver_len], 'big')
        if version != 0:
            raise ValueError(f"Expected version 0, got {version}")
        idx += ver_len
        
        # AlgorithmIdentifier (SEQUENCE)
        if der_data[idx] != 0x30:
            raise ValueError(f"Expected AlgorithmIdentifier SEQUENCE (0x30), got 0x{der_data[idx]:02x}")
        idx += 1
        
        algo_len = der_data[idx]
        idx += 1
        if algo_len & 0x80:  # Long form
            num_bytes = algo_len & 0x7F
            algo_len = int.from_bytes(der_data[idx:idx+num_bytes], 'big')
            idx += num_bytes
        
        # Skip AlgorithmIdentifier content
        idx += algo_len
        
        # PrivateKey (OCTET STRING)
        if der_data[idx] != 0x04:
            # Tentar formato antigo (tag 0x84) para compatibilidade
            if der_data[idx] == 0x84:
                idx += 1
                priv_len = der_data[idx]
                idx += 1
                private_key_bytes = der_data[idx:idx+priv_len]
                return bytes_to_little_int(private_key_bytes)
            raise ValueError(f"Expected OCTET STRING (0x04), got 0x{der_data[idx]:02x}")
        
        idx += 1
        priv_len = der_data[idx]
        idx += 1
        
        # Handle long length
        if priv_len == 0x81:
            priv_len = der_data[idx]
            idx += 1
        elif priv_len == 0x82:
            priv_len = (der_data[idx] << 8) | der_data[idx+1]
            idx += 2
        
        private_key_bytes = der_data[idx:idx+priv_len]
        
        if debug:
            print(f"DEBUG: Private key bytes length: {len(private_key_bytes)} bytes")
            print(f"DEBUG: Private key hex: {private_key_bytes.hex()}")
        
        # Convert to integer (little-endian)
        return bytes_to_little_int(private_key_bytes)
        
    except Exception as e:
        if debug:
            print(f"DEBUG: ASN.1 parsing failed: {e}")
        
        # Fallback: procurar por 66 bytes no DER
        if len(der_data) == 66:
            key_int = bytes_to_little_int(der_data)
            if 0 < key_int < N:
                if debug:
                    print("DEBUG: Whole data is a valid 66-byte key")
                return key_int
        
        for i in range(len(der_data) - 66 + 1):
            chunk = der_data[i:i+66]
            key_int = bytes_to_little_int(chunk)
            if 0 < key_int < N:
                if debug:
                    print(f"DEBUG: Found 66-byte key at offset {i}")
                return key_int
        
        raise ValueError(f"Cannot parse Ed521 private key: {e}")

# =========================
# CLI MAIN
# =========================

def main():
    parser = argparse.ArgumentParser(
        description="EDGE Crypto Toolbox - ED521, PKCS8 com Curupira-192-CBC",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Ed521 signatures (ICP-Brasil Standard)
  python %(prog)s ed521 gen --priv ed521_priv.pem --pub ed521_pub.pem [--password "mypass"]
  python %(prog)s ed521 sign --priv ed521_priv.pem --msg document.txt
  python %(prog)s ed521 verify --pub ed521_pub.pem --msg document.txt --sig SIGNATURE_HEX
  python %(prog)s ed521 prove --priv ed521_priv.pem
  python %(prog)s ed521 verify-proof --pub ed521_pub.pem --proof-file ed521_proof.bin
  python %(prog)s ed521 test
  python %(prog)s ed521 parse key.pem [--debug]
        """
    )
    
    sub = parser.add_subparsers(dest="tool", title="Tools", required=True)

    # ======================
    # Ed521
    # ======================
    ed521 = sub.add_parser("ed521", help="Ed521 signatures (521-bit curve)")
    ed521sub = ed521.add_subparsers(dest="cmd", required=True)
    
    ed521_gen = ed521sub.add_parser("gen", help="Generate Ed521 keys")
    ed521_gen.add_argument("--priv", default="ed521_private.pem", help="Private key PEM")
    ed521_gen.add_argument("--pub", default="ed521_public.pem", help="Public key PEM")
    ed521_gen.add_argument("--password", help="Password to encrypt private key (optional)")
    
    ed521_sign = ed521sub.add_parser("sign", help="Sign with Ed521")
    ed521_sign.add_argument("--priv", required=True, help="Private key PEM")
    ed521_sign.add_argument("--msg", required=True, help="Message file")
    
    ed521_ver = ed521sub.add_parser("verify", help="Verify Ed521 signature")
    ed521_ver.add_argument("--pub", required=True, help="Public key PEM")
    ed521_ver.add_argument("--msg", required=True, help="Message file")
    ed521_ver.add_argument("--sig", required=True, help="Signature hex")
    
    ed521_prove = ed521sub.add_parser("prove", help="Generate ZKP proof of private key knowledge")
    ed521_prove.add_argument("--priv", required=True, help="Private key file")

    ed521_verify_proof = ed521sub.add_parser("verify-proof", help="Verify ZKP proof")
    ed521_verify_proof.add_argument("--pub", required=True, help="Public key file")
    ed521_verify_proof.add_argument("--proof", help="Proof in hex to verify")
    ed521_verify_proof.add_argument("--proof-file", help="Proof file (takes precedence over --proof)")
    
    ed521_parse = ed521sub.add_parser("parse", help="Parse Ed521 key file and display info")
    ed521_parse.add_argument("key_file", help="PEM key file to parse")
    ed521_parse.add_argument("--debug", action="store_true", help="Debug output")

    ed521_test_cmd = ed521sub.add_parser("test", help="Test Ed521 implementation")

    args = parser.parse_args()

    # ======================
    # Dispatcher
    # ======================
    if args.tool == "ed521":
        if args.cmd == "gen":
            ed521_generate(args.priv, args.pub, args.password)
        elif args.cmd == "sign":
            ed521_sign_file(args.priv, args.msg)
        elif args.cmd == "verify":
            ed521_verify_file(args.pub, args.msg, args.sig)
        elif args.cmd == "prove":
            ed521_prove_command(args.priv)
        elif args.cmd == "verify-proof":
            ed521_verify_proof_command(args.pub, args.proof, args.proof_file)
        elif args.cmd == "test":
            ed521_test_command()
        elif args.cmd == "parse":
            ed521_parse_key(args.key_file, args.debug)
        
if __name__ == "__main__":
    main()
