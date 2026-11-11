# e521.cr
# Pure Crystal implementation of ED521 (E-521 curve), byte-compatible with
# the Go implementation at github.com/pedroalbanese/e521.

require "big"
require "random/secure"
require "base64"

# ====================================================================
# E-521 curve parameters
# ====================================================================

module ED521
  P  = BigInt.new("6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151")
  N  = BigInt.new("1716199415032652428745475199770348304317358825035826352348615864796385795849413675475876651663657849636693659065234142604319282948702542317993421293670108523")
  D  = BigInt.new("-376014")
  Gx = BigInt.new("1571054894184995387535939749894317568645297350402905821437625181152304994381188529632591196067604100772673927915114267193389905003276673749012051148356041324")
  Gy = BigInt.new("12")
  H  = BigInt.new("4")
  BIT_SIZE = 521
  BYTE_LEN = 66
  OID      = [1, 3, 6, 1, 4, 1, 44588, 2, 1]
  OID_DER  = Bytes[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xdc, 0x2c, 0x02, 0x01]
end

# ====================================================================
# Byte helpers
# ====================================================================

def bytes_to_little_int(b : Bytes) : BigInt
  return BigInt.new(0) if b.empty?
  result = BigInt.new(0)
  b.size.times do |i|
    result |= BigInt.new(b[i]) << (i * 8)
  end
  result
end

def little_int_to_bytes(n : BigInt, length : Int32) : Bytes
  return Bytes.new(length, 0_u8) if n == 0
  hex = n.to_s(16)
  hex = hex.rjust(hex.size + (hex.size.odd? ? 1 : 0), '0')
  bytes_be = Bytes.new(hex.size // 2) { |i| hex[2*i, 2].to_u8(16) }
  if bytes_be.size < length
    padding = Bytes.new(length - bytes_be.size, 0_u8)
    bytes_be = padding + bytes_be
  end
  reversed = Bytes.new(length, 0_u8)
  length.times { |i| reversed[i] = bytes_be[length - 1 - i] }
  reversed
end

def hex_to_bytes(hex : String) : Bytes
  h = hex.gsub(/\s+/, "")
  raise "invalid hex: odd length" if h.size.odd?
  raise "invalid hex: non-hex characters" unless h.matches?(/\A[0-9a-fA-F]*\z/)
  bytes = Bytes.new(h.size // 2, 0_u8)
  (h.size // 2).times do |i|
    bytes[i] = h[2*i, 2].to_u8(16)
  end
  bytes
end

def bytes_to_hex(b : Bytes) : String
  String.build { |s| b.each { |x| s << x.to_s(16).rjust(2, '0') } }
end

# ====================================================================
# SHAKE256 (Keccak-f[1600], rate 136, domain 0x1F)
# ====================================================================

module SHAKE256
  RATE   = 136
  DSBYTE = 0x1F_u8

  RC = [
    0x0000000000000001_u64, 0x0000000000008082_u64,
    0x800000000000808A_u64, 0x8000000080008000_u64,
    0x000000000000808B_u64, 0x0000000080000001_u64,
    0x8000000080008081_u64, 0x8000000000008009_u64,
    0x000000000000008A_u64, 0x0000000000000088_u64,
    0x0000000080008009_u64, 0x000000008000000A_u64,
    0x000000008000808B_u64, 0x800000000000008B_u64,
    0x8000000000008089_u64, 0x8000000000008003_u64,
    0x8000000000008002_u64, 0x8000000000000080_u64,
    0x000000000000800A_u64, 0x800000008000000A_u64,
    0x8000000080008081_u64, 0x8000000000008080_u64,
    0x0000000080000001_u64, 0x8000000080008008_u64,
  ]

  ROT = [
    [ 0, 36, 3, 41, 18 ],
    [ 1, 44, 10, 45, 2 ],
    [ 62, 6, 43, 15, 61 ],
    [ 28, 55, 25, 21, 56 ],
    [ 27, 20, 39, 8, 14 ],
  ]

  private def self.rotl(x : UInt64, n : Int32) : UInt64
    n &= 63
    return x if n == 0
    (x << n) | (x >> (64 - n))
  end

  private def self.keccak_f(a : Array(UInt64))
    c = Array(UInt64).new(5, 0_u64)
    b = Array(UInt64).new(25, 0_u64)

    24.times do |round|
      5.times { |x| c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20] }
      5.times do |x|
        d = c[(x + 4) % 5] ^ rotl(c[(x + 1) % 5], 1)
        5.times { |y| a[x + 5*y] ^= d }
      end
      5.times do |x|
        5.times do |y|
          b[y + 5*((2*x + 3*y) % 5)] = rotl(a[x + 5*y], ROT[x][y])
        end
      end
      5.times do |x|
        5.times do |y|
          a[x + 5*y] = b[x + 5*y] ^ ((~b[(x + 1) % 5 + 5*y]) & b[(x + 2) % 5 + 5*y])
        end
      end
      a[0] ^= RC[round]
    end
  end

  def self.shake256(data : Bytes, output_len : Int32) : Bytes
    state = Array(UInt64).new(25, 0_u64)
    offset = 0

    while offset + RATE <= data.size
      RATE.times { |i| state[i // 8] ^= data[offset + i].to_u64 << (8 * (i % 8)) }
      keccak_f(state)
      offset += RATE
    end

    block = Bytes.new(RATE, 0_u8)
    remaining = data.size - offset
    remaining.times { |i| block[i] = data[offset + i] }
    block[remaining] ^= DSBYTE
    block[RATE - 1] ^= 0x80

    RATE.times { |i| state[i // 8] ^= block[i].to_u64 << (8 * (i % 8)) }
    keccak_f(state)

    output = Bytes.new(output_len, 0_u8)
    extracted = 0
    while extracted < output_len
      i = 0
      while i < RATE && extracted < output_len
        lane  = i // 8
        shift = 8 * (i % 8)
        output[extracted] = ((state[lane] >> shift) & 0xFF).to_u8
        extracted += 1
        i += 1
      end
      keccak_f(state) if extracted < output_len
    end
    output
  end

  def self.shake256(data : String, output_len : Int32 = 132) : Bytes
    shake256(data.to_slice, output_len)
  end
end

# ====================================================================
# Modular arithmetic helpers
# ====================================================================

def mod_inverse(a : BigInt, m : BigInt) : BigInt
  m0 = m
  x0 = BigInt.new(0)
  x1 = BigInt.new(1)
  return BigInt.new(0) if m == 1
  a = a % m
  while a > 1
    q = a // m
    t = m
    m = a % m
    a = t
    t = x0
    x0 = x1 - q * x0
    x1 = t
  end
  x1 += m0 if x1 < 0
  x1
end

def mod_pow(base : BigInt, exp : BigInt, mod : BigInt) : BigInt
  result = BigInt.new(1)
  b = base % mod
  e = exp
  while e > 0
    result = (result * b) % mod if e.odd?
    b = (b * b) % mod
    e >>= 1
  end
  result
end

def mod_sqrt(a : BigInt, p : BigInt) : BigInt?
  a = a % p
  return BigInt.new(0) if a == 0
  return nil if mod_pow(a, (p - 1) // 2, p) != 1

  if p % 4 == 3
    x = mod_pow(a, (p + 1) // 4, p)
    return (x * x) % p == a ? x : nil
  end

  if p % 8 == 5
    x = mod_pow(a, (p + 3) // 8, p)
    if (x * x) % p != a
      x = (x * mod_pow(BigInt.new(2), (p - 1) // 4, p)) % p
    end
    return (x * x) % p == a ? x : nil
  end

  q = p - 1
  s = 0
  while q.even?
    q //= 2
    s += 1
  end
  z = BigInt.new(2)
  while mod_pow(z, (p - 1) // 2, p) != p - 1
    z += 1
  end
  m = s
  c = mod_pow(z, q, p)
  t = mod_pow(a, q, p)
  r = mod_pow(a, (q + 1) // 2, p)

  while t != 1
    i = 0
    t2 = t
    while t2 != 1
      t2 = (t2 * t2) % p
      i += 1
    end
    b = mod_pow(c, BigInt.new(1) << (m - i - 1), p)
    m = i
    c = (b * b) % p
    t = (t * c) % p
    r = (r * b) % p
  end

  (r * r) % p == a ? r : nil
end

# ====================================================================
# Curve operations
# ====================================================================

module ED521Curve
  def self.is_on_curve(x : BigInt, y : BigInt) : Bool
    x2 = (x * x) % ED521::P
    y2 = (y * y) % ED521::P
    left = (x2 + y2) % ED521::P
    dx2y2 = (x2 * y2 * ED521::D) % ED521::P
    dx2y2 = (dx2y2 + ED521::P) % ED521::P if dx2y2 < 0
    right = (BigInt.new(1) + dx2y2) % ED521::P
    left == right
  end

  def self.add(x1 : BigInt, y1 : BigInt, x2 : BigInt, y2 : BigInt) : Tuple(BigInt, BigInt)
    return {x2, y2} if x1 == 0 && y1 == 0
    return {x1, y1} if x2 == 0 && y2 == 0

    x1y2 = (x1 * y2) % ED521::P
    y1x2 = (y1 * x2) % ED521::P
    numerator_x = (x1y2 + y1x2) % ED521::P

    y1y2 = (y1 * y2) % ED521::P
    x1x2 = (x1 * x2) % ED521::P
    numerator_y = (y1y2 - x1x2) % ED521::P
    numerator_y = (numerator_y + ED521::P) % ED521::P if numerator_y < 0

    dx1x2y1y2 = (x1x2 * y1y2 * ED521::D) % ED521::P
    dx1x2y1y2 = (dx1x2y1y2 + ED521::P) % ED521::P if dx1x2y1y2 < 0

    denominator_x = (BigInt.new(1) + dx1x2y1y2) % ED521::P
    denominator_y = (BigInt.new(1) - dx1x2y1y2) % ED521::P
    denominator_y = (denominator_y + ED521::P) % ED521::P if denominator_y < 0

    inv_denom_x = mod_inverse(denominator_x, ED521::P)
    inv_denom_y = mod_inverse(denominator_y, ED521::P)

    x3 = (numerator_x * inv_denom_x) % ED521::P
    y3 = (numerator_y * inv_denom_y) % ED521::P
    {x3, y3}
  end

  def self.double(x1 : BigInt, y1 : BigInt) : Tuple(BigInt, BigInt)
    add(x1, y1, x1, y1)
  end

  def self.scalar_mult(x : BigInt, y : BigInt, k : Bytes) : Tuple(BigInt, BigInt)
    scalar = bytes_to_little_int(k) % ED521::N
    result_x = BigInt.new(0)
    result_y = BigInt.new(1)
    temp_x = BigInt.new(x)
    temp_y = BigInt.new(y)
    while scalar > 0
      result_x, result_y = add(result_x, result_y, temp_x, temp_y) if scalar.odd?
      temp_x, temp_y = double(temp_x, temp_y)
      scalar >>= 1
    end
    {result_x, result_y}
  end

  def self.scalar_base_mult(k : Bytes) : Tuple(BigInt, BigInt)
    scalar_mult(ED521::Gx, ED521::Gy, k)
  end
end

# ====================================================================
# Point compression / decompression (RFC 8032 style)
# ====================================================================

def compress_point(x : BigInt, y : BigInt) : Bytes
  byte_len = ED521::BYTE_LEN
  y_bytes = little_int_to_bytes(y, byte_len)
  x_bytes = little_int_to_bytes(x, byte_len)
  sign_bit = x_bytes[0] & 1

  compressed = Bytes.new(byte_len, 0_u8)
  byte_len.times { |i| compressed[i] = y_bytes[i] }
  compressed[byte_len - 1] |= (sign_bit << 7)
  compressed
end

def decompress_point(data : Bytes) : Tuple(BigInt?, BigInt?)
  byte_len = ED521::BYTE_LEN
  return {nil, nil} if data.size != byte_len

  sign_bit = (data[byte_len - 1] >> 7) & 1

  y_bytes = Bytes.new(byte_len, 0_u8)
  byte_len.times { |i| y_bytes[i] = data[i] }
  y_bytes[byte_len - 1] &= 0x7F
  y = bytes_to_little_int(y_bytes)
  return {nil, nil} if y >= ED521::P

  y2 = (y * y) % ED521::P

  numerator = (BigInt.new(1) - y2) % ED521::P
  numerator = (numerator + ED521::P) % ED521::P if numerator < 0

  dy2 = (y2 * ED521::D) % ED521::P
  dy2 = (dy2 + ED521::P) % ED521::P if dy2 < 0
  denominator = (BigInt.new(1) - dy2) % ED521::P
  denominator = (denominator + ED521::P) % ED521::P if denominator < 0

  inv_denom = mod_inverse(denominator, ED521::P)
  return {nil, nil} if inv_denom == 0

  x2 = (numerator * inv_denom) % ED521::P
  x = mod_sqrt(x2, ED521::P)
  return {nil, nil} if x.nil?
  return {nil, nil} if x == 0 && sign_bit == 1

  x_bytes = little_int_to_bytes(x, byte_len)
  x = ED521::P - x if (x_bytes[0] & 1) != sign_bit
  {x, y}
end

# ====================================================================
# dom5 and SHAKE256-based hash
# ====================================================================

def dom5(phflag : UInt8, context : Bytes) : Bytes
  raise "context too long for dom5" if context.size > 255
  dom = "SigEd521".to_slice
  dom = dom + Bytes[phflag]
  dom = dom + Bytes[context.size.to_u8]
  dom = dom + context
  dom
end

def hash_e521(phflag : UInt8, context : Bytes, x : Bytes) : Bytes
  SHAKE256.shake256(dom5(phflag, context) + x, 132)
end

# ====================================================================
# Key generation
# ====================================================================

def rand_little_int(max : BigInt) : BigInt
  byte_len = (max.bit_length + 7) // 8
  loop do
    buf = Random::Secure.random_bytes(byte_len)
    num = bytes_to_little_int(buf)
    return num if num < max
  end
end

def generate_private_key : BigInt
  rand_little_int(ED521::N)
end

def get_public_key(priv : BigInt) : Tuple(BigInt, BigInt)
  ED521Curve.scalar_base_mult(little_int_to_bytes(priv, ED521::BYTE_LEN))
end

# ====================================================================
# Pure EdDSA over E-521 (Go-compatible: D used directly)
# ====================================================================

def sign(priv : BigInt, message : Bytes) : Bytes
  byte_len = ED521::BYTE_LEN

  # 1. prefix = SHAKE256(dom5 || D_le_bytes, 132)
  prefix = hash_e521(0x00_u8, Bytes.empty, little_int_to_bytes(priv, byte_len))

  # 2. r = SHAKE256(dom5 || prefix || message, 132) mod N
  r_bytes = hash_e521(0x00_u8, Bytes.empty, prefix + message)
  r = bytes_to_little_int(r_bytes) % ED521::N

  # 3. R = r*G
  rx, ry = ED521Curve.scalar_base_mult(little_int_to_bytes(r, byte_len))
  r_compressed = compress_point(rx, ry)

  # 4. A = D*G
  pub_x, pub_y = ED521Curve.scalar_base_mult(little_int_to_bytes(priv, byte_len))
  a_compressed = compress_point(pub_x, pub_y)

  # 5. hram = SHAKE256(dom5 || R || A || message, 132) mod N
  hram_hash = hash_e521(0x00_u8, Bytes.empty, r_compressed + a_compressed + message)
  hram = bytes_to_little_int(hram_hash) % ED521::N

  # 6. s = (hram * D + r) mod N
  s = (hram * priv + r) % ED521::N
  r_compressed + little_int_to_bytes(s, byte_len)
end

def verify(pub_x : BigInt, pub_y : BigInt, message : Bytes, sig : Bytes) : Bool
  byte_len = ED521::BYTE_LEN
  return false if sig.size != byte_len * 2

  r_compressed = sig[0, byte_len]
  s = bytes_to_little_int(sig[byte_len, byte_len])
  return false if s >= ED521::N

  rx, ry = decompress_point(r_compressed)
  return false if rx.nil? || ry.nil?

  a_compressed = compress_point(pub_x, pub_y)
  hram_hash = hash_e521(0x00_u8, Bytes.empty, r_compressed + a_compressed + message)
  hram = bytes_to_little_int(hram_hash) % ED521::N

  sg_x, sg_y   = ED521Curve.scalar_base_mult(little_int_to_bytes(s, byte_len))
  ha_x, ha_y   = ED521Curve.scalar_mult(pub_x, pub_y, little_int_to_bytes(hram, byte_len))
  rha_x, rha_y = ED521Curve.add(rx, ry, ha_x, ha_y)

  sg_x == rha_x && sg_y == rha_y
end

# ====================================================================
# Zero-knowledge proof of knowledge (Schnorr / Fiat–Shamir)
# ====================================================================

def prove_knowledge(priv : BigInt) : Bytes
  byte_len = ED521::BYTE_LEN

  r = rand_little_int(ED521::N)
  rx, ry = ED521Curve.scalar_base_mult(little_int_to_bytes(r, byte_len))
  r_comp = compress_point(rx, ry)

  pub_x, pub_y = ED521Curve.scalar_base_mult(little_int_to_bytes(priv, byte_len))
  a_comp = compress_point(pub_x, pub_y)

  c_bytes = hash_e521(0x00_u8, Bytes.empty, r_comp + a_comp)
  c = bytes_to_little_int(c_bytes[0, byte_len]) % ED521::N

  s = (c * priv + r) % ED521::N
  r_comp + little_int_to_bytes(s, byte_len)
end

def verify_knowledge(pub_x : BigInt, pub_y : BigInt, proof : Bytes) : Bool
  byte_len = ED521::BYTE_LEN
  return false if proof.size != 2 * byte_len

  r_comp = proof[0, byte_len]
  s = bytes_to_little_int(proof[byte_len, byte_len])

  rx, ry = decompress_point(r_comp)
  return false if rx.nil? || ry.nil?

  a_comp = compress_point(pub_x, pub_y)
  c_bytes = hash_e521(0x00_u8, Bytes.empty, r_comp + a_comp)
  c = bytes_to_little_int(c_bytes[0, byte_len]) % ED521::N

  sg_x, sg_y   = ED521Curve.scalar_base_mult(little_int_to_bytes(s, byte_len))
  ca_x, ca_y   = ED521Curve.scalar_mult(pub_x, pub_y, little_int_to_bytes(c, byte_len))
  rca_x, rca_y = ED521Curve.add(rx, ry, ca_x, ca_y)

  sg_x == rca_x && sg_y == rca_y
end

# ====================================================================
# PEM / DER (PKCS#8 and SPKI), Go-compatible
# ====================================================================

def private_key_to_pem(priv : BigInt) : String
  priv_bytes = little_int_to_bytes(priv, ED521::BYTE_LEN)

  # Go: Parameters = asn1.RawValue{Tag: asn1.TagOID} -> 06 00
  oid_der = Bytes[0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xdc, 0x2c, 0x02, 0x01]
  algorithm_id = Bytes[0x30, 0x0c] + oid_der + Bytes[0x06, 0x00]

  version = Bytes[0x02, 0x01, 0x00]
  priv_field = Bytes[0x04, 0x42] + priv_bytes

  content = version + algorithm_id + priv_field
  pkcs8 = if content.size <= 0x7F
            Bytes[0x30, content.size.to_u8] + content
          else
            Bytes[0x30, 0x81, content.size.to_u8] + content
          end

  b64 = Base64.strict_encode(pkcs8)
  lines = b64.scan(/.{1,64}/).map(&.[0])
  String.build do |io|
    io << "-----BEGIN E-521 PRIVATE KEY-----\n"
    lines.each { |l| io << l << "\n" }
    io << "-----END E-521 PRIVATE KEY-----\n"
  end
end

def public_key_to_pem(pub_x : BigInt, pub_y : BigInt) : String
  compressed = compress_point(pub_x, pub_y)

  oid_der = Bytes[0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xdc, 0x2c, 0x02, 0x01]
  algorithm_id = Bytes[0x30, 0x0c] + oid_der + Bytes[0x06, 0x00]

  bit_string_data = Bytes[0x00] + compressed
  bit_string = if bit_string_data.size <= 0x7F
                 Bytes[0x03, bit_string_data.size.to_u8] + bit_string_data
               else
                 Bytes[0x03, 0x81, bit_string_data.size.to_u8] + bit_string_data
               end

  content = algorithm_id + bit_string
  spki = if content.size <= 0x7F
           Bytes[0x30, content.size.to_u8] + content
         else
           Bytes[0x30, 0x81, content.size.to_u8] + content
         end

  b64 = Base64.strict_encode(spki)
  lines = b64.scan(/.{1,64}/).map(&.[0])
  String.build do |io|
    io << "-----BEGIN E-521 PUBLIC KEY-----\n"
    lines.each { |l| io << l << "\n" }
    io << "-----END E-521 PUBLIC KEY-----\n"
  end
end

def read_asn1_len(der : Bytes, idx : Int32) : Tuple(Int32, Int32)
  b = der[idx]
  if b & 0x80 == 0
    {b.to_i, idx + 1}
  else
    n = b & 0x7F
    len = 0
    n.times { |i| len = (len << 8) | der[idx + 1 + i] }
    {len, idx + 1 + n}
  end
end

def read_private_key_from_pem(filename : String) : BigInt
  pem = File.read(filename).strip
  b64 = pem.lines.reject { |l| l.starts_with?("-----") }.join
  der = Base64.decode(b64)

  idx = 0
  raise "expected SEQUENCE" if der[idx] != 0x30
  idx += 1
  _, idx = read_asn1_len(der, idx)

  raise "expected INTEGER" if der[idx] != 0x02
  idx += 1
  ver_len, idx = read_asn1_len(der, idx)
  idx += ver_len

  raise "expected AlgorithmIdentifier" if der[idx] != 0x30
  idx += 1
  alg_len, idx = read_asn1_len(der, idx)
  idx += alg_len

  raise "expected OCTET STRING" if der[idx] != 0x04
  idx += 1
  key_len, idx = read_asn1_len(der, idx)
  bytes_to_little_int(der[idx, key_len])
end

def read_public_key_from_pem(filename : String) : Tuple(BigInt, BigInt)
  pem = File.read(filename).strip
  b64 = pem.lines.reject { |l| l.starts_with?("-----") }.join
  der = Base64.decode(b64)

  idx = 0
  raise "expected SEQUENCE" if der[idx] != 0x30
  idx += 1
  _, idx = read_asn1_len(der, idx)

  raise "expected AlgorithmIdentifier" if der[idx] != 0x30
  idx += 1
  alg_len, idx = read_asn1_len(der, idx)
  idx += alg_len

  raise "expected BIT STRING" if der[idx] != 0x03
  idx += 1
  bit_len, idx = read_asn1_len(der, idx)

  if bit_len == ED521::BYTE_LEN + 1
    unused = der[idx]
    idx += 1
    raise "unsupported BIT STRING unused bits: #{unused}" if unused != 0
    key_len = bit_len - 1
  elsif bit_len == ED521::BYTE_LEN
    key_len = bit_len
  else
    raise "unexpected BIT STRING length: #{bit_len}"
  end

  key_bytes = der[idx, key_len]
  raise "invalid public key length" if key_bytes.size != ED521::BYTE_LEN

  x, y = decompress_point(key_bytes)
  raise "failed to decompress public key" if x.nil? || y.nil?
  {x, y}
end

# ====================================================================
# Self-tests
# ====================================================================

def test_ed521
  puts "Testing ED521 (E-521) — Go-compatible variant"
  puts "=" * 70

  priv = generate_private_key
  pub_x, pub_y = get_public_key(priv)
  puts "1. Key generation: OK"

  compressed = compress_point(pub_x, pub_y)
  dx, dy = decompress_point(compressed)
  if dx && dy && dx == pub_x && dy == pub_y
    puts "2. Compress/decompress: OK"
  else
    puts "2. Compress/decompress: FAILED"
  end

  msg = "Test message".to_slice
  sig = sign(priv, msg)
  puts "3. Sign/verify: #{verify(pub_x, pub_y, msg, sig) ? "VALID" : "INVALID"}"

  other = "Another message".to_slice
  puts "4. Tampered message rejected: #{!verify(pub_x, pub_y, other, sig) ? "VALID" : "INVALID"}"

  proof = prove_knowledge(priv)
  puts "5. ZKP: #{verify_knowledge(pub_x, pub_y, proof) ? "VALID" : "INVALID"}"

  puts "=" * 70
  puts "Tests complete"
end

def test_shake256
  puts "SHAKE256(\"test\", 132) = #{bytes_to_hex(SHAKE256.shake256("test", 132))}"
  puts "SHAKE256(\"\", 132)     = #{bytes_to_hex(SHAKE256.shake256("", 132))}"
end

# ====================================================================
# CLI
# ====================================================================

require "option_parser"

class Config
  property priv_file : String? = nil
  property pub_file : String? = nil
  property msg : String? = nil
  property file : String? = nil
  property signature : String? = nil
  property proof : String? = nil
  property output : String? = nil
  property help : Bool = false
end

def die(msg : String) : NoReturn
  STDERR.puts "error: #{msg}"
  STDERR.puts "run with --help for usage"
  exit 1
end

def usage(io : IO = STDOUT)
  io.puts <<-USAGE
  ED521 — E-521 pure EdDSA (Go-compatible)

  Usage: ed521 <command> [options]

  Commands:
    test              Run built-in self-tests
    test-shake        Print SHAKE256 test vectors
    generate          Generate a key pair (PKCS#8 + SPKI PEM)
    sign              Sign a message
    verify            Verify a signature
    prove             Generate a ZKP of knowledge
    verify-proof      Verify a ZKP of knowledge

  Common options:
    --priv FILE       PEM private key file (sign, prove)
    --pub FILE        PEM public key file (verify, verify-proof)
    --msg STRING      Message as text
    --file FILE       Message from file ('-' = stdin)
    --sig HEX|@FILE   Signature in hex, or @file containing hex
    --proof HEX|@FILE Proof in hex, or @file containing hex
    --output FILE     Write result to file instead of stdout
    -h, --help        Show this help

  Examples:
    ed521 generate --output mykey
    ed521 sign --priv mykey_private.pem --file msg.txt
    ed521 verify --pub mykey_public.pem --file msg.txt --sig @sig.hex
  USAGE
end

def get_message_data(config : Config) : Bytes
  if config.msg && config.file
    die "use --msg OR --file, not both"
  elsif config.msg
    config.msg.not_nil!.to_slice
  elsif config.file
    if config.file == "-"
      STDIN.gets_to_end.to_slice
    else
      path = config.file.not_nil!
      die "file not found: #{path}" unless File.exists?(path)
      File.read(path).to_slice
    end
  else
    die "provide --msg or --file"
  end
end

def read_hex_input(input : String) : String
  if input.starts_with?('@')
    path = input[1..]
    die "file not found: #{path}" unless File.exists?(path)
    File.read(path).strip
  else
    input
  end
end

def require_file(path : String?, what : String) : String
  die "missing #{what}" if path.nil?
  die "#{what}: file not found: #{path.not_nil!}" unless File.exists?(path.not_nil!)
  path.not_nil!
end

def require_opt(v : String?, what : String) : String
  die "missing #{what}" if v.nil?
  v.not_nil!
end

def emit_output(data : String, output : String?)
  if output
    File.write(output.not_nil!, data)
    STDERR.puts "written to: #{output}"
  else
    puts data
  end
end

def parse_hex_or_die(s : String, what : String) : Bytes
  begin
    hex_to_bytes(s)
  rescue ex
    die "#{what}: #{ex.message}"
  end
end

# ---- Entry ----

config = Config.new

if ARGV.size == 0
  usage
  exit 0
end

command = ARGV.shift? || ""

parser = OptionParser.new
parser.on("--priv FILE", "")  { |f| config.priv_file = f }
parser.on("--pub FILE", "")   { |f| config.pub_file = f }
parser.on("--msg STRING", "") { |m| config.msg = m }
parser.on("--file FILE", "")  { |f| config.file = f }
parser.on("--sig HEX", "")    { |s| config.signature = s }
parser.on("--proof HEX", "")  { |p| config.proof = p }
parser.on("--output FILE", ""){ |o| config.output = o }
parser.on("-h", "--help", "") { config.help = true }

begin
  parser.parse
rescue ex
  die ex.message.to_s
end

if config.help
  usage
  exit 0
end

case command
when "test"
  test_ed521

when "test-shake"
  test_shake256

when "generate"
  priv = generate_private_key
  pub_x, pub_y = get_public_key(priv)
  base = config.output || "ed521"
  priv_file = "#{base}_private.pem"
  pub_file = "#{base}_public.pem"
  File.write(priv_file, private_key_to_pem(priv))
  File.write(pub_file, public_key_to_pem(pub_x, pub_y))
  puts "keys written to #{priv_file} and #{pub_file}"

when "sign"
  die "sign does not accept --pub"   if config.pub_file
  die "sign does not accept --sig"   if config.signature
  die "sign does not accept --proof" if config.proof

  priv_path = require_file(config.priv_file, "--priv")
  msg = get_message_data(config)
  priv = read_private_key_from_pem(priv_path)
  emit_output(bytes_to_hex(sign(priv, msg)), config.output)

when "verify"
  die "verify does not accept --priv"  if config.priv_file
  die "verify does not accept --proof" if config.proof

  pub_path = require_file(config.pub_file, "--pub")
  sig_raw  = require_opt(config.signature, "--sig")
  msg = get_message_data(config)
  pub_x, pub_y = read_public_key_from_pem(pub_path)
  sig_bytes = parse_hex_or_die(read_hex_input(sig_raw), "--sig")
  if verify(pub_x, pub_y, msg, sig_bytes)
    puts "signature valid"
    exit 0
  else
    puts "signature invalid"
    exit 1
  end

when "prove"
  die "prove does not accept --pub"   if config.pub_file
  die "prove does not accept --sig"   if config.signature
  die "prove does not accept --proof" if config.proof

  priv_path = require_file(config.priv_file, "--priv")
  priv = read_private_key_from_pem(priv_path)
  emit_output(bytes_to_hex(prove_knowledge(priv)), config.output)

when "verify-proof"
  die "verify-proof does not accept --priv" if config.priv_file
  die "verify-proof does not accept --sig"  if config.signature

  pub_path = require_file(config.pub_file, "--pub")
  proof_raw = require_opt(config.proof, "--proof")
  pub_x, pub_y = read_public_key_from_pem(pub_path)
  proof_bytes = parse_hex_or_die(read_hex_input(proof_raw), "--proof")
  if verify_knowledge(pub_x, pub_y, proof_bytes)
    puts "proof valid"
    exit 0
  else
    puts "proof invalid"
    exit 1
  end

when "help", "-h", "--help"
  usage

else
  STDERR.puts "unknown command: #{command}"
  usage(STDERR)
  exit 1
end
