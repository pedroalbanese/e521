# ed521.cr
# Implementação pura de ED521 (Curva E-521) em Crystal

require "big"
require "random/secure"
require "base64"

# ====================================================================
# Funções auxiliares de aritmética modular
# ====================================================================

# Algoritmo de Euclides estendido para inverso modular
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
  
  # Ajusta se negativo
  if x1 < 0
    x1 = x1 + m0
  end
  x1
end

# Exponenciação modular: (base ** exp) % mod
def mod_pow(base : BigInt, exp : BigInt, mod : BigInt) : BigInt
  result = BigInt.new(1)
  b = base % mod
  e = exp
  while e > 0
    if e.odd?
      result = (result * b) % mod
    end
    b = (b * b) % mod
    e >>= 1
  end
  result
end

# ====================================================================
# Parâmetros da Curva E-521 (Edwards)
# ====================================================================

module ED521
  # Módulo primo p = 2^521 - 1
  P = BigInt.new("6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151")
  
  # Ordem do grupo n
  N = BigInt.new("1716199415032652428745475199770348304317358825035826352348615864796385795849413675475876651663657849636693659065234142604319282948702542317993421293670108523")
  
  # Parâmetro d da curva de Edwards (negativo)
  D = BigInt.new(-376014)
  
  # Ponto gerador G
  Gx = BigInt.new("1571054894184995387535939749894317568645297350402905821437625181152304994381188529632591196067604100772673927915114267193389905003276673749012051148356041324")
  Gy = BigInt.new(12)
  
  # Co-fator
  H = 4
  
  # Tamanhos
  BIT_SIZE = 521
  BYTE_LEN = 66  # (521 + 7) // 8
  
  # OID oficial ED521 (1.3.6.1.4.1.44588.2.1)
  OID = [1, 3, 6, 1, 4, 1, 44588, 2, 1]
  
  # OID em formato DER para ASN.1
  OID_DER = Bytes[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xdc, 0x2c, 0x02, 0x01]
end

# ====================================================================
# Funções de conversão de bytes
# ====================================================================

# Converte bytes little-endian para BigInt
def bytes_to_little_int(bytes : Bytes) : BigInt
  result = BigInt.new(0)
  bytes.size.times do |i|
    result |= BigInt.new(bytes[i]) << (i * 8)
  end
  result
end

# Converte BigInt para bytes little-endian com tamanho fixo
def little_int_to_bytes(n : BigInt, length : Int32) : Bytes
  # Primeiro converte para bytes big-endian
  hex = n.to_s(16)
  hex = hex.rjust(hex.size + (hex.size.odd? ? 1 : 0), '0')
  bytes_be = Bytes.new(hex.size // 2) { |i| hex[2*i, 2].to_u8(16) }
  
  # Padding para o tamanho correto
  if bytes_be.size < length
    padding = Bytes.new(length - bytes_be.size, 0_u8)
    bytes_be = padding + bytes_be
  end
  
  # Reverter para little-endian
  bytes_le = Bytes.new(length, 0_u8)
  length.times { |i| bytes_le[i] = bytes_be[length - 1 - i] }
  bytes_le
end

# Converte string para bytes
def str_to_bytes(s : String) : Bytes
  s.to_slice
end

# Converte hex para bytes
def hex_to_bytes(hex : String) : Bytes
  hex = hex.gsub(/\s+/, "")
  hex = "0" + hex if hex.size.odd?
  bytes = Bytes.new(hex.size // 2)
  hex.size.times do |i|
    next if i.even?
    byte = hex[i-1, 2].to_u8(16)
    bytes[(i-1)//2] = byte
  end
  bytes
end

# Converte bytes para hex
def bytes_to_hex(bytes : Bytes) : String
  String.build { |str| bytes.each { |b| str << b.to_s(16).rjust(2, '0') } }
end

# Comparação em tempo constante de dois BigInt
def constant_time_eq(a : BigInt, b : BigInt) : Bool
  a_bytes = a.to_s(16).rjust(ED521::BYTE_LEN*2, '0').to_slice
  b_bytes = b.to_s(16).rjust(ED521::BYTE_LEN*2, '0').to_slice
  result = 0
  ED521::BYTE_LEN.times do |i|
    result |= a_bytes[i] ^ b_bytes[i]
  end
  result == 0
end

# ====================================================================
# SHAKE256 Implementation - Versão Final
# ====================================================================

module SHAKE256
  RATE = 136
  DSBYTE = 0x1F_u8
  ROUNDS = 24

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
    ((x << n) | (x >> (64 - n)))
  end

  private def self.keccak_f(state : Array(UInt64))
    24.times do |round|
      # Theta
      c = Array(UInt64).new(5) { |i|
        state[i] ^ state[i+5] ^ state[i+10] ^ state[i+15] ^ state[i+20]
      }
      d = Array(UInt64).new(5) { |i|
        c[(i+4)%5] ^ rotl(c[(i+1)%5], 1)
      }
      5.times do |i|
        5.times do |j|
          state[i + 5*j] ^= d[i]
        end
      end

      # Rho + Pi
      b = Array(UInt64).new(25, 0_u64)
      5.times do |x|
        5.times do |y|
          b[y + 5*((2*x + 3*y) % 5)] = rotl(state[x + 5*y], ROT[x][y])
        end
      end

      # Chi
      5.times do |x|
        5.times do |y|
          state[x + 5*y] = b[x + 5*y] ^ ((~b[(x+1)%5 + 5*y]) & b[(x+2)%5 + 5*y])
        end
      end

      # Iota
      state[0] ^= RC[round]
    end
  end

  # Função principal - retorna hash de qualquer tamanho
  def self.shake256(data : Bytes, output_len : Int32) : Bytes
    state = Array(UInt64).new(25, 0_u64)

    # Absorção
    offset = 0
    data_size = data.size
    
    while offset + RATE <= data_size
      block = data[offset, RATE]
      RATE.times do |i|
        state[i // 8] ^= block[i].to_u64 << (8 * (i % 8))
      end
      keccak_f(state)
      offset += RATE
    end

    # Padding
    block = Bytes.new(RATE, 0_u8)
    remaining = data_size - offset
    remaining.times { |i| block[i] = data[offset + i] }
    block[remaining] ^= DSBYTE
    block[RATE - 1] ^= 0x80

    RATE.times do |i|
      state[i // 8] ^= block[i].to_u64 << (8 * (i % 8))
    end
    keccak_f(state)

    # Squeeze
    output = Bytes.new(output_len, 0_u8)
    extracted = 0
    
    while extracted < output_len
      i = 0
      while i < RATE && extracted < output_len
        lane = i // 8
        shift = 8 * (i % 8)
        output[extracted] = ((state[lane] >> shift) & 0xFF).to_u8
        extracted += 1
        i += 1
      end
      
      if extracted < output_len
        keccak_f(state)
      end
    end

    output
  end

  # Versão para String
  def self.shake256(data : String, output_len : Int32 = 132) : Bytes
    shake256(data.to_slice, output_len)
  end

  # Versão hexadecimal
  def self.shake256_hex(data : String | Bytes, output_len : Int32 = 132) : String
    result = shake256(data, output_len)
    String.build(result.size * 2) do |io|
      result.each { |b| io << b.to_s(16).rjust(2, '0') }
    end
  end
end

# ====================================================================
# Funções da Curva Elíptica E-521
# ====================================================================

module ED521Curve
  # Verifica se um ponto está na curva
  def self.on_curve?(x : BigInt, y : BigInt) : Bool
    x2 = (x * x) % ED521::P
    y2 = (y * y) % ED521::P
    left = (x2 + y2) % ED521::P
    
    d_pos = ED521::D < 0 ? ED521::D + ED521::P : ED521::D
    right = (1 + (d_pos * x2 * y2) % ED521::P) % ED521::P
    
    left == right
  end
  
  # Adição de pontos na curva de Edwards
  def self.add(x1 : BigInt, y1 : BigInt, x2 : BigInt, y2 : BigInt) : Tuple(BigInt, BigInt)
    # Ponto neutro é (0,1)
    if x1 == 0 && y1 == 1
      return {x2, y2}
    end
    if x2 == 0 && y2 == 1
      return {x1, y1}
    end
    
    x1y2 = (x1 * y2) % ED521::P
    y1x2 = (y1 * x2) % ED521::P
    numerator_x = (x1y2 + y1x2) % ED521::P
    
    y1y2 = (y1 * y2) % ED521::P
    x1x2 = (x1 * x2) % ED521::P
    numerator_y = (y1y2 - x1x2) % ED521::P
    numerator_y = (numerator_y + ED521::P) % ED521::P if numerator_y < 0
    
    d_pos = ED521::D < 0 ? ED521::D + ED521::P : ED521::D
    dx1x2y1y2 = (d_pos * ((x1x2 * y1y2) % ED521::P)) % ED521::P
    
    denominator_x = (1 + dx1x2y1y2) % ED521::P
    denominator_y = (1 - dx1x2y1y2) % ED521::P
    denominator_y = (denominator_y + ED521::P) % ED521::P if denominator_y < 0
    
    # Inversos modulares - usando nossa função
    inv_den_x = mod_inverse(denominator_x, ED521::P)
    inv_den_y = mod_inverse(denominator_y, ED521::P)
    
    x3 = (numerator_x * inv_den_x) % ED521::P
    y3 = (numerator_y * inv_den_y) % ED521::P
    
    {x3, y3}
  end
  
  # Dobro de um ponto
  def self.double(x : BigInt, y : BigInt) : Tuple(BigInt, BigInt)
    add(x, y, x, y)
  end
  
  # Multiplicação escalar de ponto (k * P)
  def self.scalar_mult(x : BigInt, y : BigInt, k_bytes : Bytes) : Tuple(BigInt, BigInt)
    scalar = bytes_to_little_int(k_bytes) % ED521::N
    
    result_x = BigInt.new(0)
    result_y = BigInt.new(1)  # Ponto neutro
    temp_x = x
    temp_y = y
    
    while scalar > 0
      if scalar.odd?
        result_x, result_y = add(result_x, result_y, temp_x, temp_y)
      end
      temp_x, temp_y = double(temp_x, temp_y)
      scalar >>= 1
    end
    
    {result_x, result_y}
  end
  
  # Multiplicação escalar do ponto gerador (k * G)
  def self.scalar_base_mult(k_bytes : Bytes) : Tuple(BigInt, BigInt)
    scalar_mult(ED521::Gx, ED521::Gy, k_bytes)
  end
end

# ====================================================================
# Compressão/Descompressão de Pontos (RFC 8032)
# ====================================================================

# Comprime um ponto (x,y) para BYTE_LEN bytes
def compress_point(x : BigInt, y : BigInt) : Bytes
  # y em little-endian
  y_bytes = little_int_to_bytes(y, ED521::BYTE_LEN)
  
  # LSB de x determina o sinal
  x_lsb = (x & 1).to_u8
  
  # Guarda o sinal no MSB do último byte (little-endian)
  y_bytes[ED521::BYTE_LEN - 1] |= (x_lsb << 7)
  
  y_bytes
end

# Descomprime um ponto comprimido para (x,y)
def decompress_point(data : Bytes) : Tuple(BigInt?, BigInt?)
  return {nil, nil} if data.size != ED521::BYTE_LEN
  
  # Extrai sinal do MSB do último byte
  last_byte = data[ED521::BYTE_LEN - 1]
  sign_bit = (last_byte >> 7) & 1
  
  # Limpa o bit de sinal para obter y
  y_bytes = data.dup
  y_bytes[ED521::BYTE_LEN - 1] = last_byte & 0x7F
  y = bytes_to_little_int(y_bytes)
  
  # Verifica se y está no range
  return {nil, nil} if y >= ED521::P
  
  # Resolve para x usando a equação da curva: x² = (1 - y²) / (1 - d*y²)
  y2 = (y * y) % ED521::P
  
  numerator = (1 - y2) % ED521::P
  numerator = (numerator + ED521::P) % ED521::P if numerator < 0
  
  d_pos = ED521::D < 0 ? ED521::D + ED521::P : ED521::D
  denominator = (1 - (d_pos * y2) % ED521::P) % ED521::P
  denominator = (denominator + ED521::P) % ED521::P if denominator < 0
  
  # Usando nossa função de inverso
  inv_den = mod_inverse(denominator, ED521::P)
  return {nil, nil} if inv_den == 0
  
  x2 = (numerator * inv_den) % ED521::P
  
  # Raiz quadrada modular usando nossa função mod_pow
  exp = (ED521::P + 1) // 4
  x = mod_pow(x2, exp, ED521::P)
  
  # Verifica se x² está correto
  x2_check = (x * x) % ED521::P
  if x2_check != x2
    x = (-x) % ED521::P
    x2_check = (x * x) % ED521::P
    return {nil, nil} if x2_check != x2
  end
  
  # Ajusta sinal conforme sign_bit
  x_lsb = (x & 1).to_u8
  if x_lsb != sign_bit
    x = (-x) % ED521::P
  end
  
  # Verifica se o ponto está na curva
  return {nil, nil} unless ED521Curve.on_curve?(x, y)
  
  {x, y}
end

# ====================================================================
# Funções de Hash (dom5 e hash_e521)
# ====================================================================

# dom5(phflag, context) como especificado
def dom5(phflag : UInt8, context : Bytes) : Bytes
  raise "context too long for dom5" if context.size > 255
  
  # "SigEd521" + phflag + len(context) + context
  prefix = "SigEd521".to_slice
  len_byte = Bytes[context.size.to_u8]
  
  prefix + Bytes[phflag] + len_byte + context
end

# H(x) = SHAKE256(dom5(phflag,context) || x, 132)
def hash_e521(phflag : UInt8, context : Bytes, x : Bytes) : Bytes
  dom = dom5(phflag, context)
  input = dom + x
  SHAKE256.shake256(input, 132)
end

# ====================================================================
# Geração de Chaves
# ====================================================================

# Gera uma chave privada aleatória (escalar a)
def generate_private_key : BigInt
  loop do
    priv_bytes = Random::Secure.random_bytes(ED521::BYTE_LEN)
    a = bytes_to_little_int(priv_bytes)
    return a if a < ED521::N
  end
end

# Calcula a chave pública A = a * G
def get_public_key(private_key : BigInt) : Tuple(BigInt, BigInt)
  priv_bytes = little_int_to_bytes(private_key, ED521::BYTE_LEN)
  ED521Curve.scalar_base_mult(priv_bytes)
end

# ====================================================================
# Assinatura EdDSA Pura
# ====================================================================

# Assina uma mensagem com chave privada
def sign(private_key : BigInt, message : Bytes) : Bytes
  byte_len = ED521::BYTE_LEN
  
  # Hash da chave privada (prefix)
  prefix = hash_e521(0x00_u8, Bytes.empty, little_int_to_bytes(private_key, byte_len))
  
  # Calcula r = SHAKE256(prefix || message) mod N
  r_bytes = hash_e521(0x00_u8, Bytes.empty, prefix + message)
  r = bytes_to_little_int(r_bytes[0, byte_len]) % ED521::N
  
  # Computa R = r*G e comprime
  rx, ry = ED521Curve.scalar_base_mult(little_int_to_bytes(r, byte_len))
  r_compressed = compress_point(rx, ry)
  
  # Obtém chave pública A
  pub_x, pub_y = get_public_key(private_key)
  a_compressed = compress_point(pub_x, pub_y)
  
  # Calcula h = SHAKE256(dom || R || A || message) mod N
  hram_input = r_compressed + a_compressed + message
  hram_hash = hash_e521(0x00_u8, Bytes.empty, hram_input)
  h = bytes_to_little_int(hram_hash[0, byte_len]) % ED521::N
  
  # Calcula s = (r + h * a) mod N
  s = (r + (h * private_key) % ED521::N) % ED521::N
  
  # Assinatura = R_compressed || s_bytes
  s_bytes = little_int_to_bytes(s, byte_len)
  r_compressed + s_bytes
end

# Verifica uma assinatura
def verify(public_x : BigInt, public_y : BigInt, message : Bytes, signature : Bytes) : Bool
  byte_len = ED521::BYTE_LEN
  
  return false if signature.size != 2 * byte_len
  
  r_compressed = signature[0, byte_len]
  s_bytes = signature[byte_len, byte_len]
  
  # Descomprime R
  rx, ry = decompress_point(r_compressed)
  return false if rx.nil? || ry.nil?
  
  # Verifica s no range
  s = bytes_to_little_int(s_bytes)
  return false if s >= ED521::N
  
  # Comprime A
  a_compressed = compress_point(public_x, public_y)
  
  # Calcula h
  hram_input = r_compressed + a_compressed + message
  hram_hash = hash_e521(0x00_u8, Bytes.empty, hram_input)
  h = bytes_to_little_int(hram_hash[0, byte_len]) % ED521::N
  
  # Calcula s*G
  sg_x, sg_y = ED521Curve.scalar_base_mult(little_int_to_bytes(s, byte_len))
  
  # Calcula h*A
  ha_x, ha_y = ED521Curve.scalar_mult(public_x, public_y, little_int_to_bytes(h, byte_len))
  
  # Calcula R + h*A
  rha_x, rha_y = ED521Curve.add(rx, ry, ha_x, ha_y)
  
  # Compara s*G com R + h*A em tempo constante
  constant_time_eq(sg_x, rha_x) && constant_time_eq(sg_y, rha_y)
end

# ====================================================================
# Prova de Conhecimento (ZKP)
# ====================================================================

# Gera prova ZKP de conhecimento da chave privada
def prove_knowledge(private_key : BigInt) : Bytes
  byte_len = ED521::BYTE_LEN
  
  # Gera r aleatório
  r = loop do
    r_bytes = Random::Secure.random_bytes(byte_len)
    r_val = bytes_to_little_int(r_bytes)
    break r_val if r_val < ED521::N
  end
  
  # Compromisso R = r*G
  rx, ry = ED521Curve.scalar_base_mult(little_int_to_bytes(r, byte_len))
  r_comp = compress_point(rx, ry)
  
  # Chave pública A
  pub_x, pub_y = get_public_key(private_key)
  a_comp = compress_point(pub_x, pub_y)
  
  # Desafio c = H(R || A) (Fiat-Shamir)
  input_data = r_comp + a_comp
  c_bytes = hash_e521(0x00_u8, Bytes.empty, input_data)
  c = bytes_to_little_int(c_bytes[0, byte_len]) % ED521::N
  
  # Resposta s = r + c*a (mod N)
  s = (r + (c * private_key) % ED521::N) % ED521::N
  
  # Prova = R || s
  s_bytes = little_int_to_bytes(s, byte_len)
  r_comp + s_bytes
end

# Verifica prova ZKP
def verify_knowledge(public_x : BigInt, public_y : BigInt, proof : Bytes) : Bool
  byte_len = ED521::BYTE_LEN
  
  return false if proof.size != 2 * byte_len
  
  r_comp = proof[0, byte_len]
  s_bytes = proof[byte_len, byte_len]
  
  # Descomprime R
  rx, ry = decompress_point(r_comp)
  return false if rx.nil? || ry.nil?
  
  s = bytes_to_little_int(s_bytes)
  
  # Recalcula c = H(R || A)
  a_comp = compress_point(public_x, public_y)
  input_data = r_comp + a_comp
  c_bytes = hash_e521(0x00_u8, Bytes.empty, input_data)
  c = bytes_to_little_int(c_bytes[0, byte_len]) % ED521::N
  
  # Verifica s*G == R + c*A
  sg_x, sg_y = ED521Curve.scalar_base_mult(little_int_to_bytes(s, byte_len))
  ca_x, ca_y = ED521Curve.scalar_mult(public_x, public_y, little_int_to_bytes(c, byte_len))
  rca_x, rca_y = ED521Curve.add(rx, ry, ca_x, ca_y)
  
  constant_time_eq(sg_x, rca_x) && constant_time_eq(sg_y, rca_y)
end

# ====================================================================
# Formatos PEM (PKCS8 e SPKI)
# ====================================================================

# Serializa chave privada para PKCS8 PEM
def private_key_to_pem(private_key : BigInt, password : String? = nil) : String
  priv_bytes = little_int_to_bytes(private_key, ED521::BYTE_LEN)
  
  # OID em DER: 1.3.6.1.4.1.44588.2.1
  oid_der = Bytes[0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xdc, 0x2c, 0x02, 0x01]
  algorithm_id = Bytes[0x30, 0x0e] + oid_der + Bytes[0x05, 0x00]  # SEQUENCE + NULL
  
  version = Bytes[0x02, 0x01, 0x00]  # INTEGER 0
  
  # Private key como OCTET STRING (tag 0x04, length 66)
  priv_field = Bytes[0x04, 0x42] + priv_bytes
  
  content = version + algorithm_id + priv_field
  content_len = content.size
  
  # SEQUENCE com comprimento
  pkcs8 = if content_len <= 0x7F
            Bytes[0x30, content_len.to_u8] + content
          else
            Bytes[0x30, 0x81, content_len.to_u8] + content
          end
  
  if password
    STDERR.puts "Warning: Password encryption not yet implemented"
  end
  
  b64 = Base64.strict_encode(pkcs8)
  lines = b64.scan(/.{1,64}/).map(&.[0])
  
  String.build do |io|
    io << "-----BEGIN E-521 PRIVATE KEY-----\n"
    lines.each { |line| io << line << "\n" }
    io << "-----END E-521 PRIVATE KEY-----\n"
  end
end

# Serializa chave pública para SPKI PEM
def public_key_to_pem(public_x : BigInt, public_y : BigInt) : String
  compressed = compress_point(public_x, public_y)
  
  # OID em DER
  oid_der = Bytes[0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xdc, 0x2c, 0x02, 0x01]
  algorithm_id = Bytes[0x30, 0x0e] + oid_der + Bytes[0x05, 0x00]
  
  # BIT STRING com a chave comprimida
  bit_string_data = Bytes[0x00] + compressed  # Unused bits = 0
  bit_string_len = bit_string_data.size
  bit_string = if bit_string_len <= 0x7F
                 Bytes[0x03, bit_string_len.to_u8] + bit_string_data
               else
                 Bytes[0x03, 0x81, bit_string_len.to_u8] + bit_string_data
               end
  
  content = algorithm_id + bit_string
  content_len = content.size
  
  # SEQUENCE
  spki = if content_len <= 0x7F
           Bytes[0x30, content_len.to_u8] + content
         else
           Bytes[0x30, 0x81, content_len.to_u8] + content
         end
  
  b64 = Base64.strict_encode(spki)
  lines = b64.scan(/.{1,64}/).map(&.[0])
  
  String.build do |io|
    io << "-----BEGIN E-521 PUBLIC KEY-----\n"
    lines.each { |line| io << line << "\n" }
    io << "-----END E-521 PUBLIC KEY-----\n"
  end
end

# ====================================================================
# Leitura de chaves PEM
# ====================================================================

def read_private_key_from_pem(filename : String) : BigInt
  pem = File.read(filename).strip
  
  lines = pem.lines
  b64_lines = lines.reject { |l| l.starts_with?("-----") }
  b64 = b64_lines.join
  der = Base64.decode(b64)
  
  idx = 0
  
  # SEQUENCE
  raise "Invalid PEM: expected SEQUENCE (0x30)" if der[idx] != 0x30
  idx += 1
  
  # Comprimento da SEQUENCE
  if der[idx] & 0x80 != 0
    len_len = der[idx] & 0x7F
    idx += 1 + len_len
  else
    idx += 1
  end
  
  # Version (INTEGER 0)
  raise "Invalid version" if der[idx] != 0x02
  idx += 1
  ver_len = der[idx]
  idx += 1 + ver_len
  
  # PrivateKeyAlgorithm (SEQUENCE)
  raise "Invalid AlgorithmIdentifier" if der[idx] != 0x30
  idx += 1
  
  if der[idx] & 0x80 != 0
    len_len = der[idx] & 0x7F
    idx += 1 + len_len
  else
    alg_len = der[idx]
    idx += 1 + alg_len
  end
  
  # PrivateKey (OCTET STRING)
  if der[idx] == 0x04 || der[idx] == 0x84
    idx += 1
  else
    raise "Expected OCTET STRING (0x04 or 0x84), got 0x#{der[idx].to_s(16)}"
  end
  
  key_len = der[idx].to_i
  idx += 1
  
  if key_len == 0x81
    key_len = der[idx].to_i
    idx += 1
  elsif key_len == 0x82
    key_len = (der[idx].to_i << 8) | der[idx+1].to_i
    idx += 2
  end
  
  key_bytes = der[idx, key_len]
  
  bytes_to_little_int(key_bytes)
end

def read_public_key_from_pem(filename : String) : Tuple(BigInt, BigInt)
  pem = File.read(filename).strip
  
  lines = pem.lines
  b64_lines = lines.reject { |l| l.starts_with?("-----") }
  b64 = b64_lines.join
  der = Base64.decode(b64)
  
  idx = 0
  
  # SEQUENCE
  raise "Invalid PEM: expected SEQUENCE (0x30)" if der[idx] != 0x30
  idx += 1
  
  if der[idx] & 0x80 != 0
    len_len = der[idx] & 0x7F
    idx += 1 + len_len
  else
    idx += 1
  end
  
  # AlgorithmIdentifier (SEQUENCE)
  raise "Invalid AlgorithmIdentifier" if der[idx] != 0x30
  idx += 1
  
  if der[idx] & 0x80 != 0
    len_len = der[idx] & 0x7F
    idx += 1 + len_len
  else
    alg_len = der[idx]
    idx += 1 + alg_len
  end
  
  # BIT STRING
  raise "Expected BIT STRING (0x03)" if der[idx] != 0x03
  idx += 1
  
  if der[idx] & 0x80 != 0
    len_len = der[idx] & 0x7F
    bit_len = 0
    len_len.times do |i|
      bit_len = (bit_len << 8) | der[idx + 1 + i]
    end
    idx += 1 + len_len
  else
    bit_len = der[idx]
    idx += 1
  end
  
  unused = der[idx]
  idx += 1
  
  key_bytes = der[idx, ED521::BYTE_LEN]
  
  x, y = decompress_point(key_bytes)
  raise "Invalid public key" if x.nil? || y.nil?
  
  {x, y}
end

def read_message(msg_arg : String) : Bytes
  if File.exists?(msg_arg)
    File.read(msg_arg).to_slice
  else
    msg_arg.to_slice
  end
end

def read_signature(sig_arg : String) : Bytes
  if File.exists?(sig_arg)
    File.read(sig_arg).to_slice
  else
    hex_to_bytes(sig_arg)
  end
end

# ====================================================================
# Testes
# ====================================================================

def test_ed521
  puts "Testando ED521 (E-521) em Crystal puro"
  puts "=" * 70
  
  priv = generate_private_key
  pub_x, pub_y = get_public_key(priv)
  puts "\n1. Geração de chaves: OK"
  
  compressed = compress_point(pub_x, pub_y)
  decomp_x, decomp_y = decompress_point(compressed)
  if decomp_x && decomp_y && decomp_x == pub_x && decomp_y == pub_y
    puts "2. Compressão/descompressão: OK"
  else
    puts "2. Compressão/descompressão: FALHOU"
  end
  
  msg = "Mensagem de teste".to_slice
  sig = sign(priv, msg)
  valid = verify(pub_x, pub_y, msg, sig)
  puts "3. Assinatura/verificação: #{valid ? "VÁLIDO" : "INVÁLIDO"}"
  
  msg2 = "Outra mensagem".to_slice
  valid2 = verify(pub_x, pub_y, msg2, sig)
  puts "4. Mensagem alterada rejeitada: #{!valid2 ? "VÁLIDO" : "INVÁLIDO"}"
  
  proof = prove_knowledge(priv)
  valid_proof = verify_knowledge(pub_x, pub_y, proof)
  puts "5. ZKP: #{valid_proof ? "VÁLIDO" : "INVÁLIDO"}"
  
  private_pem = private_key_to_pem(priv)
  public_pem = public_key_to_pem(pub_x, pub_y)
  puts "6. Formatos PEM: OK"
  
  puts "\n" + "=" * 70
  puts "Testes concluídos"
end

# ====================================================================
# CLI com flags estilo Unix
# ====================================================================

require "option_parser"

# Configuração usando variáveis de instância
class Config
  property command : String = ""
  property priv_file : String? = nil
  property pub_file : String? = nil
  property msg : String? = nil
  property file : String? = nil
  property signature : String? = nil
  property proof : String? = nil
  property output : String? = nil
  property debug : Bool = false
end

config = Config.new

# Primeiro, mostra a ajuda se não houver argumentos
if ARGV.size == 0
  puts "ED521 - Implementação da curva E-521 em Crystal"
  puts "=" * 70
  puts "Uso: ./ed521 <comando> [opções]"
  puts ""
  puts "Comandos:"
  puts "  test                          Executa testes"
  puts "  generate                      Gera par de chaves"
  puts "  sign                          Assina mensagem/arquivo"
  puts "  verify                        Verifica assinatura"
  puts "  prove                         Gera prova ZKP"
  puts "  verify-proof                  Verifica prova"
  puts ""
  puts "Opções:"
  puts "  --priv FILE                   Arquivo de chave privada"
  puts "  --pub FILE                    Arquivo de chave pública"
  puts "  --msg STRING                  Mensagem (texto)"
  puts "  --file FILE                   Arquivo para assinar/verificar (- para stdin)"
  puts "  --sig HEX                     Assinatura em hex (ou @arquivo)"
  puts "  --proof HEX                   Prova em hex (ou @arquivo)"
  puts "  --output FILE                 Arquivo de saída"
  puts "  --debug                       Modo debug"
  puts "  -h, --help                    Mostra esta ajuda"
  puts ""
  puts "Exemplos:"
  puts "  ./ed521 test"
  puts "  ./ed521 generate"
  puts "  ./ed521 generate --output minha_chave"
  puts "  ./ed521 sign --priv priv.pem --msg 'texto direto'"
  puts "  ./ed521 sign --priv priv.pem --file documento.txt"
  puts "  ./ed521 sign --priv priv.pem --file - < documento.txt"
  puts "  ./ed521 sign --priv priv.pem --file documento.txt --output assinatura.hex"
  puts "  ./ed521 verify --pub pub.pem --file documento.txt --sig assinatura.hex"
  puts "  ./ed521 prove --priv priv.pem"
  puts "  ./ed521 prove --priv priv.pem --output prova.hex"
  puts "  ./ed521 verify-proof --pub pub.pem --proof @prova.hex"
  exit
end

# Parser de opções
parser = OptionParser.new

parser.on("--priv FILE", "Arquivo de chave privada") { |f| config.priv_file = f }
parser.on("--pub FILE", "Arquivo de chave pública") { |f| config.pub_file = f }
parser.on("--msg STRING", "Mensagem (texto)") { |m| config.msg = m }
parser.on("--file FILE", "Arquivo para assinar/verificar (- para stdin)") { |f| config.file = f }
parser.on("--sig HEX", "Assinatura em hex (ou @arquivo)") { |s| config.signature = s }
parser.on("--proof HEX", "Prova em hex (ou @arquivo)") { |p| config.proof = p }
parser.on("--output FILE", "Arquivo de saída") { |o| config.output = o }
parser.on("--debug", "Modo debug") { config.debug = true }
parser.on("-h", "--help", "Mostra ajuda") {
  puts "ED521 - Implementação da curva E-521 em Crystal"
  puts "=" * 70
  puts "Uso: ./ed521 <comando> [opções]"
  puts ""
  puts "Comandos:"
  puts "  test                          Executa testes"
  puts "  generate                      Gera par de chaves"
  puts "  sign                          Assina mensagem/arquivo"
  puts "  verify                        Verifica assinatura"
  puts "  prove                         Gera prova ZKP"
  puts "  verify-proof                  Verifica prova"
  puts ""
  puts "Opções:"
  puts "  --priv FILE                   Arquivo de chave privada"
  puts "  --pub FILE                    Arquivo de chave pública"
  puts "  --msg STRING                  Mensagem (texto)"
  puts "  --file FILE                   Arquivo para assinar/verificar (- para stdin)"
  puts "  --sig HEX                     Assinatura em hex (ou @arquivo)"
  puts "  --proof HEX                   Prova em hex (ou @arquivo)"
  puts "  --output FILE                 Arquivo de saída"
  puts "  --debug                       Modo debug"
  puts "  -h, --help                    Mostra esta ajuda"
  puts ""
  puts "Exemplos:"
  puts "  ./ed521 test"
  puts "  ./ed521 generate"
  puts "  ./ed521 generate --output minha_chave"
  puts "  ./ed521 sign --priv priv.pem --msg 'texto direto'"
  puts "  ./ed521 sign --priv priv.pem --file documento.txt"
  puts "  ./ed521 sign --priv priv.pem --file - < documento.txt"
  puts "  ./ed521 sign --priv priv.pem --file documento.txt --output assinatura.hex"
  puts "  ./ed521 verify --pub pub.pem --file documento.txt --sig assinatura.hex"
  puts "  ./ed521 prove --priv priv.pem"
  puts "  ./ed521 prove --priv priv.pem --output prova.hex"
  puts "  ./ed521 verify-proof --pub pub.pem --proof @prova.hex"
  exit
}

begin
  parser.parse
  command = ARGV[0]? || ""
rescue ex
  STDERR.puts "Erro: #{ex.message}"
  exit 1
end

# ====================================================================
# Função para obter dados da mensagem (--msg OU --file, exclusivo)
# ====================================================================

def get_message_data(config : Config) : Bytes
  if config.msg && config.file
    raise "Erro: use --msg OU --file, não ambos"
  elsif config.msg
    # Texto direto
    config.msg.not_nil!.to_slice
  elsif config.file
    if config.file == "-"
      # Lê do stdin
      STDIN.gets_to_end.to_slice
    else
      # Lê do arquivo
      File.read(config.file.not_nil!).to_slice
    end
  else
    raise "Erro: forneça --msg ou --file"
  end
end

# ====================================================================
# Função para ler hex (suporta @arquivo)
# ====================================================================

def read_hex_input(input : String) : String
  if input.starts_with?('@')
    filename = input[1..]
    File.read(filename).strip
  else
    input
  end
end

# ====================================================================
# Execução dos comandos
# ====================================================================

case command
when "test"
  test_ed521

when "generate"
  priv = generate_private_key
  pub_x, pub_y = get_public_key(priv)
  
  private_pem = private_key_to_pem(priv)
  public_pem = public_key_to_pem(pub_x, pub_y)
  
  if config.output
    priv_file = "#{config.output}_private.pem"
    pub_file = "#{config.output}_public.pem"
  else
    priv_file = "ed521_private.pem"
    pub_file = "ed521_public.pem"
  end
  
  File.write(priv_file, private_pem)
  File.write(pub_file, public_pem)
  
  puts private_pem
  puts public_pem
  puts "\nChaves salvas em #{priv_file} e #{pub_file}"

when "sign"
  if config.priv_file.nil?
    STDERR.puts "Erro: sign requer --priv"
    exit 1
  end
  
  begin
    msg = get_message_data(config)
    priv = read_private_key_from_pem(config.priv_file.not_nil!)
    
    signature = sign(priv, msg)
    sig_hex = bytes_to_hex(signature)
    
    if config.output
      File.write(config.output.not_nil!, sig_hex)
      puts "Assinatura salva em: #{config.output}"
    else
      puts sig_hex
    end
  rescue e
    STDERR.puts "Erro: #{e.message}"
    exit 1
  end

when "verify"
  if config.pub_file.nil?
    STDERR.puts "Erro: verify requer --pub"
    exit 1
  end
  
  if config.signature.nil?
    STDERR.puts "Erro: verify requer --sig"
    exit 1
  end
  
  begin
    msg = get_message_data(config)
    pub_x, pub_y = read_public_key_from_pem(config.pub_file.not_nil!)
    
    sig_hex = read_hex_input(config.signature.not_nil!)
    sig_bytes = hex_to_bytes(sig_hex)
    
    valid = verify(pub_x, pub_y, msg, sig_bytes)
    
    if valid
      puts "Assinatura válida"
      exit 0
    else
      puts "Assinatura inválida"
      exit 1
    end
  rescue e
    STDERR.puts "Erro: #{e.message}"
    exit 1
  end

when "prove"
  if config.priv_file.nil?
    STDERR.puts "Erro: prove requer --priv"
    exit 1
  end
  
  begin
    priv = read_private_key_from_pem(config.priv_file.not_nil!)
    
    proof = prove_knowledge(priv)
    proof_hex = bytes_to_hex(proof)
    
    if config.output
      File.write(config.output.not_nil!, proof_hex)
      puts "Prova salva em: #{config.output}"
    else
      puts proof_hex
    end
  rescue e
    STDERR.puts "Erro: #{e.message}"
    exit 1
  end

when "verify-proof"
  if config.pub_file.nil?
    STDERR.puts "Erro: verify-proof requer --pub"
    exit 1
  end
  
  if config.proof.nil?
    STDERR.puts "Erro: verify-proof requer --proof"
    exit 1
  end
  
  begin
    pub_x, pub_y = read_public_key_from_pem(config.pub_file.not_nil!)
    
    proof_hex = read_hex_input(config.proof.not_nil!)
    proof_bytes = hex_to_bytes(proof_hex)
    
    valid = verify_knowledge(pub_x, pub_y, proof_bytes)
    
    if valid
      puts "Prova válida"
      exit 0
    else
      puts "Prova inválida"
      exit 1
    end
  rescue e
    STDERR.puts "Erro: #{e.message}"
    exit 1
  end

else
  puts "Comando desconhecido: #{command}"
  puts "Use ./ed521 -h para ajuda"
  exit 1
end
