<?php

/**
 * Brazilian Ed521 Algorithm Implementation in Pure PHP using GMP
 * 
 * Implementation of the Brazilian Ed521 digital signature algorithm
 * based on Pure Edwards curves over prime fields.
 * 
 * @author Pedro F. Albanese <pedroalbanese@hotmail.com>
 * @copyright ALBANESE Research Lab
 * @license ISC
 * @version 1.0.1
 */

// ====================================================================
// E-521 Curve Parameters (Brazilian Standard)
// ====================================================================
define('P', '6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151');
define('N', '1716199415032652428745475199770348304317358825035826352348615864796385795849413675475876651663657849636693659065234142604319282948702542317993421293670108523');
define('D', '-376014');
define('Gx', '1571054894184995387535939749894317568645297350402905821437625181152304994381188529632591196067604100772673927915114267193389905003276673749012051148356041324');
define('Gy', '12');
define('BIT_SIZE', 521);
define('BYTE_LEN', 66); // (521 + 7) / 8 = 66 bytes

// ====================================================================
// Helper Functions for GMP
// ====================================================================

/**
 * Convert GMP number to hex string
 */
function gmp_dechex($num) {
    return gmp_strval($num, 16);
}

/**
 * Secure comparison for GMP (a == b)
 */
function gmp_eq($a, $b) {
    return gmp_cmp($a, $b) === 0;
}

/**
 * Secure comparison for GMP (a < b)
 */
function gmp_lt($a, $b) {
    return gmp_cmp($a, $b) < 0;
}

/**
 * Modular addition optimized for large numbers
 */
function gmp_addmod($a, $b, $mod) {
    $sum = gmp_add($a, $b);
    if (gmp_cmp($sum, $mod) >= 0) {
        $sum = gmp_sub($sum, $mod);
    }
    if (gmp_cmp($sum, gmp_init(0)) < 0) {
        $sum = gmp_add($sum, $mod);
    }
    return $sum;
}

/**
 * Modular subtraction optimized for large numbers
 */
function gmp_submod($a, $b, $mod) {
    $diff = gmp_sub($a, $b);
    if (gmp_cmp($diff, gmp_init(0)) < 0) {
        $diff = gmp_add($diff, $mod);
    }
    return gmp_mod($diff, $mod);
}

/**
 * Modular multiplication optimized for large numbers
 */
function gmp_mulmod($a, $b, $mod) {
    return gmp_mod(gmp_mul($a, $b), $mod);
}

/**
 * Modular exponentiation using GMP
 */
function gmp_powmod($base, $exp, $mod) {
    return gmp_powm($base, $exp, $mod);
}

/**
 * Modular multiplicative inverse using extended Euclidean algorithm
 */
function gmp_invmod($a, $mod) {
    if (gmp_cmp($a, gmp_init(0)) == 0) {
        return gmp_init(0);
    }
    
    $g = gmp_init(gmp_strval($mod));
    $x = gmp_init(0);
    $y = gmp_init(1);
    $u = gmp_init(1);
    $v = gmp_init(0);
    
    while (gmp_cmp($a, gmp_init(0)) != 0) {
        $q = gmp_div_q($g, $a);
        $r = gmp_mod($g, $a);
        
        $m = gmp_sub($x, gmp_mul($u, $q));
        $n = gmp_sub($y, gmp_mul($v, $q));
        
        $g = $a;
        $a = $r;
        $x = $u;
        $y = $v;
        $u = $m;
        $v = $n;
    }
    
    if (gmp_cmp($x, gmp_init(0)) < 0) {
        $x = gmp_add($x, $mod);
    }
    
    return $x;
}

// ====================================================================
// Byte Conversion Functions
// ====================================================================

/**
 * Convert little-endian bytes to integer using GMP
 */
function bytes_to_little_int($b) {
    $reversed_bytes = strrev($b);
    
    $result = gmp_init(0);
    $len = strlen($reversed_bytes);
    
    for ($i = 0; $i < $len; $i++) {
        $byte = ord($reversed_bytes[$i]);
        $power = gmp_pow(gmp_init(256), $len - 1 - $i);
        $result = gmp_add($result, gmp_mul(gmp_init($byte), $power));
    }
    
    return $result;
}

/**
 * Convert integer to little-endian bytes using GMP
 */
function little_int_to_bytes($n, $length) {
    if (gmp_cmp($n, gmp_init(0)) == 0) {
        $bytes_be = "\x00";
    } else {
        $bytes_be = '';
        $temp = $n;
        
        while (gmp_cmp($temp, gmp_init(0)) > 0) {
            $byte = gmp_intval(gmp_mod($temp, gmp_init(256)));
            $bytes_be = chr($byte) . $bytes_be; // Big-endian
            $temp = gmp_div_q($temp, gmp_init(256));
        }
    }
    
    // Preencher com zeros à esquerda se necessário
    if (strlen($bytes_be) < $length) {
        $bytes_be = str_repeat("\x00", $length - strlen($bytes_be)) . $bytes_be;
    }
    
    // Cortar se for maior
    if (strlen($bytes_be) > $length) {
        $bytes_be = substr($bytes_be, -$length);
    }
    
    // Inverter para little-endian
    $little_bytes = strrev($bytes_be);
    
    return $little_bytes;
}

/**
 * Generate cryptographically secure random bytes
 */
function random_bytes_bc($length) {
    if (function_exists('random_bytes')) {
        return random_bytes($length);
    }

    $bytes = '';
    for ($i = 0; $i < $length; $i++) {
        $bytes .= chr(random_int(0, 255));
    }

    return $bytes;
}

// ====================================================================
// SHAKE256 Implementation using GMP
// ====================================================================

// Check for GMP extension
if (!extension_loaded('gmp')) {
    die("GMP extension is required. Please install: sudo apt-get install php-gmp\n");
}

// Constants
define('SHAKE256_rate', 136); // 1088 bits = 136 bytes
$mask64 = gmp_init("18446744073709551615"); // 0xFFFFFFFFFFFFFFFF

// Helper function to convert hex to GMP
function hex2dec($hex) {
    $hex = str_replace('0x', '', $hex);
    return gmp_init($hex, 16);
}

// Helper functions for GMP bitwise operations
function gmp_not($x) {
    global $mask64;
    return gmp_xor($x, $mask64);
}

function gmp_shift_left($x, $bits) {
    return gmp_mul($x, gmp_pow(gmp_init(2), $bits));
}

function gmp_shift_right($x, $bits) {
    return gmp_div_q($x, gmp_pow(gmp_init(2), $bits));
}

// Round constants as hex strings (FIPS 202)
$RC_hex = [
    '0x0000000000000001', '0x0000000000008082',
    '0x800000000000808A', '0x8000000080008000',
    '0x000000000000808B', '0x0000000080000001',
    '0x8000000080008081', '0x8000000000008009',
    '0x000000000000008A', '0x0000000000000088',
    '0x0000000080008009', '0x000000008000000A',
    '0x000000008000808B', '0x800000000000008B',
    '0x8000000000008089', '0x8000000000008003',
    '0x8000000000008002', '0x8000000000000080',
    '0x000000000000800A', '0x800000008000000A',
    '0x8000000080008081', '0x8000000000008080',
    '0x0000000080000001', '0x8000000080008008'
];

// Convert to GMP
$RC = [];
foreach ($RC_hex as $hex) {
    $RC[] = hex2dec($hex);
}

// Rotation offsets
$rotc = [1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44];

// Pi indices
$piln = [10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1];

/**
 * Rotate left 64-bit GMP number
 */
function rotl64($x, $k) {
    global $mask64;
    $k = $k % 64;
    if ($k == 0) return $x;
    
    $x = gmp_and($x, $mask64);
    $left = gmp_and(gmp_shift_left($x, $k), $mask64);
    $right = gmp_and(gmp_shift_right($x, 64 - $k), $mask64);
    return gmp_or($left, $right);
}

/**
 * Keccak-f[1600] permutation using GMP
 */
function keccakF1600(&$state) {
    global $RC, $rotc, $piln, $mask64;
    
    for ($round = 0; $round < 24; $round++) {
        // θ step
        $c0 = gmp_xor($state[0], gmp_xor($state[5], gmp_xor($state[10], gmp_xor($state[15], $state[20]))));
        $c1 = gmp_xor($state[1], gmp_xor($state[6], gmp_xor($state[11], gmp_xor($state[16], $state[21]))));
        $c2 = gmp_xor($state[2], gmp_xor($state[7], gmp_xor($state[12], gmp_xor($state[17], $state[22]))));
        $c3 = gmp_xor($state[3], gmp_xor($state[8], gmp_xor($state[13], gmp_xor($state[18], $state[23]))));
        $c4 = gmp_xor($state[4], gmp_xor($state[9], gmp_xor($state[14], gmp_xor($state[19], $state[24]))));

        $d0 = gmp_xor(rotl64($c1, 1), $c4);
        $d1 = gmp_xor(rotl64($c2, 1), $c0);
        $d2 = gmp_xor(rotl64($c3, 1), $c1);
        $d3 = gmp_xor(rotl64($c4, 1), $c2);
        $d4 = gmp_xor(rotl64($c0, 1), $c3);

        // Apply θ to all lanes
        for ($i = 0; $i < 25; $i += 5) {
            $state[$i] = gmp_and(gmp_xor($state[$i], $d0), $mask64);
            $state[$i + 1] = gmp_and(gmp_xor($state[$i + 1], $d1), $mask64);
            $state[$i + 2] = gmp_and(gmp_xor($state[$i + 2], $d2), $mask64);
            $state[$i + 3] = gmp_and(gmp_xor($state[$i + 3], $d3), $mask64);
            $state[$i + 4] = gmp_and(gmp_xor($state[$i + 4], $d4), $mask64);
        }

        // ρ and π steps
        $b = array_fill(0, 25, gmp_init(0));
        $current = $state[1];
        
        for ($i = 0; $i < 24; $i++) {
            $b[$piln[$i]] = rotl64($current, $rotc[$i]);
            $current = $state[$piln[$i]];
        }
        $b[0] = $state[0];

        // χ step
        for ($y = 0; $y < 25; $y += 5) {
            $t0 = $b[$y];
            $t1 = $b[$y + 1];
            $t2 = $b[$y + 2];
            $t3 = $b[$y + 3];
            $t4 = $b[$y + 4];

            $not_t1 = gmp_not($t1);
            $not_t2 = gmp_not($t2);
            $not_t3 = gmp_not($t3);
            $not_t4 = gmp_not($t4);
            $not_t0 = gmp_not($t0);

            $state[$y] = gmp_and(gmp_xor($t0, gmp_and($not_t1, $t2)), $mask64);
            $state[$y + 1] = gmp_and(gmp_xor($t1, gmp_and($not_t2, $t3)), $mask64);
            $state[$y + 2] = gmp_and(gmp_xor($t2, gmp_and($not_t3, $t4)), $mask64);
            $state[$y + 3] = gmp_and(gmp_xor($t3, gmp_and($not_t4, $t0)), $mask64);
            $state[$y + 4] = gmp_and(gmp_xor($t4, gmp_and($not_t0, $t1)), $mask64);
        }

        // ι step
        $state[0] = gmp_and(gmp_xor($state[0], $RC[$round]), $mask64);
    }
}

// ===================================================================
// SHAKE256 implementation using GMP
// ===================================================================

/**
 * SHAKE256 hash function using GMP
 */
function shake256($input, $outputLength) {
    global $mask64;
    
    $rate = 136; // SHAKE256 rate in bytes
    $dsbyte = 0x1F; // SHAKE domain separator
    
    // Initialize state
    $state = array_fill(0, 25, gmp_init(0));
    $buffer = array_fill(0, $rate, 0);
    $bufPos = 0;
    
    $inputLen = strlen($input);
    $pos = 0;
    
    // Absorb phase
    while ($pos < $inputLen) {
        $toXor = min($rate - $bufPos, $inputLen - $pos);
        
        // XOR input into buffer
        for ($i = 0; $i < $toXor; $i++) {
            $buffer[$bufPos + $i] ^= ord($input[$pos + $i]);
        }
        
        $bufPos += $toXor;
        $pos += $toXor;
        
        // If buffer is full, absorb into state
        if ($bufPos == $rate) {
            // XOR buffer into state (little-endian)
            for ($i = 0; $i < $rate; $i += 8) {
                $word = gmp_init(0);
                for ($j = 0; $j < 8 && ($i + $j) < $rate; $j++) {
                    $byte = $buffer[$i + $j];
                    $word = gmp_add($word, gmp_mul(gmp_init($byte), gmp_pow(gmp_init(2), $j * 8)));
                }
                $state[$i / 8] = gmp_and(gmp_xor($state[$i / 8], $word), $mask64);
            }
            
            keccakF1600($state);
            $buffer = array_fill(0, $rate, 0);
            $bufPos = 0;
        }
    }
    
    // Padding
    $buffer[$bufPos] ^= $dsbyte;
    $buffer[$rate - 1] ^= 0x80;
    
    // XOR final block into state
    for ($i = 0; $i < $rate; $i += 8) {
        $word = gmp_init(0);
        for ($j = 0; $j < 8 && ($i + $j) < $rate; $j++) {
            $byte = $buffer[$i + $j];
            $word = gmp_add($word, gmp_mul(gmp_init($byte), gmp_pow(gmp_init(2), $j * 8)));
        }
        $state[$i / 8] = gmp_and(gmp_xor($state[$i / 8], $word), $mask64);
    }
    
    keccakF1600($state);
    
    // Squeeze phase
    $output = '';
    $bytesExtracted = 0;
    
    while ($bytesExtracted < $outputLength) {
        // Extract bytes from state
        for ($i = 0; $i < $rate && $bytesExtracted < $outputLength; $i++) {
            $lane = (int)($i / 8);
            $posInLane = $i % 8;
            
            // Extract byte from lane (little-endian)
            $shifted = gmp_div_q($state[$lane], gmp_pow(gmp_init(2), $posInLane * 8));
            $byte = gmp_intval(gmp_mod($shifted, gmp_init(256)));
            $output .= chr($byte);
            $bytesExtracted++;
        }
        
        if ($bytesExtracted < $outputLength) {
            keccakF1600($state);
        }
    }
    
    return $output;
}

// ====================================================================
// Elliptic Curve Point Operations using GMP
// ====================================================================

// Convert constants to GMP
$P_gmp = gmp_init(P);
$N_gmp = gmp_init(N);
$D_gmp = gmp_init(D);
$Gx_gmp = gmp_init(Gx);
$Gy_gmp = gmp_init(Gy);

/**
 * Verify if a point lies on the E-521 curve
 */
function is_on_curve($x, $y) {
    global $P_gmp, $D_gmp;
    
    $x2 = gmp_mulmod($x, $x, $P_gmp);
    $y2 = gmp_mulmod($y, $y, $P_gmp);
    $lhs = gmp_addmod($x2, $y2, $P_gmp);
    
    $d_pos = gmp_add($D_gmp, $P_gmp); // Make D positive
    $dx2y2 = gmp_mulmod($d_pos, gmp_mulmod($x2, $y2, $P_gmp), $P_gmp);
    $rhs = gmp_addmod(gmp_init(1), $dx2y2, $P_gmp);
    
    return gmp_eq($lhs, $rhs);
}

/**
 * Point addition on Twisted Edwards curve
 */
function add_points($x1, $y1, $x2, $y2) {
    global $P_gmp, $D_gmp;
    
    if (gmp_eq($x1, gmp_init(0)) && gmp_eq($y1, gmp_init(1))) {
        return [$x2, $y2];
    }
    if (gmp_eq($x2, gmp_init(0)) && gmp_eq($y2, gmp_init(1))) {
        return [$x1, $y1];
    }
    
    $x1y2 = gmp_mulmod($x1, $y2, $P_gmp);
    $y1x2 = gmp_mulmod($y1, $x2, $P_gmp);
    $numerator_x = gmp_addmod($x1y2, $y1x2, $P_gmp);
    
    $y1y2 = gmp_mulmod($y1, $y2, $P_gmp);
    $x1x2 = gmp_mulmod($x1, $x2, $P_gmp);
    $numerator_y = gmp_submod($y1y2, $x1x2, $P_gmp);
    
    $d_pos = gmp_add($D_gmp, $P_gmp);
    $dx1x2y1y2 = gmp_mulmod($d_pos, gmp_mulmod($x1x2, $y1y2, $P_gmp), $P_gmp);
    
    $denominator_x = gmp_addmod(gmp_init(1), $dx1x2y1y2, $P_gmp);
    $denominator_y = gmp_submod(gmp_init(1), $dx1x2y1y2, $P_gmp);
    
    $inv_den_x = gmp_invmod($denominator_x, $P_gmp);
    $inv_den_y = gmp_invmod($denominator_y, $P_gmp);
    
    $x3 = gmp_mulmod($numerator_x, $inv_den_x, $P_gmp);
    $y3 = gmp_mulmod($numerator_y, $inv_den_y, $P_gmp);
    
    return [$x3, $y3];
}

/**
 * Point doubling on Twisted Edwards curve
 */
function double_point($x, $y) {
    return add_points($x, $y, $x, $y);
}

/**
 * Scalar multiplication of a point (k * P)
 */
function scalar_mult($x, $y, $k_bytes) {
    global $N_gmp;
    
    $scalar = gmp_mod(bytes_to_little_int($k_bytes), $N_gmp);
    
    $result_x = gmp_init(0);
    $result_y = gmp_init(1);
    $temp_x = $x;
    $temp_y = $y;
    
    while (gmp_cmp($scalar, gmp_init(0)) > 0) {
        if (gmp_cmp(gmp_mod($scalar, gmp_init(2)), gmp_init(1)) == 0) {
            list($result_x, $result_y) = add_points($result_x, $result_y, $temp_x, $temp_y);
        }
        list($temp_x, $temp_y) = double_point($temp_x, $temp_y);
        $scalar = gmp_div_q($scalar, gmp_init(2));
    }
    
    return [$result_x, $result_y];
}

/**
 * Scalar multiplication of the base point (k * G)
 */
function scalar_base_mult($k_bytes) {
    global $Gx_gmp, $Gy_gmp;
    return scalar_mult($Gx_gmp, $Gy_gmp, $k_bytes);
}

// ====================================================================
// Point Compression/Decompression using GMP
// ====================================================================

/**
 * Compress point (RFC 8032 compliant)
 */
function compress_point($x, $y) {
    // Convert y to little-endian bytes
    $y_bytes = little_int_to_bytes($y, BYTE_LEN);
    
    // Get the least significant bit of x
    $x_lsb = gmp_intval(gmp_mod($x, gmp_init(2)));
    
    // Set the most significant bit of the last byte based on x_lsb
    $last_byte = ord($y_bytes[BYTE_LEN - 1]);
    if ($x_lsb == 1) {
        $last_byte |= 0x80; // Set MSB
    } else {
        $last_byte &= 0x7F; // Clear MSB
    }
    
    $y_bytes[BYTE_LEN - 1] = chr($last_byte);
    
    return $y_bytes;
}

/**
 * Decompress point (RFC 8032 compliant)
 */
function decompress_point($data) {
    global $P_gmp, $D_gmp;
    
    if (strlen($data) != BYTE_LEN) {
        return [null, null];
    }
    
    // Extract sign bit from MSB of last byte
    $last_byte = ord($data[BYTE_LEN - 1]);
    $sign_bit = ($last_byte >> 7) & 1;
    
    // Clear the sign bit to get y
    $y_bytes = $data;
    $y_bytes[BYTE_LEN - 1] = chr($last_byte & 0x7F);
    $y = bytes_to_little_int($y_bytes);
    
    // Verify y is in range
    if (gmp_cmp($y, $P_gmp) >= 0) {
        return [null, null];
    }
    
    // y² mod p
    $y2 = gmp_mulmod($y, $y, $P_gmp);
    
    // u = y² - 1
    $u = gmp_submod($y2, gmp_init(1), $P_gmp);
    
    // v = d*y² - 1
    $d_pos = gmp_add($D_gmp, $P_gmp);
    $v = gmp_submod(gmp_mulmod($d_pos, $y2, $P_gmp), gmp_init(1), $P_gmp);
    
    // v⁻¹ mod p
    $v_inv = gmp_invmod($v, $P_gmp);
    if (gmp_eq($v_inv, gmp_init(0))) {
        return [null, null];
    }
    
    // x² = u/v mod p
    $x2 = gmp_mulmod($u, $v_inv, $P_gmp);
    
    // x = x²^((p+1)/4) mod p (since p ≡ 3 mod 4)
    $exp = gmp_div_q(gmp_add($P_gmp, gmp_init(1)), gmp_init(4));
    $x = gmp_powmod($x2, $exp, $P_gmp);
    
    // Verify x² is correct
    $x2_check = gmp_mulmod($x, $x, $P_gmp);
    if (!gmp_eq($x2, $x2_check)) {
        // Try the other root
        $x = gmp_submod(gmp_init(0), $x, $P_gmp);
        $x2_check = gmp_mulmod($x, $x, $P_gmp);
        if (!gmp_eq($x2, $x2_check)) {
            return [null, null];
        }
    }
    
    // Check the sign bit
    $x_lsb = gmp_intval(gmp_mod($x, gmp_init(2)));
    if ($x_lsb != $sign_bit) {
        $x = gmp_submod(gmp_init(0), $x, $P_gmp);
    }
    
    // Verify the point is on the curve
    if (!is_on_curve($x, $y)) {
        return [null, null];
    }
    
    return [$x, $y];
}

// ====================================================================
// Hash Functions using GMP
// ====================================================================

/**
 * Implement dom5 as per specification
 */
function dom5($phflag, $context) {
    if (strlen($context) > 255) {
        throw new Exception("context too long for dom5");
    }
    
    $dom = "SigEd521" . chr($phflag) . chr(strlen($context)) . $context;
    return $dom;
}

/**
 * Hash function H(x) = SHAKE256(dom5(phflag,context)||x, 132)
 */
function hash_e521($phflag, $context, $x) {
    $dom = dom5($phflag, $context);
    $hash_input = $dom . $x;
    return shake256($hash_input, 132);
}

// ====================================================================
// Key Generation and Signing Functions using GMP
// ====================================================================

/**
 * Generate random private key
 */
function generate_private_key() {
    global $N_gmp;
    
    while (true) {
        $priv_bytes = random_bytes_bc(BYTE_LEN);
        $a = bytes_to_little_int($priv_bytes);
        if (gmp_lt($a, $N_gmp)) {
            return $a;
        }
    }
}

/**
 * Calculate public key A = a * G
 */
function get_public_key($priv) {
    $priv_bytes = little_int_to_bytes($priv, BYTE_LEN);
    return scalar_base_mult($priv_bytes);
}

/**
 * Create PureEdDSA signature
 */
function sign($priv, $message) {
    global $N_gmp;
    $byte_len = BYTE_LEN;
    
    // Hash the private key
    $prefix = hash_e521(0x00, '', little_int_to_bytes($priv, $byte_len));
    
    // Calculate r
    $r_bytes = hash_e521(0x00, '', $prefix . $message);
    $r = gmp_mod(bytes_to_little_int(substr($r_bytes, 0, $byte_len)), $N_gmp);
    
    // Compute R = r*G
    list($Rx, $Ry) = scalar_base_mult(little_int_to_bytes($r, $byte_len));
    $R_compressed = compress_point($Rx, $Ry);
    
    // Get public key
    list($Ax, $Ay) = get_public_key($priv);
    $A_compressed = compress_point($Ax, $Ay);
    
    // Compute h
    $hram_input = $R_compressed . $A_compressed . $message;
    $hram_hash = hash_e521(0x00, '', $hram_input);
    $h = gmp_mod(bytes_to_little_int(substr($hram_hash, 0, $byte_len)), $N_gmp);
    
    // Compute s
    $s = gmp_mod(gmp_add($r, gmp_mul($h, $priv)), $N_gmp);
    
    // Signature = R || s
    $s_bytes = little_int_to_bytes($s, $byte_len);
    $signature = $R_compressed . $s_bytes;
    
    return $signature;
}

/**
 * Verify PureEdDSA signature
 */
function verify($pub_x, $pub_y, $message, $signature) {
    global $N_gmp;
    $byte_len = BYTE_LEN;
    
    if (strlen($signature) != 2 * $byte_len) {
        return false;
    }
    
    $R_compressed = substr($signature, 0, $byte_len);
    $s_bytes = substr($signature, $byte_len);
    
    // Decompress R
    list($Rx, $Ry) = decompress_point($R_compressed);
    if ($Rx === null || $Ry === null) {
        return false;
    }
    
    // Verify s is in range
    $s = bytes_to_little_int($s_bytes);
    if (gmp_cmp($s, $N_gmp) >= 0) {
        return false;
    }
    
    // Compress public key
    $A_compressed = compress_point($pub_x, $pub_y);
    
    // Compute h
    $hram_input = $R_compressed . $A_compressed . $message;
    $hram_hash = hash_e521(0x00, '', $hram_input);
    $h = gmp_mod(bytes_to_little_int(substr($hram_hash, 0, $byte_len)), $N_gmp);
    
    // Compute s*G
    list($sGx, $sGy) = scalar_base_mult(little_int_to_bytes($s, $byte_len));
    
    // Compute h*A
    list($hAx, $hAy) = scalar_mult($pub_x, $pub_y, little_int_to_bytes($h, $byte_len));
    
    // Compute R + h*A
    list($rhaX, $rhaY) = add_points($Rx, $Ry, $hAx, $hAy);
    
    // Compare s*G with R + h*A
    return gmp_eq($sGx, $rhaX) && gmp_eq($sGy, $rhaY);
}

// ====================================================================
// Test Functions
// ====================================================================

/**
 * Test with fixed private key
 */
function test_with_fixed_key() {
    echo "=== Teste com Chave Fixa (Compatibilidade PHP-Python) ===\n";
    
    // Chave privada fixa (mesma do Python)
    $priv_fixed_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041";
    
    // Converter hex para bytes
    $priv_bytes = hex2bin($priv_fixed_hex);
    
    // Converter para GMP integer
    $priv = bytes_to_little_int($priv_bytes);
    
    echo "Chave privada fixa (hex): " . substr($priv_fixed_hex, 0, 32) . "...\n";
    echo "Chave privada (decimal): " . gmp_strval($priv) . "\n";
    echo "Chave privada < N: " . (gmp_lt($priv, gmp_init(N)) ? "SIM" : "NÃO") . "\n";
    
    // Calcula chave pública
    list($pub_x, $pub_y) = get_public_key($priv);
    echo "\nChave pública gerada:\n";
    echo "  x (hex primeiros 30 chars): " . substr(gmp_dechex($pub_x), 0, 30) . "...\n";
    echo "  y (hex primeiros 30 chars): " . substr(gmp_dechex($pub_y), 0, 30) . "...\n";
    echo "Ponto na curva: " . (is_on_curve($pub_x, $pub_y) ? "SIM" : "NÃO") . "\n";
    
    // Testa compressão/descompressão
    $compressed = compress_point($pub_x, $pub_y);
    echo "\nChave pública comprimida: " . strlen($compressed) . " bytes\n";
    echo "Comprimida (hex primeiros 32 bytes): " . bin2hex(substr($compressed, 0, 32)) . "...\n";
    
    list($decomp_x, $decomp_y) = decompress_point($compressed);
    $decomp_correct = gmp_eq($decomp_x, $pub_x) && gmp_eq($decomp_y, $pub_y);
    echo "Descompressão correta: " . ($decomp_correct ? "SIM" : "NÃO") . "\n";
    
    // Assina mensagem
    $message = "Test message for E-521 compatibility between PHP and Python";
    echo "\nMensagem: $message\n";
    echo "Tamanho mensagem: " . strlen($message) . " bytes\n";
    
    $signature = sign($priv, $message);
    echo "\nAssinatura criada: " . strlen($signature) . " bytes\n";
    echo "R (primeiros 32 bytes): " . bin2hex(substr($signature, 0, 32)) . "...\n";
    echo "s (primeiros 32 bytes): " . bin2hex(substr($signature, BYTE_LEN, 32)) . "...\n";
    
    // Verifica assinatura
    $valid = verify($pub_x, $pub_y, $message, $signature);
    echo "\nAssinatura válida: " . ($valid ? "SIM" : "NÃO") . "\n";
    
    // Verifica mensagem errada
    $wrong_valid = verify($pub_x, $pub_y, "Mensagem errada", $signature);
    echo "Mensagem errada rejeitada: " . (!$wrong_valid ? "SIM" : "NÃO") . "\n";
    
    echo "\n=== Testes concluídos ===\n";
}

/**
 * Debug function para testar conversões
 */
function debug_conversions() {
    echo "=== Debug de Conversões ===\n";
    
    $test_hex = "000102030405060708090a0b0c0d0e0f";
    $test_bytes = hex2bin($test_hex);
    
    echo "Test bytes: " . bin2hex($test_bytes) . "\n";
    echo "Python reversed: " . bin2hex(strrev($test_bytes)) . "\n";
    
    // Test PHP's bytes_to_little_int
    $result_php = bytes_to_little_int($test_bytes);
    echo "PHP bytes_to_little_int: " . gmp_strval($result_php) . "\n";
    
    // What Python should give (0x0f0e0d0c0b0a09080706050403020100 as big-endian)
    $expected_python = "5233100606242806050955395731361295"; // 0x0f0e0d0c0b0a09080706050403020100 em decimal
    echo "Python expected: $expected_python\n";
    echo "Iguais: " . (gmp_eq($result_php, gmp_init($expected_python)) ? "SIM" : "NÃO") . "\n";
    
    // Test with 0x0100 (little-endian: 0x00 0x01)
    echo "\nTest 0x0100 (little-endian):\n";
    $two_bytes = "\x00\x01"; // Em little-endian, 0x0100 = 256
    $two_int = bytes_to_little_int($two_bytes);
    echo "Bytes: " . bin2hex($two_bytes) . "\n";
    echo "Convertido: " . gmp_strval($two_int) . " (deveria ser 256)\n";
    
    // Test little_int_to_bytes
    echo "\nTest little_int_to_bytes(256, 2):\n";
    $back_bytes = little_int_to_bytes(gmp_init(256), 2);
    echo "Resultado: " . bin2hex($back_bytes) . " (deveria ser 0001 em little-endian)\n";
    
    // Test com a chave privada real
    echo "\nTest com chave privada real:\n";
    $priv_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041";
    $priv_bytes = hex2bin($priv_hex);
    $priv_int = bytes_to_little_int($priv_bytes);
    echo "Primeiros 50 chars: " . substr(gmp_strval($priv_int), 0, 50) . "...\n";
    echo "Esperado Python: 22396733597281975937350377627110805738449863045083...\n";
}

// ====================================================================
// CURUPIRA BLOCK CIPHER IMPLEMENTATION (EXATLY LIKE PYTHON)
// ====================================================================

class KeySizeError extends Exception {
    public function __construct($size) {
        parent::__construct("curupira1: invalid key size $size");
    }
}

class Curupira1 {
    const BLOCK_SIZE = 12;
    
    private $key;
    private $key_size;
    private $R;
    private $t;
    private $key_bits;
    private $encryption_round_keys;
    private $decryption_round_keys;
    private $xtimes_table;
    private $sbox_table;
    
    public function __construct($key) {
        $this->key = $key;
        $this->key_size = strlen($key);
        
        if ($this->key_size != 12 && $this->key_size != 18 && $this->key_size != 24) {
            throw new KeySizeError($this->key_size);
        }
        
        $this->_init_xtimes_table();
        $this->_init_sbox_table();
        $this->_expand_key();
    }
    
    private function _init_xtimes_table() {
        $this->xtimes_table = array_fill(0, 256, 0);
        for ($u = 0; $u < 256; $u++) {
            $d = $u << 1;
            if ($d >= 0x100) {
                $d = $d ^ 0x14D;
            }
            $this->xtimes_table[$u] = $d & 0xFF;
        }
    }
    
    private function _init_sbox_table() {
        $P = [0x3, 0xF, 0xE, 0x0, 0x5, 0x4, 0xB, 0xC,
              0xD, 0xA, 0x9, 0x6, 0x7, 0x8, 0x2, 0x1];
        $Q = [0x9, 0xE, 0x5, 0x6, 0xA, 0x2, 0x3, 0xC,
              0xF, 0x0, 0x4, 0xD, 0x7, 0xB, 0x1, 0x8];
        
        $this->sbox_table = array_fill(0, 256, 0);
        
        for ($u = 0; $u < 256; $u++) {
            $uh1 = $P[($u >> 4) & 0xF];
            $ul1 = $Q[$u & 0xF];
            $uh2 = $Q[(($uh1 & 0xC) ^ (($ul1 >> 2) & 0x3)) & 0xF];
            $ul2 = $P[((($uh1 << 2) & 0xC) ^ ($ul1 & 0x3)) & 0xF];
            $uh1 = $P[(($uh2 & 0xC) ^ (($ul2 >> 2) & 0x3)) & 0xF];
            $ul1 = $Q[((($uh2 << 2) & 0xC) ^ ($ul2 & 0x3)) & 0xF];
            
            $this->sbox_table[$u] = (($uh1 << 4) ^ $ul1) & 0xFF;
        }
    }
    
    public function xtimes($u) {
        return $this->xtimes_table[$u & 0xFF];
    }
    
    public function ctimes($u) {
        return $this->xtimes(
            $this->xtimes(
                $this->xtimes(
                    $this->xtimes($u) ^ $u
                ) ^ $u
            )
        );
    }
    
    public function sbox($u) {
        return $this->sbox_table[$u & 0xFF];
    }
    
    private function _dtimesa($a, $j, &$b) {
        $d = 3 * $j;
        $v = $this->xtimes($a[0 + $d] ^ $a[1 + $d] ^ $a[2 + $d]);
        $w = $this->xtimes($v);
        
        $b[0 + $d] = $a[0 + $d] ^ $v;
        $b[1 + $d] = $a[1 + $d] ^ $w;
        $b[2 + $d] = $a[2 + $d] ^ $v ^ $w;
    }
    
    private function _etimesa($a, $j, &$b, $e) {
        $d = 3 * $j;
        $v = $a[0 + $d] ^ $a[1 + $d] ^ $a[2 + $d];
        
        if ($e) {
            $v = $this->ctimes($v);
        } else {
            $v = $this->ctimes($v) ^ $v;
        }
        
        $b[0 + $d] = $a[0 + $d] ^ $v;
        $b[1 + $d] = $a[1 + $d] ^ $v;
        $b[2 + $d] = $a[2 + $d] ^ $v;
    }
    
    private function _apply_nonlinear_layer($a) {
        $result = [];
        foreach ($a as $x) {
            $result[] = $this->sbox($x);
        }
        return $result;
    }
    
    private function _apply_permutation_layer($a) {
        $b = array_fill(0, 12, 0);
        
        for ($i = 0; $i < 3; $i++) {
            for ($j = 0; $j < 4; $j++) {
                $b[$i + 3 * $j] = $a[$i + 3 * ($i ^ $j)];
            }
        }
        
        return $b;
    }
    
    private function _apply_linear_diffusion_layer($a) {
        $b = array_fill(0, 12, 0);
        
        for ($j = 0; $j < 4; $j++) {
            $this->_dtimesa($a, $j, $b);
        }
        
        return $b;
    }
    
    private function _apply_key_addition($a, $kr) {
        $result = [];
        for ($i = 0; $i < 12; $i++) {
            $result[] = $a[$i] ^ $kr[$i];
        }
        return $result;
    }
    
    private function _calculate_schedule_constant($s, $key_bits) {
        $t = (int)($key_bits / 48);
        $q = array_fill(0, 3 * 2 * $t, 0);
        
        if ($s == 0) {
            return $q;
        }
        
        for ($j = 0; $j < 2 * $t; $j++) {
            $q[3 * $j] = $this->sbox(2 * $t * ($s - 1) + $j);
        }
        
        return $q;
    }
    
    private function _apply_constant_addition($Kr, $subkey_rank, $key_bits, $t) {
        $b = $Kr;
        $q = $this->_calculate_schedule_constant($subkey_rank, $key_bits);
        
        for ($i = 0; $i < 3; $i++) {
            for ($j = 0; $j < 2 * $t; $j++) {
                $idx = $i + 3 * $j;
                $b[$idx] ^= $q[$idx];
            }
        }
        
        return $b;
    }
    
    private function _apply_cyclic_shift($a, $t) {
        $length = 3 * 2 * $t;
        $b = array_fill(0, $length, 0);
        
        for ($j = 0; $j < 2 * $t; $j++) {
            $b[3 * $j] = $a[3 * $j];
            $b[1 + 3 * $j] = $a[1 + 3 * (($j + 1) % (2 * $t))];
            
            if ($j > 0) {
                $b[2 + 3 * $j] = $a[2 + 3 * (($j - 1) % (2 * $t))];
            } else {
                $b[2] = $a[2 + 3 * (2 * $t - 1)];
            }
        }
        
        return $b;
    }
    
    private function _apply_linear_diffusion($a, $t) {
        $length = 3 * 2 * $t;
        $b = array_fill(0, $length, 0);
        
        for ($j = 0; $j < 2 * $t; $j++) {
            $this->_etimesa($a, $j, $b, true);
        }
        
        return $b;
    }
    
    private function _calculate_next_subkey($Kr, $subkey_rank, $key_bits, $t) {
        return $this->_apply_linear_diffusion(
            $this->_apply_cyclic_shift(
                $this->_apply_constant_addition($Kr, $subkey_rank, $key_bits, $t),
                $t
            ),
            $t
        );
    }
    
    private function _select_round_key($Kr) {
        $kr = array_fill(0, 12, 0);
        
        for ($j = 0; $j < 4; $j++) {
            $kr[3 * $j] = $this->sbox($Kr[3 * $j]);
        }
        
        for ($i = 1; $i < 3; $i++) {
            for ($j = 0; $j < 4; $j++) {
                $kr[$i + 3 * $j] = $Kr[$i + 3 * $j];
            }
        }
        
        return $kr;
    }
    
    private function _expand_key() {
        $key_bits = $this->key_size * 8;
        
        if ($key_bits == 96) {
            $this->R = 10;
        } elseif ($key_bits == 144) {
            $this->R = 14;
        } elseif ($key_bits == 192) {
            $this->R = 18;
        }
        
        $this->key_bits = $key_bits;
        $this->t = (int)($key_bits / 48);
        
        $Kr = array_values(unpack('C*', $this->key));
        
        $this->encryption_round_keys = array_fill(0, $this->R + 1, null);
        $this->decryption_round_keys = array_fill(0, $this->R + 1, null);
        
        $kr = $this->_select_round_key($Kr);
        $this->encryption_round_keys[0] = $kr;
        
        for ($r = 1; $r <= $this->R; $r++) {
            $Kr = $this->_calculate_next_subkey($Kr, $r, $this->key_bits, $this->t);
            $kr = $this->_select_round_key($Kr);
            
            $this->encryption_round_keys[$r] = $kr;
            $this->decryption_round_keys[$this->R - $r] = $this->_apply_linear_diffusion_layer($kr);
        }
        
        $this->decryption_round_keys[0] = $this->encryption_round_keys[$this->R];
        $this->decryption_round_keys[$this->R] = $this->encryption_round_keys[0];
    }
    
    private function _perform_whitening_round($a, $k0) {
        return $this->_apply_key_addition($a, $k0);
    }
    
    private function _perform_last_round($a, $kR) {
        return $this->_apply_key_addition(
            $this->_apply_permutation_layer(
                $this->_apply_nonlinear_layer($a)
            ),
            $kR
        );
    }
    
    private function _perform_round($a, $kr) {
        return $this->_apply_key_addition(
            $this->_apply_linear_diffusion_layer(
                $this->_apply_permutation_layer(
                    $this->_apply_nonlinear_layer($a)
                )
            ),
            $kr
        );
    }
    
    private function _process_block($data, $round_keys) {
        $tmp = array_values(unpack('C*', $data));
        $tmp = $this->_perform_whitening_round($tmp, $round_keys[0]);
        
        for ($r = 1; $r < $this->R; $r++) {
            $tmp = $this->_perform_round($tmp, $round_keys[$r]);
        }
        
        $tmp = $this->_perform_last_round($tmp, $round_keys[$this->R]);
        return pack('C*', ...$tmp);
    }
    
    public function encrypt($plaintext) {
        if (strlen($plaintext) != self::BLOCK_SIZE) {
            throw new Exception("Plaintext must be " . self::BLOCK_SIZE . " bytes");
        }
        return $this->_process_block($plaintext, $this->encryption_round_keys);
    }
    
    public function decrypt($ciphertext) {
        if (strlen($ciphertext) != self::BLOCK_SIZE) {
            throw new Exception("Ciphertext must be " . self::BLOCK_SIZE . " bytes");
        }
        return $this->_process_block($ciphertext, $this->decryption_round_keys);
    }
    
    public function sct($data) {
        if (strlen($data) != self::BLOCK_SIZE) {
            throw new Exception("Data must be " . self::BLOCK_SIZE . " bytes");
        }
        
        $tmp = array_values(unpack('C*', $data));
        
        $unkeyed_round = function($a) {
            return $this->_apply_linear_diffusion_layer(
                $this->_apply_permutation_layer(
                    $this->_apply_nonlinear_layer($a)
                )
            );
        };
        
        $tmp = $unkeyed_round($tmp);
        for ($i = 0; $i < 3; $i++) {
            $tmp = $unkeyed_round($tmp);
        }
        
        return pack('C*', ...$tmp);
    }
    
    public function BlockSize() {
        return self::BLOCK_SIZE;
    }
}

// ====================================================================
// CURUPIRA CBC MODE IMPLEMENTATION
// ====================================================================

/**
 * Pad data using PKCS#7 padding
 */
function pad_pkcs7($data, $block_size) {
    $padding_len = $block_size - (strlen($data) % $block_size);
    if ($padding_len == 0) {
        $padding_len = $block_size;
    }
    return $data . str_repeat(chr($padding_len), $padding_len);
}

/**
 * Remove PKCS#7 padding
 */
function unpad_pkcs7($data) {
    if (strlen($data) == 0) {
        throw new Exception("Empty data");
    }
    
    $padding_len = ord($data[strlen($data) - 1]);
    if ($padding_len > strlen($data)) {
        throw new Exception("Invalid padding length");
    }
    
    // Verify padding bytes
    for ($i = 0; $i < $padding_len; $i++) {
        if (ord($data[strlen($data) - $i - 1]) != $padding_len) {
            throw new Exception("Invalid padding bytes");
        }
    }
    
    return substr($data, 0, -$padding_len);
}

/**
 * Encrypt using Curupira in CBC mode
 */
function cbc_encrypt_curupira($key, $iv, $plaintext) {
    $cipher = new Curupira1($key);
    $block_size = $cipher->BlockSize();
    
    // Pad plaintext
    $padded_data = pad_pkcs7($plaintext, $block_size);
    
    // CBC encryption
    $ciphertext = '';
    $prev_block = $iv;
    
    for ($i = 0; $i < strlen($padded_data); $i += $block_size) {
        $block = substr($padded_data, $i, $block_size);
        
        // XOR with previous ciphertext (or IV for first block)
        $xored_block = '';
        for ($j = 0; $j < $block_size; $j++) {
            $xored_block .= chr(ord($block[$j]) ^ ord($prev_block[$j]));
        }
        
        // Encrypt with Curupira
        $encrypted_block = $cipher->encrypt($xored_block);
        $ciphertext .= $encrypted_block;
        $prev_block = $encrypted_block;
    }
    
    return $ciphertext;
}

/**
 * Decrypt using Curupira in CBC mode
 */
function cbc_decrypt_curupira($key, $iv, $ciphertext) {
    $cipher = new Curupira1($key);
    $block_size = $cipher->BlockSize();
    
    if (strlen($ciphertext) % $block_size != 0) {
        throw new Exception("Ciphertext length must be multiple of block size");
    }
    
    // CBC decryption
    $plaintext = '';
    $prev_block = $iv;
    
    for ($i = 0; $i < strlen($ciphertext); $i += $block_size) {
        $encrypted_block = substr($ciphertext, $i, $block_size);
        
        // Decrypt with Curupira
        $decrypted_block = $cipher->decrypt($encrypted_block);
        
        // XOR with previous ciphertext (or IV for first block)
        $plain_block = '';
        for ($j = 0; $j < $block_size; $j++) {
            $plain_block .= chr(ord($decrypted_block[$j]) ^ ord($prev_block[$j]));
        }
        
        $plaintext .= $plain_block;
        $prev_block = $encrypted_block;
    }
    
    // Remove padding
    return unpad_pkcs7($plaintext);
}

// ====================================================================
// RFC 1423 ENCRYPTION WITH CURUPIRA-192-CBC
// ====================================================================

/**
 * Derive key according to RFC 1423 section 1.1 (PBKDF1-like)
 * Uses MD5 iteratively: D_i = MD5(D_{i-1} || P || S)
 */
function rfc1423_derive_key_md5($password, $salt, $key_size) {
    // Use first 8 bytes of salt for key derivation (as per RFC 1423)
    $iv_salt = substr($salt, 0, 8);
    
    // RFC 1423 uses MD5 iteratively
    $d = '';
    $result = '';
    
    while (strlen($result) < $key_size) {
        $d = md5($d . $password . $iv_salt, true);
        $result .= $d;
    }
    
    return substr($result, 0, $key_size);
}

/**
 * Encrypt private key data using RFC 1423 format with Curupira-192-CBC
 */
function encrypt_private_key_pem($data, $password, $cipher_name = "CURUPIRA-192-CBC") {
    if ($cipher_name != "CURUPIRA-192-CBC") {
        throw new Exception("Unsupported cipher: $cipher_name");
    }
    
    // Generate random IV (12 bytes for Curupira)
    $iv = random_bytes_bc(12);
    
    // Derive key using RFC 1423 method (192-bit = 24 bytes)
    $key = rfc1423_derive_key_md5($password, $iv, 24);
    
    // Encrypt data with Curupira-192-CBC
    $encrypted_data = cbc_encrypt_curupira($key, $iv, $data);
    
    // Combine IV and encrypted data
    $full_data = $encrypted_data;
    
    // Encode as base64
    $b64_data = base64_encode($full_data);
    
    // Format as PEM with RFC 1423 headers
    $lines = [];
    $lines[] = "Proc-Type: 4,ENCRYPTED";
    $lines[] = "DEK-Info: $cipher_name," . bin2hex($iv);
    $lines[] = "";
    
    // Split base64 into 64-character lines
    $lines = array_merge($lines, str_split($b64_data, 64));
    
    return implode("\n", $lines);
}

/**
 * Decrypt RFC 1423 formatted private key data
 */
function decrypt_private_key_pem($pem_data, $password) {
    $lines = explode("\n", trim($pem_data));
    
    // Parse headers
    $proc_type = null;
    $dek_info = null;
    $b64_lines = [];
    
    $in_headers = true;
    foreach ($lines as $line) {
        $line = trim($line);
        if (empty($line)) {
            if ($in_headers) {
                $in_headers = false;
            }
            continue;
        }
        
        if (strpos($line, "-----") === 0) {
            continue;
        }
        
        if ($in_headers) {
            if (strpos($line, "Proc-Type:") === 0) {
                $proc_type = trim(substr($line, 10));
                if ($proc_type != "4,ENCRYPTED") {
                    throw new Exception("Not an encrypted PEM block");
                }
            } elseif (strpos($line, "DEK-Info:") === 0) {
                $dek_info = trim(substr($line, 10));
            }
        } else {
            $b64_lines[] = $line;
        }
    }
    
    if (!$dek_info) {
        throw new Exception("Missing DEK-Info header");
    }
    
    // Parse DEK-Info
    $dek_parts = explode(",", $dek_info, 2);
    if (count($dek_parts) != 2) {
        throw new Exception("Invalid DEK-Info format: $dek_info");
    }
    
    $cipher_name = trim($dek_parts[0]);
    $iv_hex = trim($dek_parts[1]);
    
    if ($cipher_name != "CURUPIRA-192-CBC") {
        throw new Exception("Unsupported cipher: $cipher_name");
    }
    
    $iv = hex2bin($iv_hex);
    if (!$iv || strlen($iv) != 12) {
        throw new Exception("Invalid IV length");
    }
    
    // Decode base64 data
    $b64_data = implode("", $b64_lines);
    $encrypted_data = base64_decode($b64_data);
    
    // Note: IV is NOT included in the encrypted data (only in header)
    $ciphertext = $encrypted_data;
    
    // Derive key
    $key = rfc1423_derive_key_md5($password, $iv, 24);
    
    try {
        // Decrypt data with Curupira-192-CBC
        $decrypted_data = cbc_decrypt_curupira($key, $iv, $ciphertext);
        
        return $decrypted_data;
    } catch (Exception $e) {
        throw new Exception("Decryption failed (wrong password?): " . $e->getMessage());
    }
}

/**
 * Convert Ed521 private key to PEM PKCS8 with optional encryption
 * Follows Python implementation exactly
 */
function ed521_private_to_pem_pkcs8($private_key_int, $password = null) {
    $private_bytes = little_int_to_bytes($private_key_int, 66);

    // ED521 OID: 1.3.6.1.4.1.44588.2.1
    $encoded_oid = "\x2b\x06\x01\x04\x01\x82\xdc\x2c\x02\x01";
    $oid_der = "\x06\x0a" . $encoded_oid;
    $algorithm_id = "\x30\x0e" . $oid_der . "\x05\x00"; // SEQUENCE (14 bytes)

    $version = "\x02\x01\x00"; // INTEGER version = 0

    // Private key as OCTET STRING (tag 0x04)
    $priv_field = "\x04\x42" . $private_bytes; // OCTET STRING tag (0x04), length 66 (0x42)

    $content = $version . $algorithm_id . $priv_field;
    $content_length = strlen($content);
    
    // Usar comprimento correto para SEQUENCE
    if ($content_length <= 127) {
        $seq = "\x30" . chr($content_length) . $content;
    } else {
        // Comprimento longo (2 bytes)
        $seq = "\x30\x81" . chr($content_length) . $content;
    }
    
    if ($password) {
        // Encrypt using RFC 1423 with Curupira-192-CBC
        $encrypted_pem = encrypt_private_key_pem($seq, $password, "CURUPIRA-192-CBC");
        return "-----BEGIN E-521 PRIVATE KEY-----\n" . $encrypted_pem . "\n-----END E-521 PRIVATE KEY-----\n";
    } else {
        $b64 = base64_encode($seq);
        $lines = str_split($b64, 64);
        return "-----BEGIN E-521 PRIVATE KEY-----\n" . implode("\n", $lines) . "\n-----END E-521 PRIVATE KEY-----\n";
    }
}

/**
 * Convert Ed521 public key to PEM SPKI
 * Follows Python implementation exactly
 */
function ed521_public_to_pem($public_key_x, $public_key_y) {
    // ED521 OID: 1.3.6.1.4.1.44588.2.1
    $encoded_oid = "\x2b\x06\x01\x04\x01\x82\xdc\x2c\x02\x01";
    $oid_der = "\x06\x0a" . $encoded_oid;
    $algorithm_id = "\x30\x0e" . $oid_der . "\x05\x00";

    $compressed_pub = compress_point($public_key_x, $public_key_y);
    
    $bit_string_data = "\x00" . $compressed_pub;
    $bit_string_len = strlen($bit_string_data);
    
    if ($bit_string_len < 128) {
        $bit_string_header = "\x03" . chr($bit_string_len);
    } else {
        $len_bytes = little_int_to_bytes(gmp_init($bit_string_len), 
            (int)ceil(log($bit_string_len, 256)));
        $bit_string_header = "\x03" . chr(0x80 | strlen($len_bytes)) . strrev($len_bytes);
    }
    
    $bit_string = $bit_string_header . $bit_string_data;
    
    $content = $algorithm_id . $bit_string;
    $content_len = strlen($content);
    
    if ($content_len < 128) {
        $seq_len = chr($content_len);
    } else {
        $len_bytes = little_int_to_bytes(gmp_init($content_len), 
            (int)ceil(log($content_len, 256)));
        $seq_len = chr(0x80 | strlen($len_bytes)) . strrev($len_bytes);
    }
    
    $subject_pub_key_info = "\x30" . $seq_len . $content;
    
    $b64_key = base64_encode($subject_pub_key_info);
    $lines = str_split($b64_key, 64);
    
    return "-----BEGIN E-521 PUBLIC KEY-----\n" .
           implode("\n", $lines) . "\n" .
           "-----END E-521 PUBLIC KEY-----\n";
}

/**
 * Parse Ed521 private key from PEM PKCS8 format
 * Follows Python implementation exactly
 */
function parse_ed521_pem_private_key($pem_data, $debug = false) {
    // Extract base64 data from PEM
    $pem_data = trim($pem_data);
    $pem_data = preg_replace('/-----(BEGIN|END).*?-----/', '', $pem_data);
    $pem_data = str_replace(["\r", "\n", " "], '', $pem_data);
    
    $der = base64_decode($pem_data);
    
    if ($debug) {
        echo "DER length: " . strlen($der) . " bytes\n";
        echo "DER hex: " . bin2hex($der) . "\n";
    }
    
    $offset = 0;
    
    // SEQUENCE
    if ($der[$offset] !== "\x30") {
        throw new Exception("Expected SEQUENCE");
    }
    $offset++;
    
    // Skip length
    $len = ord($der[$offset]);
    $offset++;
    if ($len & 0x80) {
        $len_len = $len & 0x7F;
        $offset += $len_len;
    }
    
    // Version (INTEGER 0)
    if ($der[$offset] !== "\x02" || $der[$offset+1] !== "\x01" || $der[$offset+2] !== "\x00") {
        throw new Exception("Invalid version");
    }
    $offset += 3;
    
    // AlgorithmIdentifier (SEQUENCE)
    if ($der[$offset] !== "\x30") {
        throw new Exception("Expected AlgorithmIdentifier");
    }
    $offset++;
    
    $alg_len = ord($der[$offset]);
    $offset++;
    $offset += $alg_len; // Skip algorithm identifier
    
    // PrivateKey (OCTET STRING - tag 0x04)
    if ($der[$offset] !== "\x04") {
        // Tentar tag antiga 0x84 para compatibilidade
        if ($der[$offset] === "\x84") {
            $offset++;
            $priv_len = ord($der[$offset]);
            $offset++;
            $private_bytes = substr($der, $offset, $priv_len);
            return bytes_to_little_int($private_bytes);
        }
        throw new Exception("Expected OCTET STRING for private key");
    }
    $offset++;
    
    $priv_len = ord($der[$offset]);
    $offset++;
    
    // Se for comprimento longo
    if ($priv_len === 0x81) {
        $priv_len = ord($der[$offset]);
        $offset++;
    } elseif ($priv_len === 0x82) {
        $priv_len = (ord($der[$offset]) << 8) | ord($der[$offset+1]);
        $offset += 2;
    }
    
    $private_bytes = substr($der, $offset, $priv_len);
    
    if ($debug) {
        echo "Private key bytes length: " . strlen($private_bytes) . "\n";
        echo "Private key hex: " . bin2hex($private_bytes) . "\n";
    }
    
    // Convert to GMP integer (little-endian)
    return bytes_to_little_int($private_bytes);
}

/**
 * Parse Ed521 public key from PEM SPKI format
 * Follows Python implementation exactly
 */
function parse_ed521_pem_public_key($pem_data, $debug = false) {
    $lines = explode("\n", trim($pem_data));
    $b64_data = '';
    foreach ($lines as $line) {
        $line = trim($line);
        if ($line && strpos($line, '-----') !== 0) {
            $b64_data .= $line;
        }
    }
    
    $der_data = base64_decode($b64_data);
    
    if ($debug) {
        echo "DEBUG: Public key DER length: " . strlen($der_data) . " bytes\n";
        echo "DEBUG: Public key DER hex: " . bin2hex($der_data) . "\n";
    }
    
    try {
        $idx = 0;
        $der_len = strlen($der_data);
        
        if ($der_data[$idx] != "\x30") {
            throw new Exception("Expected SEQUENCE (0x30)");
        }
        $idx++;
        
        if ($idx >= $der_len) {
            throw new Exception("Unexpected end of data");
        }
        
        $seq_len = ord($der_data[$idx]);
        $idx++;
        
        if ($seq_len & 0x80) {
            $num_bytes = $seq_len & 0x7F;
            if ($idx + $num_bytes > $der_len) {
                throw new Exception("Incomplete SEQUENCE length");
            }
            $seq_len_val = bytes_to_little_int(substr($der_data, $idx, $num_bytes));
            $idx += $num_bytes;
        }
        
        if ($der_data[$idx] != "\x30") {
            throw new Exception("Expected AlgorithmIdentifier SEQUENCE (0x30)");
        }
        $idx++;
        
        if ($idx >= $der_len) {
            throw new Exception("Unexpected end of data");
        }
        
        $algo_len = ord($der_data[$idx]);
        $idx++;
        
        if ($algo_len & 0x80) {
            $num_bytes = $algo_len & 0x7F;
            if ($idx + $num_bytes > $der_len) {
                throw new Exception("Incomplete AlgorithmIdentifier length");
            }
            $algo_len_val = bytes_to_little_int(substr($der_data, $idx, $num_bytes));
            $idx += $num_bytes;
        }
        
        $algo_end = $idx + $algo_len;
        
        if ($der_data[$idx] != "\x06") {
            throw new Exception("Expected OID (0x06)");
        }
        $idx++;
        
        if ($idx >= $der_len) {
            throw new Exception("Unexpected end of data");
        }
        
        $oid_len = ord($der_data[$idx]);
        $idx++;
        
        if ($oid_len & 0x80) {
            throw new Exception("Unexpected long form for OID length");
        }
        
        if ($idx + $oid_len > $der_len) {
            throw new Exception("Incomplete OID");
        }
        
        $oid_bytes = substr($der_data, $idx, $oid_len);
        $idx += $oid_len;
        
        if ($idx < $algo_end && $der_data[$idx] == "\x05") {
            $idx++;
            if ($idx >= $der_len) {
                throw new Exception("Unexpected end of data");
            }
            $null_len = ord($der_data[$idx]);
            $idx++;
            if ($null_len != 0) {
                throw new Exception("Expected NULL (0x00), got length $null_len");
            }
        }
        
        $idx = $algo_end;
        
        if ($der_data[$idx] != "\x03") {
            throw new Exception("Expected BIT STRING (0x03), got 0x" . bin2hex($der_data[$idx]));
        }
        $idx++;
        
        if ($idx >= $der_len) {
            throw new Exception("Unexpected end of data");
        }
        
        $bitstring_len = ord($der_data[$idx]);
        $idx++;
        
        if ($bitstring_len & 0x80) {
            $num_bytes = $bitstring_len & 0x7F;
            if ($idx + $num_bytes > $der_len) {
                throw new Exception("Incomplete BIT STRING length");
            }
            $bitstring_len_val = bytes_to_little_int(substr($der_data, $idx, $num_bytes));
            $idx += $num_bytes;
        }
        
        if ($idx >= $der_len) {
            throw new Exception("Unexpected end of data");
        }
        
        $unused_bits = ord($der_data[$idx]);
        $idx++;
        
        if ($unused_bits != 0) {
            if ($debug) {
                echo "DEBUG: Warning: BIT STRING has $unused_bits unused bits\n";
            }
        }
        
        $compressed_pub = substr($der_data, $idx, $bitstring_len - 1);
        
        if ($debug) {
            echo "DEBUG: Compressed public key length: " . strlen($compressed_pub) . " bytes\n";
            echo "DEBUG: Compressed public key hex: " . bin2hex($compressed_pub) . "\n";
        }
        
        list($pub_x, $pub_y) = decompress_point($compressed_pub);
        
        if ($pub_x === null || $pub_y === null) {
            throw new Exception("Failed to decompress public key");
        }
        
        return [$pub_x, $pub_y];
        
    } catch (Exception $e) {
        if ($debug) {
            echo "DEBUG: ASN.1 parsing failed: " . $e->getMessage() . "\n";
        }
        
        // Fallback search for compressed public key
        if (strlen($der_data) == BYTE_LEN) {
            list($pub_x, $pub_y) = decompress_point($der_data);
            if ($pub_x !== null && $pub_y !== null) {
                if ($debug) {
                    echo "DEBUG: Found raw " . BYTE_LEN . "-byte compressed public key\n";
                }
                return [$pub_x, $pub_y];
            }
        }
        
        for ($i = 0; $i <= strlen($der_data) - BYTE_LEN; $i++) {
            $chunk = substr($der_data, $i, BYTE_LEN);
            list($pub_x, $pub_y) = decompress_point($chunk);
            if ($pub_x !== null && $pub_y !== null) {
                if ($debug) {
                    echo "DEBUG: Found compressed public key at offset $i\n";
                }
                return [$pub_x, $pub_y];
            }
        }
        
        throw new Exception("Cannot parse Ed521 public key: " . $e->getMessage());
    }
}

/**
 * Parse Ed521 key file and display raw key information
 */
function ed521_parse_key($key_file, $debug = false) {
    try {
        $pem_data = file_get_contents($key_file);
        if ($pem_data === false) {
            throw new Exception("File not found: $key_file");
        }
        
        $lines = explode("\n", trim($pem_data));
        
        // Check if encrypted
        $is_encrypted = false;
        foreach ($lines as $line) {
            if (strpos($line, "Proc-Type:") === 0 && strpos($line, "ENCRYPTED") !== false) {
                $is_encrypted = true;
                break;
            }
        }
        
        // Parse private key
        if (strpos($pem_data, "PRIVATE KEY") !== false || 
            (strpos($pem_data, "E-521") !== false && strpos($pem_data, "PRIVATE") !== false)) {
            
            if ($is_encrypted) {
                echo "Enter password to decrypt private key: ";
                system('stty -echo');
                $password = trim(fgets(STDIN));
                system('stty echo');
                echo "\n";
                
                try {
                    $der_data = decrypt_private_key_pem($pem_data, $password);
                    echo "✓ Key decrypted successfully\n";
                    
                    // Convert decrypted DER back to PEM for display
                    $b64_der = base64_encode($der_data);
                    $pem_lines = str_split($b64_der, 64);
                    
                    // Print decrypted PEM
                    echo "-----BEGIN PRIVATE KEY-----\n";
                    foreach ($pem_lines as $line) {
                        echo $line . "\n";
                    }
                    echo "-----END PRIVATE KEY-----\n";
                    
                    // Parse the decrypted key
                    $private_key = parse_ed521_pem_private_key(
                        "-----BEGIN PRIVATE KEY-----\n" . 
                        implode("\n", $pem_lines) . "\n" .
                        "-----END PRIVATE KEY-----\n",
                        $debug
                    );
                } catch (Exception $e) {
                    echo "✖ Decryption failed: " . $e->getMessage() . "\n";
                    return;
                }
            } else {
                // Print original PEM
                echo $pem_data . "\n";
                // Parse the key
                $private_key = parse_ed521_pem_private_key($pem_data, $debug);
            }
            
            $private_bytes = little_int_to_bytes($private_key, 66);
            
            echo "Private-Key: (" . (strlen($private_bytes)*8) . "-bit)\n";
            echo "priv: \n";
            $hex_str = bin2hex($private_bytes);
            for ($i = 0; $i < strlen($hex_str); $i += 30) {
                $line_hex = substr($hex_str, $i, 30);
                $formatted = implode(':', str_split($line_hex, 2));
                echo "    $formatted\n";
            }
            
            // Calculate and show public key
            list($pub_x, $pub_y) = get_public_key($private_key);
            $compressed_pub = compress_point($pub_x, $pub_y);
            
            echo "pub: \n";
            $hex_str = bin2hex($compressed_pub);
            for ($i = 0; $i < strlen($hex_str); $i += 30) {
                $line_hex = substr($hex_str, $i, 30);
                $formatted = implode(':', str_split($line_hex, 2));
                echo "    $formatted\n";
            }
            
            echo "Curve: E-521\n";
            echo "OID: 1.3.6.1.4.1.44588.2.1\n";
            
            return [$private_bytes, [$pub_x, $pub_y]];
        
        // Parse public key
        } elseif (strpos($pem_data, "PUBLIC KEY") !== false || 
                 (strpos($pem_data, "E-521") !== false && strpos($pem_data, "PUBLIC") !== false)) {
            
            // Public keys are never encrypted
            echo $pem_data . "\n";
            
            // Parse public key
            list($pub_x, $pub_y) = parse_ed521_pem_public_key($pem_data, $debug);
            $compressed_pub = compress_point($pub_x, $pub_y);
            
            echo "Public-Key: (" . (strlen($compressed_pub)*8) . "-bit)\n";
            $hex_str = bin2hex($compressed_pub);
            for ($i = 0; $i < strlen($hex_str); $i += 30) {
                $line_hex = substr($hex_str, $i, 30);
                $formatted = implode(':', str_split($line_hex, 2));
                echo "    $formatted\n";
            }
            
            echo "Curve: E-521\n";
            echo "OID: 1.3.6.1.4.1.44588.2.1\n";
            
            return [null, [$pub_x, $pub_y]];
        
        } else {
            echo "✖ Unknown key format\n";
        }
        
    } catch (Exception $e) {
        echo "✖ Error: " . $e->getMessage() . "\n";
    }
}

// ====================================================================
// TEST FUNCTION FOR PKCS8 PEM
// ====================================================================

/**
 * Test PKCS8 PEM functionality
 */
function test_pkcs8_pem() {
    echo "=== Teste de PKCS8 PEM para E-521 ===\n\n";
    
    // 1. Gerar chaves
    echo "1. Gerando chaves E-521...\n";
    $private_key = generate_private_key();
    list($pub_x, $pub_y) = get_public_key($private_key);
    echo "   Chave privada gerada\n";
    echo "   Chave pública calculada\n";
    
    // 2. Salvar sem senha
    echo "\n2. Salvando em PEM PKCS8 sem senha...\n";
    $private_pem = ed521_private_to_pem_pkcs8($private_key);
    $public_pem = ed521_public_to_pem($pub_x, $pub_y);
    
    file_put_contents('test_private.pem', $private_pem);
    file_put_contents('test_public.pem', $public_pem);
    echo "   Salvo em test_private.pem e test_public.pem\n";
    
    // 3. Ler de volta
    echo "\n3. Lendo chaves de volta...\n";
    $read_private = parse_ed521_pem_private_key($private_pem);
    list($read_pub_x, $read_pub_y) = parse_ed521_pem_public_key($public_pem);
    
    echo "   Chave privada lida corretamente: " . 
         (gmp_eq($read_private, $private_key) ? "SIM" : "NÃO") . "\n";
    echo "   Chave pública lida corretamente: " . 
         (gmp_eq($read_pub_x, $pub_x) && gmp_eq($read_pub_y, $pub_y) ? "SIM" : "NÃO") . "\n";
    
    // 4. Testar assinatura com chaves lidas
    echo "\n4. Testando assinatura com chaves lidas...\n";
    $message = "Test message for PKCS8 PEM";
    $signature = sign($read_private, $message);
    $valid = verify($read_pub_x, $read_pub_y, $message, $signature);
    echo "   Assinatura válida: " . ($valid ? "SIM" : "NÃO") . "\n";
    
    // 5. Salvar com senha
    echo "\n5. Salvando com senha 'test123'...\n";
    $password = 'test123';
    $encrypted_pem = ed521_private_to_pem_pkcs8($private_key, $password);
    file_put_contents('test_encrypted.pem', $encrypted_pem);
    echo "   Salvo em test_encrypted.pem (criptografado)\n";
    
    // 6. Ler chave criptografada
    echo "\n6. Lendo chave criptografada...\n";
    $encrypted_data = file_get_contents('test_encrypted.pem');
    try {
        $decrypted_private = parse_ed521_pem_private_key($encrypted_data);
        echo "   Chave descriptografada com sucesso\n";
        echo "   Chave correta: " . (gmp_eq($decrypted_private, $private_key) ? "SIM" : "NÃO") . "\n";
    } catch (Exception $e) {
        echo "   ERRO: " . $e->getMessage() . "\n";
    }
    
    // 7. Testar senha errada
    echo "\n7. Testando senha errada...\n";
    $wrong_password = 'wrongpass';
    try {
        // Tentar ler com senha errada
        echo "   (Teste de senha errada requer entrada interativa)\n";
    } catch (Exception $e) {
        echo "   Senha errada rejeitada como esperado\n";
    }
    
    // 8. Limpar arquivos de teste
    echo "\n8. Limpando arquivos de teste...\n";
    @unlink('test_private.pem');
    @unlink('test_public.pem');
    @unlink('test_encrypted.pem');
    echo "   Arquivos removidos\n";
    
    echo "\n=== Testes de PKCS8 PEM concluídos ===\n";
}

// ====================================================================
// COMMAND LINE INTERFACE
// ====================================================================

/**
 * Command line interface for PKCS8 PEM operations
 */
function cli_pkcs8_pem() {
    global $argc, $argv;
    
    if ($argc < 2) {
        echo "Uso: php " . basename(__FILE__) . " [comando]\n";
        echo "Comandos:\n";
        echo "  test           - Testar funcionalidade PKCS8 PEM\n";
        echo "  parse <arquivo> - Analisar arquivo PEM\n";
        echo "  generate       - Gerar novas chaves E-521\n";
        echo "  sign           - Assinar mensagem\n";
        echo "  verify         - Verificar assinatura\n";
        exit(1);
    }
    
    $command = $argv[1];
    
    switch ($command) {
        case 'test':
            test_pkcs8_pem();
            break;
            
        case 'parse':
            if ($argc < 3) {
                echo "Uso: php " . basename(__FILE__) . " parse <arquivo_pem>\n";
                exit(1);
            }
            $key_file = $argv[2];
            $debug = ($argc > 3 && $argv[3] == '--debug');
            ed521_parse_key($key_file, $debug);
            break;
            
        case 'generate':
            $password = null;
            if ($argc > 2 && $argv[2] == '--password') {
                echo "Senha: ";
                system('stty -echo');
                $password = trim(fgets(STDIN));
                system('stty echo');
                echo "\n";
            }
            
            $private_key = generate_private_key();
            list($pub_x, $pub_y) = get_public_key($private_key);
            
            $private_pem = ed521_private_to_pem_pkcs8($private_key, $password);
            $public_pem = ed521_public_to_pem($pub_x, $pub_y);
            
            file_put_contents('ed521_private.pem', $private_pem);
            file_put_contents('ed521_public.pem', $public_pem);
            
            echo "Chaves geradas:\n";
            echo "- ed521_private.pem " . ($password ? "(criptografado)" : "") . "\n";
            echo "- ed521_public.pem\n";
            
            // Mostrar fingerprint
            $compressed = compress_point($pub_x, $pub_y);
            $fingerprint = substr(hash('sha256', $compressed), 0, 16);
            echo "Fingerprint: $fingerprint\n";
            break;
            
        case 'sign':
            if ($argc < 4) {
                echo "Uso: php " . basename(__FILE__) . " sign <arquivo_privado> <arquivo_mensagem>\n";
                exit(1);
            }
            $priv_file = $argv[2];
            $msg_file = $argv[3];
            
            $pem_data = file_get_contents($priv_file);
            if (!$pem_data) {
                echo "Erro: não foi possível ler $priv_file\n";
                exit(1);
            }
            
            $private_key = parse_ed521_pem_private_key($pem_data);
            $message = file_get_contents($msg_file);
            if (!$message) {
                echo "Erro: não foi possível ler $msg_file\n";
                exit(1);
            }
            
            $signature = sign($private_key, $message);
            echo "Assinatura (hex): " . bin2hex($signature) . "\n";
            break;
            
        case 'verify':
            if ($argc < 5) {
                echo "Uso: php " . basename(__FILE__) . " verify <arquivo_publico> <arquivo_mensagem> <assinatura_hex>\n";
                exit(1);
            }
            $pub_file = $argv[2];
            $msg_file = $argv[3];
            $sig_hex = $argv[4];
            
            $pem_data = file_get_contents($pub_file);
            if (!$pem_data) {
                echo "Erro: não foi possível ler $pub_file\n";
                exit(1);
            }
            
            list($pub_x, $pub_y) = parse_ed521_pem_public_key($pem_data);
            $message = file_get_contents($msg_file);
            if (!$message) {
                echo "Erro: não foi possível ler $msg_file\n";
                exit(1);
            }
            
            $signature = hex2bin($sig_hex);
            $valid = verify($pub_x, $pub_y, $message, $signature);
            
            if ($valid) {
                echo "✓ Assinatura válida\n";
            } else {
                echo "✖ Assinatura inválida\n";
            }
            break;
            
        default:
            echo "Comando desconhecido: $command\n";
            break;
    }
}

// ====================================================================
// Main Test Execution
// ====================================================================

if (PHP_SAPI === 'cli' && basename(__FILE__) === basename($_SERVER['PHP_SELF'])) {
    // Primeiro debug das conversões
    debug_conversions();
    echo "\n" . str_repeat("=", 60) . "\n\n";
    
    // Depois teste completo
    test_with_fixed_key();
    cli_pkcs8_pem();
}
