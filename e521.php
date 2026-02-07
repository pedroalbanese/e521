<?php

/**
 * Brazilian Ed521 Algorithm Implementation in Pure PHP using BCMath
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
// Helper Functions for BCMath (CORRIGIDAS)
// ====================================================================

/**
 * Convert BCMath number to hex string
 */
function bcdechex($num) {
    if (bceq($num, '0')) {
        return '0';
    }
    
    $hex = '';
    while (bccomp($num, '0') > 0) {
        $byte = bcmod($num, '16');
        $hex = dechex(intval($byte)) . $hex;
        $num = bcdiv($num, '16', 0);
    }
    
    return $hex;
}

/**
 * Secure comparison for BCMath (a == b)
 */
function bceq($a, $b) {
    return bccomp($a, $b) === 0;
}

/**
 * Secure comparison for BCMath (a < b)
 */
function bclt($a, $b) {
    return bccomp($a, $b) < 0;
}

/**
 * Modular addition optimized for large numbers
 */
function bcaddmod($a, $b, $mod) {
    $sum = bcadd($a, $b);
    if (bccomp($sum, $mod) >= 0) {
        $sum = bcsub($sum, $mod);
    }
    if (bccomp($sum, '0') < 0) {
        $sum = bcadd($sum, $mod);
    }
    return $sum;
}

/**
 * Modular subtraction optimized for large numbers
 */
function bcsubmod($a, $b, $mod) {
    $diff = bcsub($a, $b);
    if (bccomp($diff, '0') < 0) {
        $diff = bcadd($diff, $mod);
    }
    return bcmod($diff, $mod);
}

/**
 * Modular multiplication optimized for large numbers
 */
function bcmulmod($a, $b, $mod) {
    $prod = bcmul($a, $b);
    return bcmod($prod, $mod);
}

/**
 * Modular exponentiation fallback
 */
if (!function_exists('bcpowmod')) {
    function bcpowmod($base, $exp, $mod) {
        $result = '1';
        $base = bcmod($base, $mod);
        
        while (bccomp($exp, '0') > 0) {
            if (bcmod($exp, '2') === '1') {
                $result = bcmod(bcmul($result, $base), $mod);
            }
            $base = bcmod(bcmul($base, $base), $mod);
            $exp = bcdiv($exp, '2', 0);
        }
        
        return $result;
    }
}

/**
 * Modular multiplicative inverse using extended Euclidean algorithm
 */
function bcinvmod($a, $mod) {
    if (bceq($a, '0')) {
        return '0';
    }
    
    $g = $mod;
    $x = '0';
    $y = '1';
    $u = '1';
    $v = '0';
    
    while (!bceq($a, '0')) {
        $q = bcdiv($g, $a, 0);
        $r = bcmod($g, $a);
        
        $m = bcsub($x, bcmul($u, $q));
        $n = bcsub($y, bcmul($v, $q));
        
        $g = $a;
        $a = $r;
        $x = $u;
        $y = $v;
        $u = $m;
        $v = $n;
    }
    
    if (bccomp($x, '0') < 0) {
        $x = bcadd($x, $mod);
    }
    
    return $x;
}

// ====================================================================
// Byte Conversion Functions (CORRIGIDAS - AGORA IGUAIS AO PYTHON)
// ====================================================================

/**
 * Convert little-endian bytes to integer (EXATAMENTE como Python)
 * Python: reversed_bytes = bytes(reversed(b)); return int.from_bytes(reversed_bytes, 'big')
 */
function bytes_to_little_int($b) {
    // Inverter os bytes como no Python
    $reversed_bytes = strrev($b);
    
    // Converter para inteiro (big-endian após inverter)
    $result = '0';
    $len = strlen($reversed_bytes);
    
    for ($i = 0; $i < $len; $i++) {
        $byte = ord($reversed_bytes[$i]);
        $power = bcpow('256', (string)($len - 1 - $i));
        $result = bcadd($result, bcmul((string)$byte, $power));
    }
    
    return $result;
}

/**
 * Convert integer to little-endian bytes (EXATAMENTE como Python)
 * Python: bytes_be = n.to_bytes((n.bit_length() + 7) // 8 or 1, 'big')
 *         reversed_bytes = bytes(reversed(bytes_be))
 *         return reversed_bytes[:length]
 */
function little_int_to_bytes($n, $length) {
    // Primeiro converter para bytes big-endian
    $bytes_be = '';
    $temp = $n;
    
    if (bceq($temp, '0')) {
        $bytes_be = "\x00";
    } else {
        while (bccomp($temp, '0') > 0) {
            $byte = bcmod($temp, '256');
            $bytes_be = chr(intval($byte)) . $bytes_be; // Big-endian
            $temp = bcdiv($temp, '256', 0);
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
    
    // Inverter para little-endian (como no Python)
    $little_bytes = strrev($bytes_be);
    
    return $little_bytes;
}

/**
 * Generate cryptographically secure random bytes
 */
function random_bytes_bc($length) {
    // Se random_bytes existir, use ele (PHP 7+)
    if (function_exists('random_bytes')) {
        return random_bytes($length);
    }

    // Fallback seguro para PHP <7, usando random_int
    $bytes = '';
    for ($i = 0; $i < $length; $i++) {
        $bytes .= chr(random_int(0, 255));
    }

    return $bytes;
}

// ====================================================================
// SHAKE256 Implementation (SIMPLIFICADA mas funcional)
// ====================================================================

/**
 * SHAKE256 implementation following golang.org/x/crypto/sha3
 * Using BCMath for 64-bit operations - CORRECTED VERSION
 */

// Check for BCMath extension
if (!extension_loaded('bcmath')) {
    die("BCMath extension is required. Please install: sudo apt-get install php-bcmath\n");
}

// Constants
define('SHAKE256_rate', 136); // 1088 bits = 136 bytes
$mask64 = "18446744073709551615"; // 0xFFFFFFFFFFFFFFFF

// Helper function to convert hex to BCMath decimal string
function hex2dec($hex) {
    $hex = str_replace('0x', '', $hex);
    $dec = '0';
    $len = strlen($hex);
    
    for ($i = 0; $i < $len; $i++) {
        $char = $hex[$len - 1 - $i];
        $val = hexdec($char);
        $dec = bcadd($dec, bcmul($val, bcpow('16', $i)));
    }
    
    return $dec;
}

// Helper functions for BCMath operations
function bc_and($x, $y) {
    // BCMath doesn't have bitwise AND, we need to implement it
    $result = "0";
    $x = trim($x);
    $y = trim($y);
    
    $bit = "1";
    while (bccomp($x, "0") > 0 || bccomp($y, "0") > 0) {
        $x_bit = bcmod($x, "2");
        $y_bit = bcmod($y, "2");
        
        if (bccomp($x_bit, "1") == 0 && bccomp($y_bit, "1") == 0) {
            $result = bcadd($result, $bit);
        }
        
        $x = bcdiv($x, "2", 0);
        $y = bcdiv($y, "2", 0);
        $bit = bcmul($bit, "2");
    }
    return $result;
}

function bc_or($x, $y) {
    $x = trim($x);
    $y = trim($y);
    $result = "0";
    $bit = "1";
    
    while (bccomp($x, "0") > 0 || bccomp($y, "0") > 0) {
        $x_bit = bcmod($x, "2");
        $y_bit = bcmod($y, "2");
        
        if (bccomp($x_bit, "1") == 0 || bccomp($y_bit, "1") == 0) {
            $result = bcadd($result, $bit);
        }
        
        $x = bcdiv($x, "2", 0);
        $y = bcdiv($y, "2", 0);
        $bit = bcmul($bit, "2");
    }
    return $result;
}

function bc_xor($x, $y) {
    $x = trim($x);
    $y = trim($y);
    $result = "0";
    $bit = "1";
    
    while (bccomp($x, "0") > 0 || bccomp($y, "0") > 0) {
        $x_bit = bcmod($x, "2");
        $y_bit = bcmod($y, "2");
        
        if ((bccomp($x_bit, "1") == 0 && bccomp($y_bit, "0") == 0) ||
            (bccomp($x_bit, "0") == 0 && bccomp($y_bit, "1") == 0)) {
            $result = bcadd($result, $bit);
        }
        
        $x = bcdiv($x, "2", 0);
        $y = bcdiv($y, "2", 0);
        $bit = bcmul($bit, "2");
    }
    return $result;
}

function bc_not($x) {
    global $mask64;
    return bc_xor($x, $mask64);
}

function bc_shift_left($x, $bits) {
    // Left shift for BCMath
    return bcmul($x, bcpow("2", $bits));
}

function bc_shift_right($x, $bits) {
    // Right shift for BCMath
    return bcdiv($x, bcpow("2", $bits), 0);
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

// Convert to BCMath decimal strings
$RC = [];
foreach ($RC_hex as $hex) {
    $RC[] = hex2dec($hex);
}

// Rotation offsets
$rotc = [1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44];

// Pi indices
$piln = [10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1];

// ===================================================================
// Core Keccak functions using BCMath
// ===================================================================

/**
 * Rotate left 64-bit BCMath number
 */
function rotl64($x, $k) {
    global $mask64;
    $k = $k % 64;
    if ($k == 0) return $x;
    
    $x = bc_and($x, $mask64);
    $left = bc_and(bc_shift_left($x, $k), $mask64);
    $right = bc_and(bc_shift_right($x, 64 - $k), $mask64);
    return bc_or($left, $right);
}

/**
 * Keccak-f[1600] permutation using BCMath
 */
function keccakF1600(&$state) {
    global $RC, $rotc, $piln, $mask64;
    
    for ($round = 0; $round < 24; $round++) {
        // θ step
        $c0 = bc_xor($state[0], bc_xor($state[5], bc_xor($state[10], bc_xor($state[15], $state[20]))));
        $c1 = bc_xor($state[1], bc_xor($state[6], bc_xor($state[11], bc_xor($state[16], $state[21]))));
        $c2 = bc_xor($state[2], bc_xor($state[7], bc_xor($state[12], bc_xor($state[17], $state[22]))));
        $c3 = bc_xor($state[3], bc_xor($state[8], bc_xor($state[13], bc_xor($state[18], $state[23]))));
        $c4 = bc_xor($state[4], bc_xor($state[9], bc_xor($state[14], bc_xor($state[19], $state[24]))));

        $d0 = bc_xor(rotl64($c1, 1), $c4);
        $d1 = bc_xor(rotl64($c2, 1), $c0);
        $d2 = bc_xor(rotl64($c3, 1), $c1);
        $d3 = bc_xor(rotl64($c4, 1), $c2);
        $d4 = bc_xor(rotl64($c0, 1), $c3);

        // Apply θ to all lanes
        for ($i = 0; $i < 25; $i += 5) {
            $state[$i] = bc_and(bc_xor($state[$i], $d0), $mask64);
            $state[$i + 1] = bc_and(bc_xor($state[$i + 1], $d1), $mask64);
            $state[$i + 2] = bc_and(bc_xor($state[$i + 2], $d2), $mask64);
            $state[$i + 3] = bc_and(bc_xor($state[$i + 3], $d3), $mask64);
            $state[$i + 4] = bc_and(bc_xor($state[$i + 4], $d4), $mask64);
        }

        // ρ and π steps
        $b = array_fill(0, 25, "0");
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

            $not_t1 = bc_not($t1);
            $not_t2 = bc_not($t2);
            $not_t3 = bc_not($t3);
            $not_t4 = bc_not($t4);
            $not_t0 = bc_not($t0);

            $state[$y] = bc_and(bc_xor($t0, bc_and($not_t1, $t2)), $mask64);
            $state[$y + 1] = bc_and(bc_xor($t1, bc_and($not_t2, $t3)), $mask64);
            $state[$y + 2] = bc_and(bc_xor($t2, bc_and($not_t3, $t4)), $mask64);
            $state[$y + 3] = bc_and(bc_xor($t3, bc_and($not_t4, $t0)), $mask64);
            $state[$y + 4] = bc_and(bc_xor($t4, bc_and($not_t0, $t1)), $mask64);
        }

        // ι step
        $state[0] = bc_and(bc_xor($state[0], $RC[$round]), $mask64);
    }
}

// ===================================================================
// SHAKE256 implementation using BCMath
// ===================================================================

/**
 * SHAKE256 hash function using BCMath
 */
function shake256($input, $outputLength) {
    global $mask64;
    
    $rate = 136; // SHAKE256 rate in bytes
    $dsbyte = 0x1F; // SHAKE domain separator
    
    // Initialize state
    $state = array_fill(0, 25, "0");
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
                $word = "0";
                for ($j = 0; $j < 8 && ($i + $j) < $rate; $j++) {
                    $byte = $buffer[$i + $j];
                    $word = bcadd($word, bcmul($byte, bcpow("2", $j * 8)));
                }
                $state[$i / 8] = bc_and(bc_xor($state[$i / 8], $word), $mask64);
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
        $word = "0";
        for ($j = 0; $j < 8 && ($i + $j) < $rate; $j++) {
            $byte = $buffer[$i + $j];
            $word = bcadd($word, bcmul($byte, bcpow("2", $j * 8)));
        }
        $state[$i / 8] = bc_and(bc_xor($state[$i / 8], $word), $mask64);
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
            $shifted = bcdiv($state[$lane], bcpow("2", $posInLane * 8));
            $byte = bcmod($shifted, "256");
            $output .= chr(intval($byte));
            $bytesExtracted++;
        }
        
        if ($bytesExtracted < $outputLength) {
            keccakF1600($state);
        }
    }
    
    return $output;
}

// ====================================================================
// Elliptic Curve Point Operations (MANTIDAS)
// ====================================================================

/**
 * Verify if a point lies on the E-521 curve
 */
function is_on_curve($x, $y) {
    $x2 = bcmulmod($x, $x, P);
    $y2 = bcmulmod($y, $y, P);
    $lhs = bcaddmod($x2, $y2, P);
    
    $d_pos = bcadd(D, P); // Make D positive
    $dx2y2 = bcmulmod($d_pos, bcmulmod($x2, $y2, P), P);
    $rhs = bcaddmod('1', $dx2y2, P);
    
    return bceq($lhs, $rhs);
}

/**
 * Point addition on Twisted Edwards curve
 */
function add_points($x1, $y1, $x2, $y2) {
    if (bceq($x1, '0') && bceq($y1, '1')) {
        return [$x2, $y2];
    }
    if (bceq($x2, '0') && bceq($y2, '1')) {
        return [$x1, $y1];
    }
    
    $x1y2 = bcmulmod($x1, $y2, P);
    $y1x2 = bcmulmod($y1, $x2, P);
    $numerator_x = bcaddmod($x1y2, $y1x2, P);
    
    $y1y2 = bcmulmod($y1, $y2, P);
    $x1x2 = bcmulmod($x1, $x2, P);
    $numerator_y = bcsubmod($y1y2, $x1x2, P);
    
    $d_pos = bcadd(D, P);
    $dx1x2y1y2 = bcmulmod($d_pos, bcmulmod($x1x2, $y1y2, P), P);
    
    $denominator_x = bcaddmod('1', $dx1x2y1y2, P);
    $denominator_y = bcsubmod('1', $dx1x2y1y2, P);
    
    $inv_den_x = bcinvmod($denominator_x, P);
    $inv_den_y = bcinvmod($denominator_y, P);
    
    $x3 = bcmulmod($numerator_x, $inv_den_x, P);
    $y3 = bcmulmod($numerator_y, $inv_den_y, P);
    
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
    $scalar = bcmod(bytes_to_little_int($k_bytes), N);
    
    $result_x = '0';
    $result_y = '1';
    $temp_x = $x;
    $temp_y = $y;
    
    while (bccomp($scalar, '0') > 0) {
        if (bcmod($scalar, '2') === '1') {
            list($result_x, $result_y) = add_points($result_x, $result_y, $temp_x, $temp_y);
        }
        list($temp_x, $temp_y) = double_point($temp_x, $temp_y);
        $scalar = bcdiv($scalar, '2', 0);
    }
    
    return [$result_x, $result_y];
}

/**
 * Scalar multiplication of the base point (k * G)
 */
function scalar_base_mult($k_bytes) {
    return scalar_mult(Gx, Gy, $k_bytes);
}

// ====================================================================
// Point Compression/Decompression (MANTIDAS)
// ====================================================================

/**
 * Compress point (RFC 8032 compliant)
 */
function compress_point($x, $y) {
    // Convert y to little-endian bytes
    $y_bytes = little_int_to_bytes($y, BYTE_LEN);
    
    // Get the least significant bit of x
    $x_lsb = bcmod($x, '2');
    
    // Set the most significant bit of the last byte based on x_lsb
    $last_byte = ord($y_bytes[BYTE_LEN - 1]);
    if (bceq($x_lsb, '1')) {
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
    if (bccomp($y, P) >= 0) {
        return [null, null];
    }
    
    // y² mod p
    $y2 = bcmulmod($y, $y, P);
    
    // u = y² - 1
    $u = bcsubmod($y2, '1', P);
    
    // v = d*y² - 1
    $d_pos = bcadd(D, P);
    $v = bcsubmod(bcmulmod($d_pos, $y2, P), '1', P);
    
    // v⁻¹ mod p
    $v_inv = bcinvmod($v, P);
    if (bceq($v_inv, '0')) {
        return [null, null];
    }
    
    // x² = u/v mod p
    $x2 = bcmulmod($u, $v_inv, P);
    
    // x = x²^((p+1)/4) mod p (since p ≡ 3 mod 4)
    $exp = bcdiv(bcadd(P, '1'), '4', 0);
    $x = bcpowmod($x2, $exp, P);
    
    // Verify x² is correct
    $x2_check = bcmulmod($x, $x, P);
    if (!bceq($x2, $x2_check)) {
        // Try the other root
        $x = bcsubmod('0', $x, P);
        $x2_check = bcmulmod($x, $x, P);
        if (!bceq($x2, $x2_check)) {
            return [null, null];
        }
    }
    
    // Check the sign bit
    $x_lsb = bcmod($x, '2');
    if (intval($x_lsb) != $sign_bit) {
        $x = bcsubmod('0', $x, P);
    }
    
    // Verify the point is on the curve
    if (!is_on_curve($x, $y)) {
        return [null, null];
    }
    
    return [$x, $y];
}

// ====================================================================
// Hash Functions (MANTIDAS)
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
// Key Generation and Signing Functions (MANTIDAS)
// ====================================================================

/**
 * Generate random private key
 */
function generate_private_key() {
    while (true) {
        $priv_bytes = random_bytes_bc(BYTE_LEN);
        $a = bytes_to_little_int($priv_bytes);
        if (bclt($a, N)) {
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
    $byte_len = BYTE_LEN;
    
    // Hash the private key
    $prefix = hash_e521(0x00, '', little_int_to_bytes($priv, $byte_len));
    
    // Calculate r
    $r_bytes = hash_e521(0x00, '', $prefix . $message);
    $r = bcmod(bytes_to_little_int(substr($r_bytes, 0, $byte_len)), N);
    
    // Compute R = r*G
    list($Rx, $Ry) = scalar_base_mult(little_int_to_bytes($r, $byte_len));
    $R_compressed = compress_point($Rx, $Ry);
    
    // Get public key
    list($Ax, $Ay) = get_public_key($priv);
    $A_compressed = compress_point($Ax, $Ay);
    
    // Compute h
    $hram_input = $R_compressed . $A_compressed . $message;
    $hram_hash = hash_e521(0x00, '', $hram_input);
    $h = bcmod(bytes_to_little_int(substr($hram_hash, 0, $byte_len)), N);
    
    // Compute s
    $s = bcmod(bcadd($r, bcmul($h, $priv)), N);
    
    // Signature = R || s
    $s_bytes = little_int_to_bytes($s, $byte_len);
    $signature = $R_compressed . $s_bytes;
    
    return $signature;
}

/**
 * Verify PureEdDSA signature
 */
function verify($pub_x, $pub_y, $message, $signature) {
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
    if (bccomp($s, N) >= 0) {
        return false;
    }
    
    // Compress public key
    $A_compressed = compress_point($pub_x, $pub_y);
    
    // Compute h
    $hram_input = $R_compressed . $A_compressed . $message;
    $hram_hash = hash_e521(0x00, '', $hram_input);
    $h = bcmod(bytes_to_little_int(substr($hram_hash, 0, $byte_len)), N);
    
    // Compute s*G
    list($sGx, $sGy) = scalar_base_mult(little_int_to_bytes($s, $byte_len));
    
    // Compute h*A
    list($hAx, $hAy) = scalar_mult($pub_x, $pub_y, little_int_to_bytes($h, $byte_len));
    
    // Compute R + h*A
    list($rhaX, $rhaY) = add_points($Rx, $Ry, $hAx, $hAy);
    
    // Compare s*G with R + h*A
    return bceq($sGx, $rhaX) && bceq($sGy, $rhaY);
}

// ====================================================================
// Test Functions (ATUALIZADAS)
// ====================================================================

/**
 * Test with fixed private key (same as Python)
 */
function test_with_fixed_key() {
    echo "=== Teste com Chave Fixa (Compatibilidade PHP-Python) ===\n";
    
    // Chave privada fixa (mesma do Python)
    $priv_fixed_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041";
    
    // Converter hex para bytes
    $priv_bytes = hex2bin($priv_fixed_hex);
    
    // Converter para inteiro (little-endian) - CORRIGIDO
    $priv = bytes_to_little_int($priv_bytes);
    
    echo "Chave privada fixa (hex): " . substr($priv_fixed_hex, 0, 32) . "...\n";
    echo "Chave privada (decimal): $priv\n";
    echo "Chave privada < N: " . (bclt($priv, N) ? "SIM" : "NÃO") . "\n";
    
    // Comparar com valor do Python
    $expected_priv_python = "223967335972819759373503776271108057384498630450836115547541579141642024888412028915164180638113607345740788317113536007100795972714107924372918861158145982720";
    echo "Chave Python esperada: " . substr($expected_priv_python, 0, 50) . "...\n";
    echo "Chaves iguais: " . (bceq($priv, $expected_priv_python) ? "SIM" : "NÃO") . "\n";
    
    if (!bceq($priv, $expected_priv_python)) {
        echo "ERRO: Chaves privadas diferentes!\n";
        echo "PHP: " . substr($priv, 0, 100) . "\n";
        echo "Python: " . substr($expected_priv_python, 0, 100) . "\n";
        
        // Debug adicional
        echo "\nDebug da conversão:\n";
        echo "Bytes hex: " . bin2hex($priv_bytes) . "\n";
        echo "Bytes length: " . strlen($priv_bytes) . "\n";
        
        // Testar conversão manual
        $manual = '0';
        for ($i = 0; $i < strlen($priv_bytes); $i++) {
            $byte = ord($priv_bytes[strlen($priv_bytes) - 1 - $i]); // Invertido
            $manual = bcadd($manual, bcmul((string)$byte, bcpow('256', (string)$i)));
        }
        echo "Conversão manual: $manual\n";
        
        return;
    }
    
    // Calcula chave pública
    list($pub_x, $pub_y) = get_public_key($priv);
    echo "\nChave pública gerada:\n";
    echo "  x (hex primeiros 30 chars): " . substr(bcdechex($pub_x), 0, 30) . "...\n";
    echo "  y (hex primeiros 30 chars): " . substr(bcdechex($pub_y), 0, 30) . "...\n";
    echo "Ponto na curva: " . (is_on_curve($pub_x, $pub_y) ? "SIM" : "NÃO") . "\n";
    
    // Testa compressão/descompressão
    $compressed = compress_point($pub_x, $pub_y);
    echo "\nChave pública comprimida: " . strlen($compressed) . " bytes\n";
    echo "Comprimida (hex primeiros 32 bytes): " . bin2hex(substr($compressed, 0, 32)) . "...\n";
    
    list($decomp_x, $decomp_y) = decompress_point($compressed);
    $decomp_correct = bceq($decomp_x, $pub_x) && bceq($decomp_y, $pub_y);
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
    
    // Valores para comparação com Python
    echo "\n=== Valores para Comparação com Python ===\n";
    echo "Private key (little-endian hex): " . bin2hex($priv_bytes) . "\n";
    echo "Private key (decimal): $priv\n";
    
    // Hash do prefixo para debug
    $prefix = hash_e521(0x00, '', little_int_to_bytes($priv, BYTE_LEN));
    echo "\nPrefix hash (primeiros 32 bytes): " . bin2hex(substr($prefix, 0, 32)) . "...\n";
    
    // Valor r para debug
    $r_bytes = hash_e521(0x00, '', $prefix . $message);
    $r = bcmod(bytes_to_little_int(substr($r_bytes, 0, BYTE_LEN)), N);
    echo "r (mod N): $r\n";
    echo "r_bytes (hex primeiros 32): " . bin2hex(substr($r_bytes, 0, 32)) . "...\n";
    
    // Ponto R
    list($Rx, $Ry) = scalar_base_mult(little_int_to_bytes($r, BYTE_LEN));
    $R_compressed = compress_point($Rx, $Ry);
    echo "\nR ponto x: $Rx\n";
    echo "R ponto y: $Ry\n";
    echo "R comprimido (hex): " . bin2hex($R_compressed) . "\n";
    
    // Chave pública A
    $A_compressed = compress_point($pub_x, $pub_y);
    echo "\nA comprimido (hex): " . bin2hex($A_compressed) . "\n";
    
    // Valor h
    $hram_input = $R_compressed . $A_compressed . $message;
    $hram_hash = hash_e521(0x00, '', $hram_input);
    $h = bcmod(bytes_to_little_int(substr($hram_hash, 0, BYTE_LEN)), N);
    echo "h (mod N): $h\n";
    echo "hram_input length: " . strlen($hram_input) . " bytes\n";
    echo "hram_hash (primeiros 32 bytes): " . bin2hex(substr($hram_hash, 0, 32)) . "...\n";
    
    // Valor s
    $s = bcmod(bcadd($r, bcmul($h, $priv)), N);
    echo "\ns (mod N): $s\n";
    echo "Assinatura completa (hex): " . bin2hex($signature) . "\n";
    
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
    echo "PHP bytes_to_little_int: $result_php\n";
    
    // What Python should give (0x0f0e0d0c0b0a09080706050403020100 as big-endian)
    $expected_python = "5233100606242806050955395731361295"; // 0x0f0e0d0c0b0a09080706050403020100 em decimal
    echo "Python expected: $expected_python\n";
    echo "Iguais: " . (bceq($result_php, $expected_python) ? "SIM" : "NÃO") . "\n";
    
    // Test with 0x0100 (little-endian: 0x00 0x01)
    echo "\nTest 0x0100 (little-endian):\n";
    $two_bytes = "\x00\x01"; // Em little-endian, 0x0100 = 256
    $two_int = bytes_to_little_int($two_bytes);
    echo "Bytes: " . bin2hex($two_bytes) . "\n";
    echo "Convertido: $two_int (deveria ser 256)\n";
    
    // Test little_int_to_bytes
    echo "\nTest little_int_to_bytes(256, 2):\n";
    $back_bytes = little_int_to_bytes('256', 2);
    echo "Resultado: " . bin2hex($back_bytes) . " (deveria ser 0001 em little-endian)\n";
    
    // Test com a chave privada real
    echo "\nTest com chave privada real:\n";
    $priv_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041";
    $priv_bytes = hex2bin($priv_hex);
    $priv_int = bytes_to_little_int($priv_bytes);
    echo "Primeiros 50 chars: " . substr($priv_int, 0, 50) . "...\n";
    echo "Esperado Python: 22396733597281975937350377627110805738449863045083...\n";
}

// ====================================================================
// Main Test Execution
// ====================================================================

if (PHP_SAPI === 'cli' && basename(__FILE__) === basename($_SERVER['PHP_SELF'])) {
    // Set BC scale for high precision
    bcscale(0);
    
    // Primeiro debug das conversões
    debug_conversions();
    echo "\n" . str_repeat("=", 60) . "\n\n";
    
    // Depois teste completo
    test_with_fixed_key();
}
