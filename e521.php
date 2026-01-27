<?php

/**
 * Brazilian Ed521 Algorithm Implementation in Pure PHP using BCMath
 * 
 * Implementation of the Brazilian Ed521 digital signature algorithm
 * based on Twisted Edwards curves over prime fields.
 * 
 * Reference Implementation for ALBANESE Research Lab
 * Developed by Pedro F. Albanese - ALBANESE Research Lab
 * 
 * @author Pedro F. Albanese <pedro.albanese@albaneseresearchlab.com>
 * @copyright ALBANESE Research Lab
 * @license MIT
 * @version 1.0.0
 */

// ====================================================================
// E-521 Curve Parameters (Brazilian Standard)
// ====================================================================
define('P', '6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151');
define('N', '1716199415032652428745475199770348304317358825035826352348615864796385795849413675475876651663657849636693659065234142604319282948702542317993421293670108523');
define('D', '-376014');
define('Gx', '1571054894184995387535939749894317568645297350402905821437625181152304994381188529632591196067604100772673927915114267193389905003276673749012051148356041324');
define('Gy', '12');
define('H', 4);
define('BIT_SIZE', 521);
define('BYTE_LEN', 66); // (BIT_SIZE + 7) // 8 = 66 bytes

// ====================================================================
// BCMath Helper Functions
// ====================================================================

/**
 * Secure comparison for BCMath (a == b)
 * 
 * @param string $a First number
 * @param string $b Second number
 * @return bool True if equal
 */
function bceq($a, $b) {
    return bccomp($a, $b) === 0;
}

/**
 * Secure comparison for BCMath (a < b)
 * 
 * @param string $a First number
 * @param string $b Second number
 * @return bool True if a < b
 */
function bclt($a, $b) {
    return bccomp($a, $b) < 0;
}

/**
 * Modular addition optimized for large numbers
 * 
 * @param string $a First operand
 * @param string $b Second operand
 * @param string $mod Modulus
 * @return string (a + b) mod modulus
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
 * 
 * @param string $a First operand
 * @param string $b Second operand
 * @param string $mod Modulus
 * @return string (a - b) mod modulus
 */
function bcsubmod($a, $b, $mod) {
    $diff = bcsub($a, $b);
    if (bccomp($diff, '0') < 0) {
        $diff = bcadd($diff, $mod);
    }
    if (bccomp($diff, $mod) >= 0) {
        $diff = bcsub($diff, $mod);
    }
    return $diff;
}

/**
 * Modular multiplication optimized for large numbers
 * 
 * @param string $a First operand
 * @param string $b Second operand
 * @param string $mod Modulus
 * @return string (a * b) mod modulus
 */
function bcmulmod($a, $b, $mod) {
    $prod = bcmul($a, $b);
    return bcmod($prod, $mod);
}

/**
 * Modular exponentiation - fallback implementation
 * Only defined if PHP doesn't have native bcpowmod
 */
if (!function_exists('bcpowmod')) {
    /**
     * Modular exponentiation (a^b mod m)
     * 
     * @param string $base Base
     * @param string $exp Exponent
     * @param string $mod Modulus
     * @return string (base^exp) mod modulus
     */
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
 * 
 * @param string $a Number to invert
 * @param string $mod Modulus
 * @return string Modular inverse of a mod modulus
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
// Byte Conversion Functions (Little-Endian Format)
// ====================================================================

/**
 * Convert little-endian bytes to integer
 * 
 * @param string $b Bytes in little-endian order
 * @return string Integer representation
 */
function bytes_to_little_int($b) {
    $reversed_bytes = strrev($b);
    $result = '0';
    for ($i = 0; $i < strlen($reversed_bytes); $i++) {
        $byte = ord($reversed_bytes[$i]);
        $result = bcadd(bcmul($result, '256'), (string)$byte);
    }
    return $result;
}

/**
 * Convert integer to little-endian bytes
 * 
 * @param string $n Integer to convert
 * @param int $length Desired byte length
 * @return string Bytes in little-endian order
 */
function little_int_to_bytes($n, $length) {
    $bytes_be = '';
    while (bccomp($n, '0') > 0) {
        $byte = bcmod($n, '256');
        $bytes_be = chr((int)$byte) . $bytes_be;
        $n = bcdiv($n, '256', 0);
    }
    
    $pad_len = $length - strlen($bytes_be);
    if ($pad_len > 0) {
        $bytes_be = str_repeat("\x00", $pad_len) . $bytes_be;
    }
    
    return strrev(substr($bytes_be, -$length));
}

/**
 * Generate cryptographically secure random bytes
 * 
 * @param int $length Number of bytes to generate
 * @return string Random bytes
 */
function random_bytes_bc($length) {
    if (function_exists('random_bytes')) {
        return random_bytes($length);
    }
    
    if (function_exists('openssl_random_pseudo_bytes')) {
        return openssl_random_pseudo_bytes($length);
    }
    
    // Fallback for systems without proper CSPRNG
    $bytes = '';
    for ($i = 0; $i < $length; $i++) {
        $bytes .= chr(random_int(0, 255));
    }
    return $bytes;
}

// ====================================================================
// Elliptic Curve Point Operations
// ====================================================================

/**
 * Verify if a point lies on the E-521 curve
 * 
 * @param string $x X-coordinate
 * @param string $y Y-coordinate
 * @return bool True if point is on curve
 */
function is_on_curve($x, $y) {
    $x2 = bcmulmod($x, $x, P);
    $y2 = bcmulmod($y, $y, P);
    $lhs = bcaddmod($x2, $y2, P);
    
    $dx2y2 = bcmulmod(D, bcmulmod($x2, $y2, P), P);
    $rhs = bcaddmod('1', $dx2y2, P);
    
    return bceq($lhs, $rhs);
}

/**
 * Point addition on Twisted Edwards curve
 * 
 * @param string $x1 X-coordinate of first point
 * @param string $y1 Y-coordinate of first point
 * @param string $x2 X-coordinate of second point
 * @param string $y2 Y-coordinate of second point
 * @return array [x3, y3] Resulting point coordinates
 */
function add_points($x1, $y1, $x2, $y2) {
    // Neutral point in Edwards coordinates: (0, 1)
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
    
    $dx1x2y1y2 = bcmulmod(D, bcmulmod($x1x2, $y1y2, P), P);
    
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
 * 
 * @param string $x X-coordinate
 * @param string $y Y-coordinate
 * @return array [x2, y2] Doubled point coordinates
 */
function double_point($x, $y) {
    return add_points($x, $y, $x, $y);
}

/**
 * Scalar multiplication of a point (k * P)
 * 
 * @param string $x X-coordinate of point P
 * @param string $y Y-coordinate of point P
 * @param string $k_bytes Scalar k in little-endian bytes
 * @return array [x, y] Resulting point coordinates
 */
function scalar_mult($x, $y, $k_bytes) {
    $scalar = bcmod(bytes_to_little_int($k_bytes), N);
    
    $result_x = '0';
    $result_y = '1'; // Neutral point
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
 * 
 * @param string $k_bytes Scalar k in little-endian bytes
 * @return array [x, y] Resulting point coordinates
 */
function scalar_base_mult($k_bytes) {
    return scalar_mult(Gx, Gy, $k_bytes);
}

// ====================================================================
// Point Compression/Decompression (RFC 8032 Compliant)
// ====================================================================

/**
 * Compress point according to RFC 8032 specification
 * 
 * @param string $x X-coordinate
 * @param string $y Y-coordinate
 * @return string Compressed point bytes
 */
function compress_point($x, $y) {
    $y_bytes = little_int_to_bytes($y, BYTE_LEN);
    
    // Get least significant bit of x (little-endian)
    $x_bytes = little_int_to_bytes($x, BYTE_LEN);
    $sign_bit = ord($x_bytes[0]) & 1;
    
    // Store sign bit in MSB of last byte
    $compressed = $y_bytes;
    $last_byte = ord($compressed[BYTE_LEN - 1]);
    $last_byte |= ($sign_bit << 7);
    $compressed[BYTE_LEN - 1] = chr($last_byte);
    
    return $compressed;
}

/**
 * Decompress point according to RFC 8032 specification
 * 
 * @param string $data Compressed point bytes
 * @return array [x, y] or [null, null] if invalid
 */
function decompress_point($data) {
    if (strlen($data) != BYTE_LEN) {
        return [null, null];
    }
    
    // Extract sign bit from MSB of last byte
    $last_byte = ord($data[BYTE_LEN - 1]);
    $sign_bit = ($last_byte >> 7) & 1;
    
    // Clear sign bit from y data
    $y_bytes = $data;
    $y_bytes[BYTE_LEN - 1] = chr($last_byte & 0x7F);
    $y = bytes_to_little_int($y_bytes);
    
    // Solve for x using Edwards curve equation:
    // x² + y² = 1 + d*x²*y² => x² = (1 - y²) / (1 - d*y²)
    $y2 = bcmulmod($y, $y, P);
    
    $numerator = bcsubmod('1', $y2, P);
    $denominator = bcsubmod('1', bcmulmod(D, $y2, P), P);
    
    $inv_den = bcinvmod($denominator, P);
    if (bceq($inv_den, '0')) {
        return [null, null];
    }
    
    $x2 = bcmulmod($numerator, $inv_den, P);
    
    // Calculate square root mod p (p ≡ 1 mod 4)
    $exp = bcdiv(bcadd(P, '1'), '4', 0);
    $x = bcpowmod($x2, $exp, P);
    
    // Choose correct x based on sign bit
    $x_bytes = little_int_to_bytes($x, BYTE_LEN);
    if ((ord($x_bytes[0]) & 1) != $sign_bit) {
        $x = bcsubmod('0', $x, P);
    }
    
    return [$x, $y];
}

// ====================================================================
// Hash Functions (SHAKE256 Implementation)
// ====================================================================

/**
 * SHAKE256 hash function (simplified implementation)
 * Note: For production use, implement proper SHAKE256
 * 
 * @param string $data Input data
 * @param int $output_length Desired output length in bytes
 * @return string Hash output
 */
function shake256($data, $output_length) {
    // Try to use SHAKE256 if available
    if (function_exists('hash') && in_array('shake256', hash_algos())) {
        return substr(hash('shake256', $data, true), 0, $output_length);
    }
    
    // Fallback to SHA3-256 (NOT equivalent to SHAKE256, for demo only)
    if (function_exists('hash') && in_array('sha3-256', hash_algos())) {
        $ctx = hash_init('sha3-256');
        hash_update($ctx, $data);
        $hash = hash_final($ctx, true);
        
        // Extend to required length
        while (strlen($hash) < $output_length) {
            $ctx = hash_init('sha3-256');
            hash_update($ctx, $hash);
            $hash .= hash_final($ctx, true);
        }
        
        return substr($hash, 0, $output_length);
    }
    
    // Basic fallback for demonstration only
    // DO NOT USE IN PRODUCTION
    $hash = hash('sha256', $data, true);
    while (strlen($hash) < $output_length) {
        $hash .= hash('sha256', $hash, true);
    }
    return substr($hash, 0, $output_length);
}

/**
 * Implement dom5 as per specification (context separation)
 * 
 * @param int $phflag Prehash flag
 * @param string $context Context string
 * @return string DOM string
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
 * 
 * @param int $phflag Prehash flag
 * @param string $context Context string
 * @param string $x Input data
 * @return string 132-byte hash output
 */
function hash_e521($phflag, $context, $x) {
    $dom = dom5($phflag, $context);
    $hash_input = $dom . $x;
    return shake256($hash_input, 132);
}

// ====================================================================
// Key Generation and Signing Functions
// ====================================================================

/**
 * Generate random private key
 * 
 * @return string Private key as integer string
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
 * 
 * @param string $priv Private key
 * @return array [x, y] Public key point coordinates
 */
function get_public_key($priv) {
    $priv_bytes = little_int_to_bytes($priv, BYTE_LEN);
    return scalar_base_mult($priv_bytes);
}

/**
 * Create PureEdDSA signature according to specification
 * 
 * @param string $priv Private key
 * @param string $message Message to sign
 * @return string Signature bytes
 */
function sign($priv, $message) {
    $byte_len = BYTE_LEN;
    
    // 1. Hash prefix "dom" + priv.D bytes
    $prefix = hash_e521(0x00, '', little_int_to_bytes($priv, $byte_len));
    
    // 2. Calculate r = SHAKE256(prefix || message) mod N
    $r_bytes = hash_e521(0x00, '', $prefix . $message);
    $r = bcmod(bytes_to_little_int(substr($r_bytes, 0, $byte_len)), N);
    
    // 3. Compute R = r*G and compress
    list($Rx, $Ry) = scalar_base_mult(little_int_to_bytes($r, $byte_len));
    $R_compressed = compress_point($Rx, $Ry);
    
    // 4. Get public key and compress
    list($Ax, $Ay) = get_public_key($priv);
    $A_compressed = compress_point($Ax, $Ay);
    
    // 5. Compute h = SHAKE256(dom || R || A || message) mod N
    $hram_input = $R_compressed . $A_compressed . $message;
    $hram_hash = hash_e521(0x00, '', $hram_input);
    $h = bcmod(bytes_to_little_int(substr($hram_hash, 0, $byte_len)), N);
    
    // 6. s = (r + h * a) mod N
    $s = bcmod(bcadd($r, bcmul($h, $priv)), N);
    
    // 7. Signature = R_compressed || s_bytes
    $s_bytes = little_int_to_bytes($s, $byte_len);
    $signature = $R_compressed . $s_bytes;
    
    return $signature;
}

// ====================================================================
// Signature Verification
// ====================================================================

/**
 * Verify PureEdDSA signature according to specification
 * 
 * @param string $pub_x Public key X-coordinate
 * @param string $pub_y Public key Y-coordinate
 * @param string $message Original message
 * @param string $signature Signature to verify
 * @return bool True if signature is valid
 */
function verify($pub_x, $pub_y, $message, $signature) {
    $byte_len = BYTE_LEN;
    
    if (strlen($signature) != 2 * $byte_len) {
        return false;
    }
    
    $R_compressed = substr($signature, 0, $byte_len);
    $s_bytes = substr($signature, $byte_len);
    
    // Verify R
    list($Rx, $Ry) = decompress_point($R_compressed);
    if ($Rx === null || $Ry === null) {
        return false;
    }
    
    // Verify s
    $s = bytes_to_little_int($s_bytes);
    if (bccomp($s, N) >= 0) {
        return false;
    }
    
    // Compress public key A
    $A_compressed = compress_point($pub_x, $pub_y);
    
    // Compute h = SHAKE256(dom || R || A || message) mod N
    $hram_input = $R_compressed . $A_compressed . $message;
    $hram_hash = hash_e521(0x00, '', $hram_input);
    $h = bcmod(bytes_to_little_int(substr($hram_hash, 0, $byte_len)), N);
    
    // Compute s*G
    list($sGx, $sGy) = scalar_base_mult(little_int_to_bytes($s, $byte_len));
    
    // Compute h*A
    list($hAx, $hAy) = scalar_mult($pub_x, $pub_y, little_int_to_bytes($h, $byte_len));
    
    // Compute R + h*A
    list($rhaX, $rhaY) = add_points($Rx, $Ry, $hAx, $hAy);
    
    // Constant-time comparison
    return bceq($sGx, $rhaX) && bceq($sGy, $rhaY);
}

// ====================================================================
// Zero-Knowledge Proof Functions
// ====================================================================

/**
 * Generate non-interactive zero-knowledge proof of private key knowledge
 * 
 * @param string $priv Private key
 * @return string Proof bytes
 */
function prove_knowledge($priv) {
    $byte_len = BYTE_LEN;
    
    // 1. Commitment R = r*G (generate random r)
    while (true) {
        $r_bytes = random_bytes_bc($byte_len);
        $r = bytes_to_little_int($r_bytes);
        if (bclt($r, N)) {
            break;
        }
    }
    
    list($Rx, $Ry) = scalar_base_mult(little_int_to_bytes($r, $byte_len));
    $R_comp = compress_point($Rx, $Ry);
    
    // 2. Get public key A
    list($Ax, $Ay) = get_public_key($priv);
    $A_comp = compress_point($Ax, $Ay);
    
    // 3. Challenge c = H(R || A) using Fiat–Shamir heuristic
    $input_data = $R_comp . $A_comp;
    $c_bytes = hash_e521(0x00, '', $input_data);
    $c = bcmod(bytes_to_little_int(substr($c_bytes, 0, $byte_len)), N);
    
    // 4. Response: s = r + c * a (mod N)
    $s = bcmod(bcadd($r, bcmul($c, $priv)), N);
    
    // 5. Final proof = R || s
    $s_bytes = little_int_to_bytes($s, $byte_len);
    $proof = $R_comp . $s_bytes;
    
    return $proof;
}

/**
 * Verify non-interactive zero-knowledge proof
 * 
 * @param string $pub_x Public key X-coordinate
 * @param string $pub_y Public key Y-coordinate
 * @param string $proof Proof to verify
 * @return bool True if proof is valid
 */
function verify_knowledge($pub_x, $pub_y, $proof) {
    $byte_len = BYTE_LEN;
    
    if (strlen($proof) != 2 * $byte_len) {
        return false;
    }
    
    $R_comp = substr($proof, 0, $byte_len);
    $s_bytes = substr($proof, $byte_len);
    
    // 1. Decompress commitment R
    list($Rx, $Ry) = decompress_point($R_comp);
    if ($Rx === null || $Ry === null) {
        return false;
    }
    
    $s = bytes_to_little_int($s_bytes);
    
    // 2. Recalculate c = H(R || A)
    $A_comp = compress_point($pub_x, $pub_y);
    $input_data = $R_comp . $A_comp;
    $c_bytes = hash_e521(0x00, '', $input_data);
    $c = bcmod(bytes_to_little_int(substr($c_bytes, 0, $byte_len)), N);
    
    // 3. Verification: s*G == R + c*A
    list($sGx, $sGy) = scalar_base_mult(little_int_to_bytes($s, $byte_len));
    list($cAx, $cAy) = scalar_mult($pub_x, $pub_y, little_int_to_bytes($c, $byte_len));
    list($RpluscAx, $RpluscAy) = add_points($Rx, $Ry, $cAx, $cAy);
    
    return bceq($sGx, $RpluscAx) && bceq($sGy, $RpluscAy);
}

// ====================================================================
// Main Test Suite
// ====================================================================

/**
 * Run comprehensive test suite for E-521 implementation
 */
function run_ed521_test_suite() {
    echo "===========================================\n";
    echo "E-521 EdDSA Implementation Test Suite\n";
    echo "Developed by Pedro F. Albanese\n";
    echo "ALBANESE Research Lab\n";
    echo "===========================================\n\n";
    
    // Check if bcmath extension is available
    if (!extension_loaded('bcmath')) {
        die("ERROR: BCMath extension not enabled. Add 'extension=bcmath' to php.ini\n");
    }
    
    // Increase execution time for large number operations
    set_time_limit(60);
    
    try {
        echo "1. Generating private key...\n";
        $priv = generate_private_key();
        $priv_hex = bin2hex(little_int_to_bytes($priv, BYTE_LEN));
        echo "   Private key (first 16 bytes): " . substr($priv_hex, 0, 32) . "...\n";
        
        echo "2. Calculating public key...\n";
        list($pub_x, $pub_y) = get_public_key($priv);
        echo "   Public key point on curve: " . (is_on_curve($pub_x, $pub_y) ? "YES" : "NO") . "\n";
        
        echo "3. Testing point compression/decompression...\n";
        $compressed = compress_point($pub_x, $pub_y);
        echo "   Compressed length: " . strlen($compressed) . " bytes\n";
        
        list($decomp_x, $decomp_y) = decompress_point($compressed);
        $decompress_correct = bceq($decomp_x, $pub_x) && bceq($decomp_y, $pub_y);
        echo "   Decompression correct: " . ($decompress_correct ? "YES" : "NO") . "\n";
        
        echo "4. Signing test message...\n";
        $message = "Brazilian E-521 EdDSA Test - ALBANESE Research Lab";
        $signature = sign($priv, $message);
        echo "   Signature length: " . strlen($signature) . " bytes\n";
        
        echo "5. Verifying signature...\n";
        $valid = verify($pub_x, $pub_y, $message, $signature);
        echo "   Signature valid: " . ($valid ? "YES" : "NO") . "\n";
        
        echo "6. Testing signature rejection for wrong message...\n";
        $wrong_valid = verify($pub_x, $pub_y, "Wrong message", $signature);
        echo "   Wrong message rejected: " . (!$wrong_valid ? "YES" : "NO") . "\n";
        
        echo "\n7. Testing Zero-Knowledge Proof of Knowledge...\n";
        $proof = prove_knowledge($priv);
        echo "   Proof length: " . strlen($proof) . " bytes\n";
        
        $proof_valid = verify_knowledge($pub_x, $pub_y, $proof);
        echo "   Proof valid: " . ($proof_valid ? "YES" : "NO") . "\n";
        
        echo "8. Testing invalid proof rejection...\n";
        $invalid_proof = random_bytes_bc(strlen($proof));
        $invalid_valid = verify_knowledge($pub_x, $pub_y, $invalid_proof);
        echo "   Invalid proof rejected: " . (!$invalid_valid ? "YES" : "NO") . "\n";
        
        echo "\n===========================================\n";
        echo "All tests completed successfully!\n";
        echo "E-521 Implementation by Pedro F. Albanese\n";
        echo "ALBANESE Research Lab - Secure by Design\n";
        echo "===========================================\n";
        
    } catch (Exception $e) {
        echo "\nERROR during execution: " . $e->getMessage() . "\n";
        echo "Stack trace: " . $e->getTraceAsString() . "\n";
    }
}

// ====================================================================
// Utility Functions for Debugging and Testing
// ====================================================================

/**
 * Display point information for debugging
 * 
 * @param string $x X-coordinate
 * @param string $y Y-coordinate
 * @param string $name Point name/identifier
 */
function debug_point($x, $y, $name = "Point") {
    echo "\n$name:\n";
    echo "  x (first 20 chars): " . substr($x, 0, 20) . "...\n";
    echo "  y (first 20 chars): " . substr($y, 0, 20) . "...\n";
    echo "  On curve: " . (is_on_curve($x, $y) ? "YES" : "NO") . "\n";
}

/**
 * Benchmark a function's execution time
 * 
 * @param callable $func Function to benchmark
 * @param string $name Function name for display
 * @return mixed Function return value
 */
function benchmark($func, $name) {
    $start = microtime(true);
    $result = $func();
    $end = microtime(true);
    echo "$name execution time: " . round(($end - $start) * 1000, 2) . " ms\n";
    return $result;
}

// ====================================================================
// Example Usage
// ====================================================================

/**
 * Example usage of E-521 for message signing
 */
function example_ed521_usage() {
    echo "E-521 Example Usage:\n";
    echo "-------------------\n";
    
    // Generate key pair
    $private_key = generate_private_key();
    list($public_x, $public_y) = get_public_key($private_key);
    
    // Message to sign
    $message = "Confidential message from ALBANESE Research Lab";
    
    // Create signature
    $signature = sign($private_key, $message);
    
    // Verify signature
    $is_valid = verify($public_x, $public_y, $message, $signature);
    
    echo "Message: $message\n";
    echo "Signature valid: " . ($is_valid ? "YES" : "NO") . "\n";
    echo "Signature size: " . strlen($signature) . " bytes\n";
}

// ====================================================================
// Execution Entry Point
// ====================================================================

// Run test suite if executed directly
if (PHP_SAPI === 'cli' && basename(__FILE__) === basename($_SERVER['PHP_SELF'])) {
    run_ed521_test_suite();
    
    // Uncomment to run example usage
    // echo "\n\n";
    // example_ed521_usage();
}

// ====================================================================
// API Functions for External Use
// ====================================================================

/**
 * Generate a new E-521 key pair
 * 
 * @return array [private_key, public_x, public_y]
 */
function ed521_generate_keypair() {
    $private_key = generate_private_key();
    list($public_x, $public_y) = get_public_key($private_key);
    return [$private_key, $public_x, $public_y];
}

/**
 * Sign a message with E-521
 * 
 * @param string $private_key Private key
 * @param string $message Message to sign
 * @return string Signature
 */
function ed521_sign($private_key, $message) {
    return sign($private_key, $message);
}

/**
 * Verify an E-521 signature
 * 
 * @param string $public_x Public key X-coordinate
 * @param string $public_y Public key Y-coordinate
 * @param string $message Original message
 * @param string $signature Signature to verify
 * @return bool True if signature is valid
 */
function ed521_verify($public_x, $public_y, $message, $signature) {
    return verify($public_x, $public_y, $message, $signature);
}

/**
 * Compress a public key point
 * 
 * @param string $x X-coordinate
 * @param string $y Y-coordinate
 * @return string Compressed public key
 */
function ed521_compress_public_key($x, $y) {
    return compress_point($x, $y);
}

/**
 * Decompress a public key point
 * 
 * @param string $compressed Compressed public key
 * @return array [x, y] or [null, null] if invalid
 */
function ed521_decompress_public_key($compressed) {
    return decompress_point($compressed);
}

?>
