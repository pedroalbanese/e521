<?php

/**
 * Brazilian Ed521 (E-521) — Pure PHP implementation using GMP
 *
 * Byte-compatible with the Go implementation at
 * github.com/pedroalbanese/e521.
 *
 * Requires the GMP extension (php-gmp).
 * Uses PHP's native hash('shake256') when available (PHP 8.1+);
 * otherwise falls back to a pure GMP SHAKE256.
 *
 * @author Pedro F. Albanese <pedroalbanese@hotmail.com>
 * @copyright ALBANESE Research Lab
 * @license ISC
 * @version 2.0.0
 */

if (!extension_loaded('gmp')) {
    die("GMP extension is required. Please install php-gmp.\n");
}

// ====================================================================
// E-521 curve parameters
// ====================================================================
define('P', gmp_init('6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151', 10));
define('N', gmp_init('1716199415032652428745475199770348304317358825035826352348615864796385795849413675475876651663657849636693659065234142604319282948702542317993421293670108523', 10));
define('D_RAW', gmp_init('-376014', 10));
define('D', gmp_mod(gmp_add(D_RAW, P), P));
define('GX', gmp_init('1571054894184995387535939749894317568645297350402905821437625181152304994381188529632591196067604100772673927915114267193389905003276673749012051148356041324', 10));
define('GY', gmp_init('12', 10));
define('BIT_SIZE', 521);
define('BYTE_LEN', 66);

// OID 1.3.6.1.4.1.44588.2.1 (DER-encoded content, without tag/length)
define('OID_DER', "\x06\x0a\x2b\x06\x01\x04\x01\x82\xdc\x2c\x02\x01");

// ====================================================================
// GMP helpers
// ====================================================================
function gaddmod($a, $b, $m) { return gmp_mod(gmp_add($a, $b), $m); }
function gsubmod($a, $b, $m) { return gmp_mod(gmp_add(gmp_sub($a, $b), $m), $m); }
function gmulmod($a, $b, $m) { return gmp_mod(gmp_mul($a, $b), $m); }

function ginvmod($a, $m) {
    $inv = gmp_invert($a, $m);
    return $inv === false ? gmp_init(0) : $inv;
}

function geq($a, $b) { return gmp_cmp($a, $b) === 0; }

// ====================================================================
// Byte helpers (little-endian)
// ====================================================================
function bytes_to_little_int($b) {
    $len = strlen($b);
    if ($len === 0) return gmp_init(0);
    return gmp_import(strrev($b), 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);
}

function little_int_to_bytes($n, $length) {
    if (gmp_sign($n) < 0) {
        throw new Exception("negative not supported");
    }
    if (gmp_sign($n) === 0) {
        return str_repeat("\x00", $length);
    }
    $be = gmp_export($n, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);
    if (strlen($be) > $length) {
        $be = substr($be, -$length);
    } elseif (strlen($be) < $length) {
        $be = str_repeat("\x00", $length - strlen($be)) . $be;
    }
    return strrev($be);
}

function hex_to_bytes_strict($h) {
    $h = preg_replace('/\s+/', '', $h);
    if (strlen($h) % 2 !== 0) throw new Exception("odd hex length");
    if (!ctype_xdigit($h)) throw new Exception("non-hex characters");
    return hex2bin($h);
}

function random_bytes_gmp($length) {
    if (function_exists('random_bytes')) return random_bytes($length);
    $out = '';
    for ($i = 0; $i < $length; $i++) $out .= chr(random_int(0, 255));
    return $out;
}

// ====================================================================
// SHAKE256 — native hash() (PHP 8.1+), fallback GMP
// ====================================================================
define('SHAKE256_RATE', 136);
define('MASK64', gmp_init('18446744073709551615', 10));

function shake256($input, $outputLength) {
    if (function_exists('hash') && in_array('shake256', hash_algos(), true)) {
        try {
            $out = hash('shake256', $input, true, ['size' => $outputLength]);
            if (is_string($out) && strlen($out) === $outputLength) {
                return $out;
            }
        } catch (Throwable $e) {
            // fall through to GMP
        }
    }
    return _shake256_gmp($input, $outputLength);
}

function _shake256_gmp($input, $outputLength) {
    $rate = SHAKE256_RATE;
    $dsbyte = 0x1F;
    $state = array_fill(0, 25, gmp_init(0));
    $buffer = array_fill(0, $rate, 0);
    $bufPos = 0;
    $inputLen = strlen($input);
    $pos = 0;

    while ($pos < $inputLen) {
        $toXor = min($rate - $bufPos, $inputLen - $pos);
        for ($i = 0; $i < $toXor; $i++) {
            $buffer[$bufPos + $i] ^= ord($input[$pos + $i]);
        }
        $bufPos += $toXor;
        $pos += $toXor;

        if ($bufPos === $rate) {
            _shake_absorb($state, $buffer, $rate);
            _keccak_f1600($state);
            $buffer = array_fill(0, $rate, 0);
            $bufPos = 0;
        }
    }

    $buffer[$bufPos] ^= $dsbyte;
    $buffer[$rate - 1] ^= 0x80;
    _shake_absorb($state, $buffer, $rate);
    _keccak_f1600($state);

    $output = '';
    $extracted = 0;
    while ($extracted < $outputLength) {
        for ($i = 0; $i < $rate && $extracted < $outputLength; $i++) {
            $lane = (int)($i / 8);
            $shift = ($i % 8) * 8;
            $byte = gmp_intval(gmp_mod(gmp_div_q($state[$lane], gmp_pow(gmp_init(2), $shift)), gmp_init(256)));
            $output .= chr($byte);
            $extracted++;
        }
        if ($extracted < $outputLength) _keccak_f1600($state);
    }
    return $output;
}

function _shake_absorb(&$state, &$buffer, $rate) {
    $b256 = gmp_init(256);
    for ($i = 0; $i < $rate; $i += 8) {
        $word = gmp_init(0);
        $pow = gmp_init(1);
        for ($j = 0; $j < 8 && ($i + $j) < $rate; $j++) {
            $byte = $buffer[$i + $j];
            if ($byte !== 0) {
                $word = gmp_add($word, gmp_mul(gmp_init($byte), $pow));
            }
            $pow = gmp_mul($pow, $b256);
        }
        $state[$i / 8] = gmp_and(gmp_xor($state[$i / 8], $word), MASK64);
    }
}

$GLOBALS['SHAKE_RC'] = null;
$GLOBALS['SHAKE_ROTC'] = [1,3,6,10,15,21,28,36,45,55,2,14,27,41,56,8,25,43,62,18,39,61,20,44];
$GLOBALS['SHAKE_PILN'] = [10,7,11,17,18,3,5,16,8,21,24,4,15,23,19,13,12,2,20,14,22,9,6,1];

function _shake_init_rc() {
    if ($GLOBALS['SHAKE_RC'] !== null) return;
    $rc_hex = [
        '0000000000000001','0000000000008082','800000000000808A','8000000080008000',
        '000000000000808B','0000000080000001','8000000080008081','8000000000008009',
        '000000000000008A','0000000000000088','0000000080008009','000000008000000A',
        '000000008000808B','800000000000008B','8000000000008089','8000000000008003',
        '8000000000008002','8000000000000080','000000000000800A','800000008000000A',
        '8000000080008081','8000000000008080','0000000080000001','8000000080008008',
    ];
    $rc = [];
    foreach ($rc_hex as $h) $rc[] = gmp_init($h, 16);
    $GLOBALS['SHAKE_RC'] = $rc;
}

function _rotl64($x, $k) {
    $k = $k % 64;
    if ($k === 0) return $x;
    $x = gmp_and($x, MASK64);
    $left  = gmp_and(gmp_mul($x, gmp_pow(gmp_init(2), $k)), MASK64);
    $right = gmp_div_q($x, gmp_pow(gmp_init(2), 64 - $k));
    return gmp_or($left, $right);
}

function _keccak_f1600(&$state) {
    _shake_init_rc();
    $RC = $GLOBALS['SHAKE_RC'];
    $rotc = $GLOBALS['SHAKE_ROTC'];
    $piln = $GLOBALS['SHAKE_PILN'];

    for ($round = 0; $round < 24; $round++) {
        $c0 = gmp_xor($state[0], gmp_xor($state[5], gmp_xor($state[10], gmp_xor($state[15], $state[20]))));
        $c1 = gmp_xor($state[1], gmp_xor($state[6], gmp_xor($state[11], gmp_xor($state[16], $state[21]))));
        $c2 = gmp_xor($state[2], gmp_xor($state[7], gmp_xor($state[12], gmp_xor($state[17], $state[22]))));
        $c3 = gmp_xor($state[3], gmp_xor($state[8], gmp_xor($state[13], gmp_xor($state[18], $state[23]))));
        $c4 = gmp_xor($state[4], gmp_xor($state[9], gmp_xor($state[14], gmp_xor($state[19], $state[24]))));

        $d0 = gmp_xor(_rotl64($c1, 1), $c4);
        $d1 = gmp_xor(_rotl64($c2, 1), $c0);
        $d2 = gmp_xor(_rotl64($c3, 1), $c1);
        $d3 = gmp_xor(_rotl64($c4, 1), $c2);
        $d4 = gmp_xor(_rotl64($c0, 1), $c3);

        for ($i = 0; $i < 25; $i += 5) {
            $state[$i]     = gmp_and(gmp_xor($state[$i],     $d0), MASK64);
            $state[$i + 1] = gmp_and(gmp_xor($state[$i + 1], $d1), MASK64);
            $state[$i + 2] = gmp_and(gmp_xor($state[$i + 2], $d2), MASK64);
            $state[$i + 3] = gmp_and(gmp_xor($state[$i + 3], $d3), MASK64);
            $state[$i + 4] = gmp_and(gmp_xor($state[$i + 4], $d4), MASK64);
        }

        $b = array_fill(0, 25, gmp_init(0));
        $current = $state[1];
        for ($i = 0; $i < 24; $i++) {
            $b[$piln[$i]] = _rotl64($current, $rotc[$i]);
            $current = $state[$piln[$i]];
        }
        $b[0] = $state[0];

        for ($y = 0; $y < 25; $y += 5) {
            $t0 = $b[$y]; $t1 = $b[$y+1]; $t2 = $b[$y+2]; $t3 = $b[$y+3]; $t4 = $b[$y+4];
            $state[$y]     = gmp_and(gmp_xor($t0, gmp_and(gmp_com($t1), $t2)), MASK64);
            $state[$y + 1] = gmp_and(gmp_xor($t1, gmp_and(gmp_com($t2), $t3)), MASK64);
            $state[$y + 2] = gmp_and(gmp_xor($t2, gmp_and(gmp_com($t3), $t4)), MASK64);
            $state[$y + 3] = gmp_and(gmp_xor($t3, gmp_and(gmp_com($t4), $t0)), MASK64);
            $state[$y + 4] = gmp_and(gmp_xor($t4, gmp_and(gmp_com($t0), $t1)), MASK64);
        }

        $state[0] = gmp_and(gmp_xor($state[0], $RC[$round]), MASK64);
    }
}

// ====================================================================
// Curve operations (Edwards form, Go-compatible)
// ====================================================================
function is_on_curve($x, $y) {
    $x2 = gmulmod($x, $x, P);
    $y2 = gmulmod($y, $y, P);
    $lhs = gaddmod($x2, $y2, P);
    $dx2y2 = gmulmod(D, gmulmod($x2, $y2, P), P);
    $rhs = gaddmod(gmp_init(1), $dx2y2, P);
    return geq($lhs, $rhs);
}

function add_points($x1, $y1, $x2, $y2) {
    // Go treats (0,0) as neutral (non-canonical)
    if (gmp_sign($x1) === 0 && gmp_sign($y1) === 0) return [$x2, $y2];
    if (gmp_sign($x2) === 0 && gmp_sign($y2) === 0) return [$x1, $y1];

    $x1y2 = gmulmod($x1, $y2, P);
    $y1x2 = gmulmod($y1, $x2, P);
    $num_x = gaddmod($x1y2, $y1x2, P);

    $y1y2 = gmulmod($y1, $y2, P);
    $x1x2 = gmulmod($x1, $x2, P);
    $num_y = gsubmod($y1y2, $x1x2, P);

    $dx1x2y1y2 = gmulmod(D, gmulmod($x1x2, $y1y2, P), P);

    $den_x = gaddmod(gmp_init(1), $dx1x2y1y2, P);
    $den_y = gsubmod(gmp_init(1), $dx1x2y1y2, P);

    $inv_x = ginvmod($den_x, P);
    $inv_y = ginvmod($den_y, P);

    $x3 = gmulmod($num_x, $inv_x, P);
    $y3 = gmulmod($num_y, $inv_y, P);
    return [$x3, $y3];
}

function double_point($x, $y) { return add_points($x, $y, $x, $y); }

function scalar_mult($x, $y, $k_bytes) {
    $scalar = gmp_mod(bytes_to_little_int($k_bytes), N);
    $rx = gmp_init(0); $ry = gmp_init(1);
    $tx = $x; $ty = $y;
    while (gmp_sign($scalar) > 0) {
        if (gmp_testbit($scalar, 0)) {
            list($rx, $ry) = add_points($rx, $ry, $tx, $ty);
        }
        list($tx, $ty) = double_point($tx, $ty);
        $scalar = gmp_div_q($scalar, gmp_init(2));
    }
    return [$rx, $ry];
}

function scalar_base_mult($k_bytes) { return scalar_mult(GX, GY, $k_bytes); }

// ====================================================================
// Compress / decompress (RFC 8032 style)
// ====================================================================
function compress_point($x, $y) {
    $y_bytes = little_int_to_bytes($y, BYTE_LEN);
    $x_lsb = gmp_intval(gmp_mod($x, gmp_init(2)));
    $last = ord($y_bytes[BYTE_LEN - 1]);
    if ($x_lsb === 1) $last |= 0x80;
    else              $last &= 0x7F;
    $y_bytes[BYTE_LEN - 1] = chr($last);
    return $y_bytes;
}

function sqrt_mod_p($a) {
    $a = gmp_mod($a, P);
    if (gmp_sign($a) === 0) return gmp_init(0);
    // E-521: p = 2^521 - 1 ≡ 7 (mod 8), so x = a^((p+1)/4) mod p
    $exp = gmp_div_q(gmp_add(P, gmp_init(1)), gmp_init(4));
    $x = gmp_powm($a, $exp, P);
    if (geq(gmulmod($x, $x, P), $a)) return $x;
    return null;
}

function decompress_point($data) {
    if (strlen($data) !== BYTE_LEN) return [null, null];
    $last = ord($data[BYTE_LEN - 1]);
    $sign_bit = ($last >> 7) & 1;
    $y_bytes = $data;
    $y_bytes[BYTE_LEN - 1] = chr($last & 0x7F);
    $y = bytes_to_little_int($y_bytes);
    if (gmp_cmp($y, P) >= 0) return [null, null];

    $y2 = gmulmod($y, $y, P);
    $num = gsubmod(gmp_init(1), $y2, P);
    $den = gsubmod(gmp_init(1), gmulmod(D, $y2, P), P);

    $inv = ginvmod($den, P);
    if (gmp_sign($inv) === 0) return [null, null];

    $x2 = gmulmod($num, $inv, P);
    $x = sqrt_mod_p($x2);
    if ($x === null) return [null, null];
    if (gmp_sign($x) === 0 && $sign_bit === 1) return [null, null];

    $x_lsb = gmp_intval(gmp_mod($x, gmp_init(2)));
    if ($x_lsb !== $sign_bit) $x = gsubmod(gmp_init(0), $x, P);

    return [$x, $y];
}

// ====================================================================
// dom5 / hash_e521
// ====================================================================
function dom5($phflag, $context) {
    if (strlen($context) > 255) throw new Exception("context too long for dom5");
    return "SigEd521" . chr($phflag) . chr(strlen($context)) . $context;
}

function hash_e521($phflag, $context, $x) {
    return shake256(dom5($phflag, $context) . $x, 132);
}

// ====================================================================
// Key generation, sign, verify (Go-compatible: D used directly)
// ====================================================================
function rand_little_int($max) {
    $bits = strlen(gmp_strval($max, 2));
    $byte_len = (int)(($bits + 7) / 8);
    while (true) {
        $buf = random_bytes_gmp($byte_len);
        $n = bytes_to_little_int($buf);
        if (gmp_cmp($n, $max) < 0) return $n;
    }
}

function generate_private_key() { return rand_little_int(N); }

function get_public_key($priv) {
    return scalar_base_mult(little_int_to_bytes($priv, BYTE_LEN));
}

function sign($priv, $message) {
    // 1. prefix = SHAKE256(dom5 || D_le, 132)
    $prefix = hash_e521(0x00, '', little_int_to_bytes($priv, BYTE_LEN));

    // 2. r = SHAKE256(dom5 || prefix || message, 132) mod N — all 132 bytes
    $r_bytes = hash_e521(0x00, '', $prefix . $message);
    $r = gmp_mod(bytes_to_little_int($r_bytes), N);

    // 3. R = r*G
    list($Rx, $Ry) = scalar_base_mult(little_int_to_bytes($r, BYTE_LEN));
    $R_comp = compress_point($Rx, $Ry);

    // 4. A = D*G
    list($Ax, $Ay) = scalar_base_mult(little_int_to_bytes($priv, BYTE_LEN));
    $A_comp = compress_point($Ax, $Ay);

    // 5. h = SHAKE256(dom5 || R || A || message, 132) mod N — all 132 bytes
    $h_hash = hash_e521(0x00, '', $R_comp . $A_comp . $message);
    $h = gmp_mod(bytes_to_little_int($h_hash), N);

    // 6. s = (h*D + r) mod N
    $s = gmp_mod(gmp_add(gmp_mul($h, $priv), $r), N);

    return $R_comp . little_int_to_bytes($s, BYTE_LEN);
}

function verify($pub_x, $pub_y, $message, $signature) {
    if (strlen($signature) !== 2 * BYTE_LEN) return false;

    $R_comp = substr($signature, 0, BYTE_LEN);
    $s = bytes_to_little_int(substr($signature, BYTE_LEN));
    if (gmp_cmp($s, N) >= 0) return false;

    list($Rx, $Ry) = decompress_point($R_comp);
    if ($Rx === null || $Ry === null) return false;

    $A_comp = compress_point($pub_x, $pub_y);
    $h_hash = hash_e521(0x00, '', $R_comp . $A_comp . $message);
    $h = gmp_mod(bytes_to_little_int($h_hash), N);

    list($sGx, $sGy) = scalar_base_mult(little_int_to_bytes($s, BYTE_LEN));
    list($hAx, $hAy) = scalar_mult($pub_x, $pub_y, little_int_to_bytes($h, BYTE_LEN));
    list($rha_x, $rha_y) = add_points($Rx, $Ry, $hAx, $hAy);

    return geq($sGx, $rha_x) && geq($sGy, $rha_y);
}

// ====================================================================
// ZKP (Go-compatible: c truncated to 66 bytes here, unlike sign/verify)
// ====================================================================
function prove_knowledge($priv) {
    $r = rand_little_int(N);
    list($Rx, $Ry) = scalar_base_mult(little_int_to_bytes($r, BYTE_LEN));
    $R_comp = compress_point($Rx, $Ry);

    list($Ax, $Ay) = scalar_base_mult(little_int_to_bytes($priv, BYTE_LEN));
    $A_comp = compress_point($Ax, $Ay);

    $c_bytes = hash_e521(0x00, '', $R_comp . $A_comp);
    $c = gmp_mod(bytes_to_little_int(substr($c_bytes, 0, BYTE_LEN)), N);

    $s = gmp_mod(gmp_add(gmp_mul($c, $priv), $r), N);
    return $R_comp . little_int_to_bytes($s, BYTE_LEN);
}

function verify_knowledge($pub_x, $pub_y, $proof) {
    if (strlen($proof) !== 2 * BYTE_LEN) return false;

    $R_comp = substr($proof, 0, BYTE_LEN);
    $s = bytes_to_little_int(substr($proof, BYTE_LEN));

    list($Rx, $Ry) = decompress_point($R_comp);
    if ($Rx === null || $Ry === null) return false;

    $A_comp = compress_point($pub_x, $pub_y);
    $c_bytes = hash_e521(0x00, '', $R_comp . $A_comp);
    $c = gmp_mod(bytes_to_little_int(substr($c_bytes, 0, BYTE_LEN)), N);

    list($sGx, $sGy) = scalar_base_mult(little_int_to_bytes($s, BYTE_LEN));
    list($cAx, $cAy) = scalar_mult($pub_x, $pub_y, little_int_to_bytes($c, BYTE_LEN));
    list($rca_x, $rca_y) = add_points($Rx, $Ry, $cAx, $cAy);

    return geq($sGx, $rca_x) && geq($sGy, $rca_y);
}

// ====================================================================
// Minimal DER encoder / decoder
// ====================================================================
function der_len($n) {
    if ($n < 0x80) return chr($n);
    $b = '';
    while ($n > 0) { $b = chr($n & 0xFF) . $b; $n >>= 8; }
    return chr(0x80 | strlen($b)) . $b;
}

function der_seq($content)    { return "\x30" . der_len(strlen($content)) . $content; }
function der_octet_string($b) { return "\x04" . der_len(strlen($b)) . $b; }

function der_int($n) {
    if ($n === 0) return "\x02\x01\x00";
    $b = '';
    while ($n > 0) { $b = chr($n & 0xFF) . $b; $n >>= 8; }
    if (ord($b[0]) & 0x80) $b = "\x00" . $b;
    return "\x02" . der_len(strlen($b)) . $b;
}

function der_bit_string($b, $unused = 0) {
    $content = chr($unused) . $b;
    return "\x03" . der_len(strlen($content)) . $content;
}

function der_read_tlv($data, $idx) {
    if ($idx >= strlen($data)) throw new Exception("DER: unexpected end");
    $tag = ord($data[$idx]); $idx++;
    if ($idx >= strlen($data)) throw new Exception("DER: unexpected end (length)");
    $first = ord($data[$idx]); $idx++;
    if ($first & 0x80) {
        $n = $first & 0x7F;
        if ($n === 0) throw new Exception("DER: indefinite length");
        if ($idx + $n > strlen($data)) throw new Exception("DER: truncated length");
        $length = 0;
        for ($i = 0; $i < $n; $i++) $length = ($length << 8) | ord($data[$idx + $i]);
        $idx += $n;
    } else {
        $length = $first;
    }
    if ($idx + $length > strlen($data)) throw new Exception("DER: truncated value");
    $value = substr($data, $idx, $length);
    return [$tag, $value, $idx + $length];
}

// ====================================================================
// PKCS#8 private / SPKI public (Go-compatible: Parameters = 06 00)
// ====================================================================
function private_key_to_pem($priv) {
    $priv_bytes = little_int_to_bytes($priv, BYTE_LEN);
    $alg_id = der_seq(OID_DER . "\x06\x00");
    $version = der_int(0);
    $priv_field = der_octet_string($priv_bytes);
    $pkcs8 = der_seq($version . $alg_id . $priv_field);

    $b64 = base64_encode($pkcs8);
    $lines = str_split($b64, 64);
    return "-----BEGIN E-521 PRIVATE KEY-----\n"
         . implode("\n", $lines)
         . "\n-----END E-521 PRIVATE KEY-----\n";
}

function public_key_to_pem($pub_x, $pub_y) {
    $compressed = compress_point($pub_x, $pub_y);
    $alg_id = der_seq(OID_DER . "\x06\x00");
    $bit_str = der_bit_string($compressed, 0);
    $spki = der_seq($alg_id . $bit_str);

    $b64 = base64_encode($spki);
    $lines = str_split($b64, 64);
    return "-----BEGIN E-521 PUBLIC KEY-----\n"
         . implode("\n", $lines)
         . "\n-----END E-521 PUBLIC KEY-----\n";
}

function _load_pem_b64($path, $expected_label) {
    $text = file_get_contents($path);
    if ($text === false) throw new Exception("file not found: $path");
    $lines = explode("\n", trim($text));
    $body = []; $in_block = false; $found = false;
    foreach ($lines as $line) {
        if (strpos($line, "-----BEGIN ") === 0) {
            if (strpos($line, $expected_label) !== false) { $in_block = true; $found = true; }
            else $in_block = false;
        } elseif (strpos($line, "-----END ") === 0) {
            $in_block = false;
        } elseif ($in_block) {
            $body[] = trim($line);
        }
    }
    if (!$found) throw new Exception("PEM: no '$expected_label' block in $path");
    return base64_decode(implode("", $body));
}

function read_private_key_from_pem($path) {
    $der = _load_pem_b64($path, "PRIVATE KEY");
    list($tag, $content, $_) = der_read_tlv($der, 0);
    if ($tag !== 0x30) throw new Exception("PKCS#8: expected SEQUENCE");

    $idx = 0;
    list($tag, $_, $idx) = der_read_tlv($content, $idx);
    if ($tag !== 0x02) throw new Exception("PKCS#8: expected INTEGER (version)");

    list($tag, $_, $idx) = der_read_tlv($content, $idx);
    if ($tag !== 0x30) throw new Exception("PKCS#8: expected AlgorithmIdentifier");

    list($tag, $key_bytes, $idx) = der_read_tlv($content, $idx);
    if ($tag !== 0x04) throw new Exception("PKCS#8: expected OCTET STRING");
    if (strlen($key_bytes) !== BYTE_LEN) throw new Exception("PKCS#8: unexpected key length");

    return bytes_to_little_int($key_bytes);
}

function read_public_key_from_pem($path) {
    $der = _load_pem_b64($path, "PUBLIC KEY");
    list($tag, $content, $_) = der_read_tlv($der, 0);
    if ($tag !== 0x30) throw new Exception("SPKI: expected SEQUENCE");

    $idx = 0;
    list($tag, $_, $idx) = der_read_tlv($content, $idx);
    if ($tag !== 0x30) throw new Exception("SPKI: expected AlgorithmIdentifier");

    list($tag, $bs, $idx) = der_read_tlv($content, $idx);
    if ($tag !== 0x03) throw new Exception("SPKI: expected BIT STRING");
    if (strlen($bs) < 1) throw new Exception("SPKI: empty BIT STRING");

    $unused = ord($bs[0]);
    if ($unused !== 0) throw new Exception("SPKI: unsupported unused bits ($unused)");

    $compressed = substr($bs, 1);
    if (strlen($compressed) !== BYTE_LEN) throw new Exception("SPKI: unexpected key length");

    list($x, $y) = decompress_point($compressed);
    if ($x === null || $y === null) throw new Exception("SPKI: failed to decompress");
    return [$x, $y];
}

// ====================================================================
// Self-tests
// ====================================================================
function test_core() {
    echo "Testing ED521 (E-521) — Go-compatible variant (PHP/GMP)\n";
    echo str_repeat("=", 70) . "\n";

    $priv = generate_private_key();
    list($pub_x, $pub_y) = get_public_key($priv);
    echo "1. Key generation: OK\n";

    $compressed = compress_point($pub_x, $pub_y);
    list($dx, $dy) = decompress_point($compressed);
    echo "2. Compress/decompress: " . (($dx !== null && geq($dx, $pub_x) && geq($dy, $pub_y)) ? "OK" : "FAILED") . "\n";

    $msg = "Test message";
    $sig = sign($priv, $msg);
    echo "3. Sign/verify: " . (verify($pub_x, $pub_y, $msg, $sig) ? "VALID" : "INVALID") . "\n";

    $other = "Another message";
    echo "4. Tampered message rejected: " . (!verify($pub_x, $pub_y, $other, $sig) ? "VALID" : "INVALID") . "\n";

    $proof = prove_knowledge($priv);
    echo "5. ZKP: " . (verify_knowledge($pub_x, $pub_y, $proof) ? "VALID" : "INVALID") . "\n";

    echo str_repeat("=", 70) . "\n";
}

function test_shake256() {
    echo 'SHAKE256("test", 132) = ' . bin2hex(shake256("test", 132)) . "\n";
    echo 'SHAKE256("", 132)     = ' . bin2hex(shake256("", 132)) . "\n";
}

// ====================================================================
// CURUPIRA block cipher (unchanged; operates on ints)
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
            if ($d >= 0x100) $d = $d ^ 0x14D;
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

    public function xtimes($u) { return $this->xtimes_table[$u & 0xFF]; }
    public function ctimes($u) {
        return $this->xtimes($this->xtimes($this->xtimes($this->xtimes($u) ^ $u) ^ $u));
    }
    public function sbox($u) { return $this->sbox_table[$u & 0xFF]; }

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
        if ($e) $v = $this->ctimes($v);
        else    $v = $this->ctimes($v) ^ $v;
        $b[0 + $d] = $a[0 + $d] ^ $v;
        $b[1 + $d] = $a[1 + $d] ^ $v;
        $b[2 + $d] = $a[2 + $d] ^ $v;
    }

    private function _apply_nonlinear_layer($a) {
        $r = [];
        foreach ($a as $x) $r[] = $this->sbox($x);
        return $r;
    }

    private function _apply_permutation_layer($a) {
        $b = array_fill(0, 12, 0);
        for ($i = 0; $i < 3; $i++)
            for ($j = 0; $j < 4; $j++)
                $b[$i + 3 * $j] = $a[$i + 3 * ($i ^ $j)];
        return $b;
    }

    private function _apply_linear_diffusion_layer($a) {
        $b = array_fill(0, 12, 0);
        for ($j = 0; $j < 4; $j++) $this->_dtimesa($a, $j, $b);
        return $b;
    }

    private function _apply_key_addition($a, $kr) {
        $r = [];
        for ($i = 0; $i < 12; $i++) $r[] = $a[$i] ^ $kr[$i];
        return $r;
    }

    private function _calculate_schedule_constant($s, $key_bits) {
        $t = (int)($key_bits / 48);
        $q = array_fill(0, 3 * 2 * $t, 0);
        if ($s == 0) return $q;
        for ($j = 0; $j < 2 * $t; $j++) $q[3 * $j] = $this->sbox(2 * $t * ($s - 1) + $j);
        return $q;
    }

    private function _apply_constant_addition($Kr, $subkey_rank, $key_bits, $t) {
        $b = $Kr;
        $q = $this->_calculate_schedule_constant($subkey_rank, $key_bits);
        for ($i = 0; $i < 3; $i++)
            for ($j = 0; $j < 2 * $t; $j++)
                $b[$i + 3 * $j] ^= $q[$i + 3 * $j];
        return $b;
    }

    private function _apply_cyclic_shift($a, $t) {
        $length = 3 * 2 * $t;
        $b = array_fill(0, $length, 0);
        for ($j = 0; $j < 2 * $t; $j++) {
            $b[3 * $j] = $a[3 * $j];
            $b[1 + 3 * $j] = $a[1 + 3 * (($j + 1) % (2 * $t))];
            if ($j > 0) $b[2 + 3 * $j] = $a[2 + 3 * (($j - 1) % (2 * $t))];
            else        $b[2] = $a[2 + 3 * (2 * $t - 1)];
        }
        return $b;
    }

    private function _apply_linear_diffusion($a, $t) {
        $length = 3 * 2 * $t;
        $b = array_fill(0, $length, 0);
        for ($j = 0; $j < 2 * $t; $j++) $this->_etimesa($a, $j, $b, true);
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
        for ($j = 0; $j < 4; $j++) $kr[3 * $j] = $this->sbox($Kr[3 * $j]);
        for ($i = 1; $i < 3; $i++)
            for ($j = 0; $j < 4; $j++)
                $kr[$i + 3 * $j] = $Kr[$i + 3 * $j];
        return $kr;
    }

    private function _expand_key() {
        $key_bits = $this->key_size * 8;
        if ($key_bits == 96)      $this->R = 10;
        elseif ($key_bits == 144) $this->R = 14;
        elseif ($key_bits == 192) $this->R = 18;

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

    private function _perform_whitening_round($a, $k0) { return $this->_apply_key_addition($a, $k0); }

    private function _perform_last_round($a, $kR) {
        return $this->_apply_key_addition(
            $this->_apply_permutation_layer($this->_apply_nonlinear_layer($a)),
            $kR
        );
    }

    private function _perform_round($a, $kr) {
        return $this->_apply_key_addition(
            $this->_apply_linear_diffusion_layer(
                $this->_apply_permutation_layer($this->_apply_nonlinear_layer($a))
            ),
            $kr
        );
    }

    private function _process_block($data, $round_keys) {
        $tmp = array_values(unpack('C*', $data));
        $tmp = $this->_perform_whitening_round($tmp, $round_keys[0]);
        for ($r = 1; $r < $this->R; $r++) $tmp = $this->_perform_round($tmp, $round_keys[$r]);
        $tmp = $this->_perform_last_round($tmp, $round_keys[$this->R]);
        return pack('C*', ...$tmp);
    }

    public function encrypt($plaintext) {
        if (strlen($plaintext) != self::BLOCK_SIZE) throw new Exception("Plaintext must be 12 bytes");
        return $this->_process_block($plaintext, $this->encryption_round_keys);
    }

    public function decrypt($ciphertext) {
        if (strlen($ciphertext) != self::BLOCK_SIZE) throw new Exception("Ciphertext must be 12 bytes");
        return $this->_process_block($ciphertext, $this->decryption_round_keys);
    }

    public function sct($data) {
        if (strlen($data) != self::BLOCK_SIZE) throw new Exception("Data must be 12 bytes");
        $tmp = array_values(unpack('C*', $data));
        $unkeyed_round = function($a) {
            return $this->_apply_linear_diffusion_layer(
                $this->_apply_permutation_layer($this->_apply_nonlinear_layer($a))
            );
        };
        $tmp = $unkeyed_round($tmp);
        for ($i = 0; $i < 3; $i++) $tmp = $unkeyed_round($tmp);
        return pack('C*', ...$tmp);
    }

    public function BlockSize() { return self::BLOCK_SIZE; }
}

// ====================================================================
// CURUPIRA CBC mode
// ====================================================================
function pad_pkcs7($data, $bs) {
    $pad = $bs - (strlen($data) % $bs);
    if ($pad == 0) $pad = $bs;
    return $data . str_repeat(chr($pad), $pad);
}

function unpad_pkcs7($data) {
    if (strlen($data) == 0) throw new Exception("Empty data");
    $pad = ord($data[strlen($data) - 1]);
    if ($pad > strlen($data)) throw new Exception("Invalid padding length");
    for ($i = 0; $i < $pad; $i++)
        if (ord($data[strlen($data) - $i - 1]) != $pad) throw new Exception("Invalid padding bytes");
    return substr($data, 0, -$pad);
}

function cbc_encrypt_curupira($key, $iv, $plaintext) {
    $cipher = new Curupira1($key);
    $bs = $cipher->BlockSize();
    $padded = pad_pkcs7($plaintext, $bs);
    $ct = ''; $prev = $iv;
    for ($i = 0; $i < strlen($padded); $i += $bs) {
        $blk = substr($padded, $i, $bs);
        $x = '';
        for ($j = 0; $j < $bs; $j++) $x .= chr(ord($blk[$j]) ^ ord($prev[$j]));
        $e = $cipher->encrypt($x);
        $ct .= $e;
        $prev = $e;
    }
    return $ct;
}

function cbc_decrypt_curupira($key, $iv, $ct) {
    $cipher = new Curupira1($key);
    $bs = $cipher->BlockSize();
    if (strlen($ct) % $bs != 0) throw new Exception("Ciphertext length must be multiple of block size");
    $pt = ''; $prev = $iv;
    for ($i = 0; $i < strlen($ct); $i += $bs) {
        $blk = substr($ct, $i, $bs);
        $d = $cipher->decrypt($blk);
        for ($j = 0; $j < $bs; $j++) $pt .= chr(ord($d[$j]) ^ ord($prev[$j]));
        $prev = $blk;
    }
    return unpad_pkcs7($pt);
}

// ====================================================================
// RFC 1423 key derivation + PEM encryption (Curupira-192-CBC)
// ====================================================================
function rfc1423_derive_key_md5($password, $salt, $key_size) {
    $iv_salt = substr($salt, 0, 8);
    $d = ''; $result = '';
    while (strlen($result) < $key_size) {
        $d = md5($d . $password . $iv_salt, true);
        $result .= $d;
    }
    return substr($result, 0, $key_size);
}

function encrypt_private_key_pem($data, $password, $cipher_name = "CURUPIRA-192-CBC") {
    if ($cipher_name != "CURUPIRA-192-CBC") throw new Exception("Unsupported cipher: $cipher_name");
    $iv = random_bytes_gmp(12);
    $key = rfc1423_derive_key_md5($password, $iv, 24);
    $enc = cbc_encrypt_curupira($key, $iv, $data);
    $b64 = base64_encode($enc);
    $lines = ["Proc-Type: 4,ENCRYPTED", "DEK-Info: $cipher_name," . bin2hex($iv), ""];
    $lines = array_merge($lines, str_split($b64, 64));
    return implode("\n", $lines);
}

function decrypt_private_key_pem($pem_data, $password) {
    $lines = explode("\n", trim($pem_data));
    $dek_info = null; $b64_lines = []; $in_headers = true;
    foreach ($lines as $line) {
        $line = trim($line);
        if (empty($line)) { if ($in_headers) $in_headers = false; continue; }
        if (strpos($line, "-----") === 0) continue;
        if ($in_headers) {
            if (strpos($line, "Proc-Type:") === 0) {
                if (trim(substr($line, 10)) != "4,ENCRYPTED") throw new Exception("Not an encrypted PEM block");
            } elseif (strpos($line, "DEK-Info:") === 0) {
                $dek_info = trim(substr($line, 10));
            }
        } else {
            $b64_lines[] = $line;
        }
    }
    if (!$dek_info) throw new Exception("Missing DEK-Info header");
    $parts = explode(",", $dek_info, 2);
    if (count($parts) != 2) throw new Exception("Invalid DEK-Info format: $dek_info");
    $cipher_name = trim($parts[0]);
    $iv_hex = trim($parts[1]);
    if ($cipher_name != "CURUPIRA-192-CBC") throw new Exception("Unsupported cipher: $cipher_name");
    $iv = hex2bin($iv_hex);
    if (!$iv || strlen($iv) != 12) throw new Exception("Invalid IV length");
    $ct = base64_decode(implode("", $b64_lines));
    $key = rfc1423_derive_key_md5($password, $iv, 24);
    return cbc_decrypt_curupira($key, $iv, $ct);
}

// ====================================================================
// PEM serializer / parser for E-521 keys (with optional encryption)
// ====================================================================
function ed521_private_to_pem_pkcs8($priv, $password = null) {
    $priv_bytes = little_int_to_bytes($priv, BYTE_LEN);
    $alg_id = der_seq(OID_DER . "\x06\x00");
    $version = der_int(0);
    $priv_field = der_octet_string($priv_bytes);
    $seq = der_seq($version . $alg_id . $priv_field);

    if ($password) {
        $enc = encrypt_private_key_pem($seq, $password, "CURUPIRA-192-CBC");
        return "-----BEGIN E-521 PRIVATE KEY-----\n" . $enc . "\n-----END E-521 PRIVATE KEY-----\n";
    }
    $b64 = base64_encode($seq);
    $lines = str_split($b64, 64);
    return "-----BEGIN E-521 PRIVATE KEY-----\n" . implode("\n", $lines) . "\n-----END E-521 PRIVATE KEY-----\n";
}

function ed521_public_to_pem($pub_x, $pub_y) {
    $compressed = compress_point($pub_x, $pub_y);
    $alg_id = der_seq(OID_DER . "\x06\x00");
    $bit_str = der_bit_string($compressed, 0);
    $spki = der_seq($alg_id . $bit_str);

    $b64 = base64_encode($spki);
    $lines = str_split($b64, 64);
    return "-----BEGIN E-521 PUBLIC KEY-----\n" . implode("\n", $lines) . "\n-----END E-521 PUBLIC KEY-----\n";
}

function parse_ed521_pem_private_key($pem_data, $debug = false) {
    $pem_data = trim($pem_data);
    $pem_data = preg_replace('/-----(BEGIN|END).*?-----/', '', $pem_data);
    $pem_data = str_replace(["\r", "\n", " "], '', $pem_data);
    $der = base64_decode($pem_data);

    list($tag, $content, $_) = der_read_tlv($der, 0);
    if ($tag !== 0x30) throw new Exception("Expected SEQUENCE");
    $idx = 0;
    list($tag, $_, $idx) = der_read_tlv($content, $idx);
    if ($tag !== 0x02) throw new Exception("Invalid version");
    list($tag, $_, $idx) = der_read_tlv($content, $idx);
    if ($tag !== 0x30) throw new Exception("Expected AlgorithmIdentifier");
    list($tag, $priv_bytes, $idx) = der_read_tlv($content, $idx);
    if ($tag !== 0x04) throw new Exception("Expected OCTET STRING for private key");
    return bytes_to_little_int($priv_bytes);
}

function parse_ed521_pem_public_key($pem_data, $debug = false) {
    $lines = explode("\n", trim($pem_data));
    $b64 = '';
    foreach ($lines as $l) {
        $l = trim($l);
        if ($l && strpos($l, '-----') !== 0) $b64 .= $l;
    }
    $der = base64_decode($b64);
    list($tag, $content, $_) = der_read_tlv($der, 0);
    if ($tag !== 0x30) throw new Exception("Expected SEQUENCE");
    $idx = 0;
    list($tag, $_, $idx) = der_read_tlv($content, $idx);
    if ($tag !== 0x30) throw new Exception("Expected AlgorithmIdentifier");
    list($tag, $bs, $idx) = der_read_tlv($content, $idx);
    if ($tag !== 0x03) throw new Exception("Expected BIT STRING");
    if (strlen($bs) < 1) throw new Exception("Empty BIT STRING");
    $compressed = substr($bs, 1);
    list($x, $y) = decompress_point($compressed);
    if ($x === null || $y === null) throw new Exception("Failed to decompress public key");
    return [$x, $y];
}

// ====================================================================
// CLI
// ====================================================================
function usage() {
    echo "ED521 — E-521 pure EdDSA (Go-compatible, PHP/GMP)\n\n";
    echo "Usage: php " . basename(__FILE__) . " <command> [options]\n\n";
    echo "Commands:\n";
    echo "  test                                Run core self-tests\n";
    echo "  test-shake                          Print SHAKE256 vectors\n";
    echo "  generate [--password] [--output F]  Generate a key pair\n";
    echo "  sign <priv.pem> <msgfile>           Sign a message (hex output)\n";
    echo "  verify <pub.pem> <msgfile> <sig>    Verify a signature\n";
    echo "  prove <priv.pem>                    ZKP of knowledge (hex output)\n";
    echo "  verify-proof <pub.pem> <proof>      Verify a ZKP\n";
    echo "  parse <keyfile> [--debug]           Dump key info\n";
}

function cli_main() {
    global $argc, $argv;
    if ($argc < 2) { usage(); exit(0); }
    $cmd = $argv[1];

    switch ($cmd) {
        case 'test':
            test_core();
            break;

        case 'test-shake':
            test_shake256();
            break;

        case 'generate': {
            $password = null;
            $output = null;
            for ($i = 2; $i < $argc; $i++) {
                if ($argv[$i] === '--password') {
                    echo "Password: ";
                    system('stty -echo');
                    $password = trim(fgets(STDIN));
                    system('stty echo');
                    echo "\n";
                } elseif ($argv[$i] === '--output' && $i + 1 < $argc) {
                    $output = $argv[++$i];
                }
            }
            $priv = generate_private_key();
            list($px, $py) = get_public_key($priv);
            $base = $output ?: 'ed521';
            $priv_path = "{$base}_private.pem";
            $pub_path  = "{$base}_public.pem";
            file_put_contents($priv_path, ed521_private_to_pem_pkcs8($priv, $password));
            file_put_contents($pub_path,  ed521_public_to_pem($px, $py));
            echo "keys written to $priv_path and $pub_path\n";
            break;
        }

        case 'sign': {
            if ($argc < 4) { echo "Usage: sign <priv.pem> <msgfile>\n"; exit(1); }
            $priv = parse_ed521_pem_private_key(file_get_contents($argv[2]));
            $msg = file_get_contents($argv[3]);
            echo bin2hex(sign($priv, $msg)) . "\n";
            break;
        }

        case 'verify': {
            if ($argc < 5) { echo "Usage: verify <pub.pem> <msgfile> <sig_hex>\n"; exit(1); }
            list($px, $py) = parse_ed521_pem_public_key(file_get_contents($argv[2]));
            $msg = file_get_contents($argv[3]);
            $sig = hex_to_bytes_strict($argv[4]);
            if (verify($px, $py, $msg, $sig)) { echo "signature valid\n"; exit(0); }
            echo "signature invalid\n"; exit(1);
        }

        case 'prove': {
            if ($argc < 3) { echo "Usage: prove <priv.pem>\n"; exit(1); }
            $priv = parse_ed521_pem_private_key(file_get_contents($argv[2]));
            echo bin2hex(prove_knowledge($priv)) . "\n";
            break;
        }

        case 'verify-proof': {
            if ($argc < 4) { echo "Usage: verify-proof <pub.pem> <proof_hex>\n"; exit(1); }
            list($px, $py) = parse_ed521_pem_public_key(file_get_contents($argv[2]));
            $proof = hex_to_bytes_strict($argv[3]);
            if (verify_knowledge($px, $py, $proof)) { echo "proof valid\n"; exit(0); }
            echo "proof invalid\n"; exit(1);
        }

        case 'parse': {
            if ($argc < 3) { echo "Usage: parse <keyfile> [--debug]\n"; exit(1); }
            $file = $argv[2];
            $pem = file_get_contents($file);
            if ($pem === false) { echo "error: file not found: $file\n"; exit(1); }
            try {
                if (strpos($pem, "PRIVATE KEY") !== false) {
                    $priv = parse_ed521_pem_private_key($pem);
                    echo "Private-Key: " . (BYTE_LEN * 8) . "-bit\n";
                    echo "priv: " . bin2hex(little_int_to_bytes($priv, BYTE_LEN)) . "\n";
                    list($px, $py) = get_public_key($priv);
                    echo "pub:  " . bin2hex(compress_point($px, $py)) . "\n";
                } elseif (strpos($pem, "PUBLIC KEY") !== false) {
                    list($px, $py) = parse_ed521_pem_public_key($pem);
                    echo "Public-Key: " . (BYTE_LEN * 8) . "-bit\n";
                    echo "pub:  " . bin2hex(compress_point($px, $py)) . "\n";
                } else {
                    echo "unknown PEM format\n";
                    exit(1);
                }
                echo "Curve: E-521\n";
                echo "OID: 1.3.6.1.4.1.44588.2.1\n";
            } catch (Exception $e) {
                echo "error: " . $e->getMessage() . "\n";
                exit(1);
            }
            break;
        }

        case '-h':
        case '--help':
        case 'help':
            usage();
            break;

        default:
            echo "unknown command: $cmd\n";
            usage();
            exit(1);
    }
}

if (PHP_SAPI === 'cli' && realpath($_SERVER['argv'][0] ?? '') === realpath(__FILE__)) {
    cli_main();
}
