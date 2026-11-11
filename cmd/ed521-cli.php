<?php
// ed521_cli.php - Ed521 CLI Tool (edgetk-style)
// Usage: php ed521_cli.php [command] [options]
//
// Requires: ed521_gmp.php (the GMP-based core).
// All numeric operations use GMP; no BCMath is used.

require_once('e521.php');

// ====================================================================
// CLI HELPERS
// ====================================================================

function show_help() {
    echo "ED521 CLI TOOL - BRAZILIAN DIGITAL SIGNATURE ALGORITHM\n";
    echo "=======================================================\n\n";
    echo "Usage: php ed521_cli.php [command] [options]\n\n";
    echo "COMMANDS:\n";
    echo "  help                - Show this help\n";
    echo "  version             - Show version\n";
    echo "\n  generate            - Generate new key pair\n";
    echo "    --password        - Encrypt private key with password\n";
    echo "    --out=DIR         - Output directory (default: ./)\n";
    echo "    --name=NAME       - Base name for key files\n";
    echo "\n  sign                - Sign file or text\n";
    echo "    --key=FILE        - Private key file\n";
    echo "    --file=FILE       - File to sign\n";
    echo "    --text=TEXT       - Text to sign\n";
    echo "    --out=FILE        - Output signature file\n";
    echo "\n  verify              - Verify signature\n";
    echo "    --key=FILE        - Public key file\n";
    echo "    --file=FILE       - File to verify\n";
    echo "    --text=TEXT       - Text to verify\n";
    echo "    --sig=FILE        - Signature file (raw bytes or hex)\n";
    echo "    --sig-hex=HEX     - Signature in hex\n";
    echo "\n  parse               - Parse and display key information (edgetk style)\n";
    echo "    --key=FILE        - Key file to parse\n";
    echo "    --debug           - Show debug information\n";
    echo "\nEXAMPLES:\n";
    echo "  php ed521_cli.php generate --password\n";
    echo "  php ed521_cli.php sign --key=private.pem --file=document.txt\n";
    echo "  php ed521_cli.php verify --key=public.pem --file=document.txt --sig=signature.bin\n";
    echo "  php ed521_cli.php parse --key=public.pem\n";
}

function show_version() {
    echo "Ed521 CLI Tool v1.1\n";
    echo "Ed521 Brazilian Digital Signature Algorithm (E-521)\n";
    echo "ALBANESE Research Lab\n";
    echo "OID: 1.3.6.1.4.1.44588.2.1\n";
}

function get_password($confirm = false) {
    echo "Password: ";
    system('stty -echo');
    $password = trim(fgets(STDIN));
    system('stty echo');
    echo "\n";

    if ($confirm) {
        echo "Confirm password: ";
        system('stty -echo');
        $confirm_password = trim(fgets(STDIN));
        system('stty echo');
        echo "\n";

        if ($password !== $confirm_password) {
            echo "ERROR: Passwords do not match!\n";
            exit(1);
        }
    }
    return $password;
}

// Helper: does the given PEM string look like an encrypted key?
function pem_is_encrypted($pem_data) {
    foreach (explode("\n", $pem_data) as $line) {
        if (strpos($line, "Proc-Type:") === 0 && strpos($line, "ENCRYPTED") !== false) {
            return true;
        }
    }
    return false;
}

// Helper: convert a GMP value to a 66-byte big-endian hex string, padding
// with zeros as the edgetk output expects.
function gmp_to_display_hex($value, $byte_len = 66) {
    $be = gmp_export($value, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);
    if (strlen($be) < $byte_len) {
        $be = str_repeat("\x00", $byte_len - strlen($be)) . $be;
    } elseif (strlen($be) > $byte_len) {
        $be = substr($be, -$byte_len);
    }
    return bin2hex($be);
}

// Format a hex string as colon-separated pairs, 15 bytes per line.
function format_hex_lines($hex_str) {
    $out = '';
    $len = strlen($hex_str);
    for ($i = 0; $i < $len; $i += 30) {
        $chunk = substr($hex_str, $i, 30);
        $out .= "    " . implode(':', str_split($chunk, 2)) . "\n";
    }
    return $out;
}

// ====================================================================
// EDGETK-STYLE PARSING
// ====================================================================

function edgetk_style_parse_key($key_file, $debug = false) {
    try {
        $pem_data = @file_get_contents($key_file);
        if ($pem_data === false) {
            echo "ERROR: Cannot read key file: $key_file\n";
            return 1;
        }

        $is_encrypted = pem_is_encrypted($pem_data);

        // ---- Private key ----
        if (strpos($pem_data, "PRIVATE KEY") !== false) {
            if ($is_encrypted) {
                echo "Enter password to decrypt private key: ";
                system('stty -echo');
                $password = trim(fgets(STDIN));
                system('stty echo');
                echo "\n";

                try {
                    $der_data = decrypt_private_key_pem($pem_data, $password);
                    echo "✓ Key decrypted successfully\n";

                    // Print decrypted PEM
                    $b64_der = base64_encode($der_data);
                    $pem_lines = str_split($b64_der, 64);
                    echo "-----BEGIN E-521 PRIVATE KEY-----\n";
                    foreach ($pem_lines as $line) {
                        echo $line . "\n";
                    }
                    echo "-----END E-521 PRIVATE KEY-----\n\n";

                    // Save to a temp file and let the core parse it
                    $tmp = tempnam(sys_get_temp_dir(), 'e521');
                    file_put_contents(
                        $tmp,
                        "-----BEGIN E-521 PRIVATE KEY-----\n" .
                        implode("\n", $pem_lines) . "\n" .
                        "-----END E-521 PRIVATE KEY-----\n"
                    );
                    try {
                        $private_key = read_private_key_from_pem($tmp);
                    } finally {
                        @unlink($tmp);
                    }
                } catch (Exception $e) {
                    echo "✖ Decryption failed: " . $e->getMessage() . "\n";
                    return 1;
                }
            } else {
                echo $pem_data;
                $private_key = read_private_key_from_pem($key_file);
            }

            $priv_bytes = little_int_to_bytes($private_key, BYTE_LEN);
            $hex = gmp_to_display_hex($private_key, BYTE_LEN);

            echo "Private-Key: (" . (BYTE_LEN * 8) . " bit)\n";
            echo "priv:\n";
            echo format_hex_lines($hex);

            list($pub_x, $pub_y) = get_public_key($private_key);
            $compressed_pub = compress_point($pub_x, $pub_y);

            echo "pub:\n";
            echo format_hex_lines(bin2hex($compressed_pub));

            echo "ASN1 OID: 1.3.6.1.4.1.44588.2.1\n";
            echo "Curve: E-521\n";
            echo "\nAdditional Information:\n";
            echo "  Private key size: " . (BYTE_LEN * 8) . " bits\n";
            echo "  Public key size: " . (strlen($compressed_pub) * 8) . " bits\n";
            echo "  Curve parameters:\n";
            echo "    Prime P: " . strlen(gmp_strval(P)) . " digits\n";
            echo "    Order N: " . strlen(gmp_strval(N)) . " digits\n";
            echo "    Cofactor: 4\n";
            echo "\n✓ Private key parsed successfully\n";
            return 0;
        }

        // ---- Public key ----
        if (strpos($pem_data, "PUBLIC KEY") !== false) {
            echo $pem_data;
            list($pub_x, $pub_y) = read_public_key_from_pem($key_file);
            $compressed_pub = compress_point($pub_x, $pub_y);

            echo "Public-Key: (" . (strlen($compressed_pub) * 8) . " bit)\n";
            echo "pub:\n";
            echo format_hex_lines(bin2hex($compressed_pub));

            echo "ASN1 OID: 1.3.6.1.4.1.44588.2.1\n";
            echo "Curve: E-521\n";

            $fp = hash('sha256', $compressed_pub);
            echo "\nFingerprint:\n";
            echo "  SHA256: $fp\n";
            echo "  Short: " . substr($fp, 0, 16) . "\n";
            echo "\n✓ Public key parsed successfully\n";
            return 0;
        }

        echo "✖ Unknown key format\n";
        return 1;

    } catch (Exception $e) {
        echo "✖ Error: " . $e->getMessage() . "\n";
        return 1;
    }
}

// ====================================================================
// COMMANDS
// ====================================================================

function cmd_generate($args) {
    $password = null;
    $output_dir = './';
    $name = 'ed521';

    foreach ($args as $arg) {
        if ($arg === '--password') {
            $password = get_password(true);
        } elseif (strpos($arg, '--out=') === 0) {
            $output_dir = substr($arg, 6);
            if (!is_dir($output_dir)) mkdir($output_dir, 0755, true);
        } elseif (strpos($arg, '--name=') === 0) {
            $name = substr($arg, 7);
        }
    }

    echo "Generating Ed521 key pair...\n";
    $priv = generate_private_key();
    list($px, $py) = get_public_key($priv);

    $priv_file = rtrim($output_dir, '/') . '/' . $name . '_private.pem';
    $pub_file  = rtrim($output_dir, '/') . '/' . $name . '_public.pem';

    file_put_contents($priv_file, private_key_to_pem($priv, $password));
    file_put_contents($pub_file,  public_key_to_pem($px, $py));

    echo "✓ Key pair generated successfully:\n";
    echo "  Private: $priv_file " . ($password ? "(encrypted)" : "") . "\n";
    echo "  Public:  $pub_file\n";

    $compressed = compress_point($px, $py);
    $fp = hash('sha256', $compressed);
    echo "\nFingerprint (SHA256):\n  $fp\n  Short: " . substr($fp, 0, 16) . "\n";
    return 0;
}

function cmd_sign($args) {
    $key_file = null; $input_file = null; $input_text = null; $output_file = null;

    foreach ($args as $arg) {
        if (strpos($arg, '--key=') === 0)       $key_file    = substr($arg, 6);
        elseif (strpos($arg, '--file=') === 0)  $input_file  = substr($arg, 7);
        elseif (strpos($arg, '--text=') === 0)  $input_text  = substr($arg, 7);
        elseif (strpos($arg, '--out=') === 0)   $output_file = substr($arg, 6);
    }

    if (!$key_file)   { echo "ERROR: Private key file not specified (use --key=FILE)\n"; return 1; }
    if (!$input_file && $input_text === null) { echo "ERROR: No input specified (use --file=FILE or --text=TEXT)\n"; return 1; }

    echo "Loading private key...\n";
    $pem_data = @file_get_contents($key_file);
    if ($pem_data === false) { echo "ERROR: Cannot read key file: $key_file\n"; return 1; }

    try {
        if (pem_is_encrypted($pem_data)) {
            echo "Enter password to decrypt private key: ";
            system('stty -echo');
            $password = trim(fgets(STDIN));
            system('stty echo');
            echo "\n";

            $der = decrypt_private_key_pem($pem_data, $password);
            $b64 = base64_encode($der);
            $lines = str_split($b64, 64);
            $tmp = tempnam(sys_get_temp_dir(), 'e521');
            file_put_contents($tmp, "-----BEGIN E-521 PRIVATE KEY-----\n" . implode("\n", $lines) . "\n-----END E-521 PRIVATE KEY-----\n");
            try {
                $priv = read_private_key_from_pem($tmp);
            } finally {
                @unlink($tmp);
            }
            echo "✓ Private key decrypted\n";
        } else {
            $priv = read_private_key_from_pem($key_file);
        }
    } catch (Exception $e) {
        echo "ERROR: Failed to load private key: " . $e->getMessage() . "\n";
        return 1;
    }

    if ($input_file) {
        echo "Reading file to sign: $input_file\n";
        $message = @file_get_contents($input_file);
        if ($message === false) { echo "ERROR: Cannot read file: $input_file\n"; return 1; }
        echo "✓ File read (" . strlen($message) . " bytes)\n";
    } else {
        $message = $input_text;
        echo "✓ Text to sign (" . strlen($message) . " bytes)\n";
    }

    echo "\nSigning...\n";
    $sig = sign($priv, $message);
    echo "✓ Signature generated (" . strlen($sig) . " bytes)\n";

    if ($output_file) {
        file_put_contents($output_file, $sig);
        echo "\n✓ Signature saved to: $output_file\n";
        $hex_file = $output_file . '.hex';
        file_put_contents($hex_file, bin2hex($sig));
        echo "  Hex saved to: $hex_file\n";
        echo "\nSignature (hex):\n" . format_hex_lines(bin2hex($sig));
    } else {
        echo "\nSignature (hexadecimal):\n" . bin2hex($sig) . "\n";
    }
    return 0;
}

function cmd_verify($args) {
    $key_file = null; $input_file = null; $input_text = null;
    $sig_file = null; $sig_hex = null;

    foreach ($args as $arg) {
        if (strpos($arg, '--key=') === 0)          $key_file   = substr($arg, 6);
        elseif (strpos($arg, '--file=') === 0)     $input_file = substr($arg, 7);
        elseif (strpos($arg, '--text=') === 0)     $input_text = substr($arg, 7);
        elseif (strpos($arg, '--sig-hex=') === 0)  $sig_hex    = substr($arg, 10);
        elseif (strpos($arg, '--sig=') === 0)      $sig_file   = substr($arg, 6);
    }

    if (!$key_file)   { echo "ERROR: Public key file not specified (--key=FILE)\n"; return 1; }
    if (!$input_file && $input_text === null) { echo "ERROR: No input specified\n"; return 1; }
    if (!$sig_file && !$sig_hex) { echo "ERROR: No signature specified\n"; return 1; }

    echo "Loading public key...\n";
    try {
        list($px, $py) = read_public_key_from_pem($key_file);
        echo "✓ Public key loaded\n";
    } catch (Exception $e) {
        echo "ERROR: Failed to load public key: " . $e->getMessage() . "\n";
        return 1;
    }

    if ($input_file) {
        $message = @file_get_contents($input_file);
        if ($message === false) { echo "ERROR: Cannot read file: $input_file\n"; return 1; }
        echo "✓ File read (" . strlen($message) . " bytes)\n";
    } else {
        $message = $input_text;
        echo "✓ Text to verify (" . strlen($message) . " bytes)\n";
    }

    if ($sig_file) {
        $raw = @file_get_contents($sig_file);
        if ($raw === false) { echo "ERROR: Cannot read signature: $sig_file\n"; return 1; }
        // If file looks like hex text, decode it; otherwise treat as raw bytes.
        if (strlen($raw) === 2 * BYTE_LEN * 2 && ctype_xdigit(trim($raw))) {
            $sig = hex2bin(trim($raw));
        } else {
            $sig = $raw;
        }
        echo "✓ Signature read (" . strlen($sig) . " bytes)\n";
    } else {
        $sig = hex_to_bytes_strict($sig_hex);
        echo "✓ Signature decoded from hex (" . strlen($sig) . " bytes)\n";
    }

    echo "\nVerifying signature...\n";
    if (verify($px, $py, $message, $sig)) {
        echo "✓ SIGNATURE VALID\n\n";
        echo "The signature is valid and matches the message and public key.\n";
        echo "\nSignature components:\n";
        echo "  R (compressed): " . bin2hex(substr($sig, 0, BYTE_LEN)) . "\n";
        echo "  s (scalar):     " . bin2hex(substr($sig, BYTE_LEN)) . "\n";
        return 0;
    }
    echo "✖ SIGNATURE INVALID\n\n";
    echo "The signature is NOT valid. Possible reasons:\n";
    echo "1. The message has been modified\n";
    echo "2. The signature is corrupted\n";
    echo "3. Wrong public key used for verification\n";
    echo "4. Different algorithm was used for signing\n";
    return 1;
}

function cmd_parse($args) {
    $key_file = null; $debug = false;
    foreach ($args as $arg) {
        if (strpos($arg, '--key=') === 0) $key_file = substr($arg, 6);
        elseif ($arg === '--debug')       $debug = true;
    }
    if (!$key_file) { echo "ERROR: Key file not specified (--key=FILE)\n"; return 1; }
    return edgetk_style_parse_key($key_file, $debug);
}

// ====================================================================
// MAIN
// ====================================================================

function main() {
    global $argc, $argv;
    if ($argc < 2) { show_help(); return 1; }
    $command = $argv[1];
    $args = array_slice($argv, 2);

    try {
        switch ($command) {
            case 'help':    show_help(); return 0;
            case 'version': show_version(); return 0;
            case 'generate': return cmd_generate($args);
            case 'sign':     return cmd_sign($args);
            case 'verify':   return cmd_verify($args);
            case 'parse':    return cmd_parse($args);
            default:
                echo "ERROR: Unknown command: $command\n";
                echo "       Use 'php ed521_cli.php help'.\n";
                return 1;
        }
    } catch (Exception $e) {
        echo "ERROR: " . $e->getMessage() . "\n";
        return 1;
    }
}

if (PHP_SAPI === 'cli' && basename(__FILE__) === basename($_SERVER['PHP_SELF'])) {
    exit(main());
}
return;
