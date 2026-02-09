<?php
// ed521_cli.php - Ed521 CLI Tool (edgetk-style parsing)
// Usage: php ed521_cli.php [command] [options]

require_once('ed521_gmp.php'); 

// ====================================================================
// CLI HELPER FUNCTIONS (EDGETK STYLE)
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
    echo "    --text=TEXT       - Text to sign (alternative to --file)\n";
    echo "    --out=FILE        - Output signature file\n";
    echo "\n  verify              - Verify signature\n";
    echo "    --key=FILE        - Public key file\n";
    echo "    --file=FILE       - File to verify\n";
    echo "    --text=TEXT       - Text to verify (alternative to --file)\n";
    echo "    --sig=FILE        - Signature file\n";
    echo "    --sig-hex=HEX     - Signature in hexadecimal\n";
    echo "\n  parse               - Parse and display key information (edgetk style)\n";
    echo "    --key=FILE        - Key file to parse\n";
    echo "    --debug           - Show debug information\n";
    echo "\nEXAMPLES:\n";
    echo "  php ed521_cli.php generate --password\n";
    echo "  php ed521_cli.php sign --key=private.pem --file=document.txt\n";
    echo "  php ed521_cli.php verify --key=public.pem --file=document.txt --sig=signature.sig\n";
    echo "  php ed521_cli.php parse --key=public.pem\n";
}

function show_version() {
    echo "Ed521 CLI Tool v1.0\n";
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

// ====================================================================
// EDGETK-STYLE PARSING FUNCTIONS
// ====================================================================

function edgetk_style_parse_key($key_file, $debug = false) {
    try {
        $pem_data = file_get_contents($key_file);
        if ($pem_data === false) {
            echo "ERROR: Cannot read key file: $key_file\n";
            return 1;
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
                    
                    // Print decrypted PEM exactly like edgetk
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
                    return 1;
                }
            } else {
                // Print original PEM exactly like edgetk
                echo $pem_data;
                // Parse the key
                $private_key = parse_ed521_pem_private_key($pem_data, $debug);
            }
            
            $private_bytes = little_int_to_bytes($private_key, 66);
            
            // EDGETK-STYLE OUTPUT FOR PRIVATE KEY
            echo "Private-Key: (" . (strlen($private_bytes)*8) . " bit)\n";
            echo "priv:\n";
            
            $temp = $private_key;
            $bytes = [];

            while (bccomp($temp, '0') > 0) {
                $bytes[] = bcmod($temp, '256');
                $temp = bcdiv($temp, '256', 0);
            }

            $bytes = array_reverse($bytes);
            $hex_parts = [];

            foreach ($bytes as $byte) {
                $hex_parts[] = str_pad(dechex(intval($byte)), 2, '0', STR_PAD_LEFT);
            }

            $hex_str = implode('', $hex_parts);

            if (strlen($hex_str) < 132) {
                $hex_str = str_pad($hex_str, 132, '0', STR_PAD_RIGHT);
            } elseif (strlen($hex_str) > 132) {
                $hex_str = substr($hex_str, 0, 132);
            }
            // Format like edgetk: 66 bytes = 132 hex chars, break every 30 hex chars (15 bytes)
            for ($i = 0; $i < strlen($hex_str); $i += 30) {
                $line_hex = substr($hex_str, $i, 30);
                // Format as colon-separated pairs
                $formatted = implode(':', str_split($line_hex, 2));
                echo "    " . $formatted . "\n";
            }
            
            // Calculate and show public key
            list($pub_x, $pub_y) = get_public_key($private_key);
            $compressed_pub = compress_point($pub_x, $pub_y);
            
            echo "pub:\n";
            $hex_str = bin2hex($compressed_pub);
            // Format public key exactly like private key - multiple lines
            for ($i = 0; $i < strlen($hex_str); $i += 30) {
                $line_hex = substr($hex_str, $i, 30);
                $formatted = implode(':', str_split($line_hex, 2));
                echo "    " . $formatted . "\n";
            }
            
            echo "ASN1 OID: 1.3.6.1.4.1.44588.2.1\n";
            echo "Curve: E-521\n";
            
            // Show additional info like edgetk
            echo "\nAdditional Information:\n";
            echo "  Private key size: " . (strlen($private_bytes)*8) . " bits\n";
            echo "  Public key size: " . (strlen($compressed_pub)*8) . " bits\n";
            echo "  Curve parameters:\n";
            echo "    Prime P: " . strlen(P) . " digits\n";
            echo "    Order N: " . strlen(N) . " digits\n";
            echo "    Cofactor: 4\n";
            
            echo "\n✓ Private key parsed successfully\n";
            
        // Parse public key
        } elseif (strpos($pem_data, "PUBLIC KEY") !== false || 
                 (strpos($pem_data, "E-521") !== false && strpos($pem_data, "PUBLIC") !== false)) {
            
            // Public keys are never encrypted
            echo $pem_data;
            
            // Parse public key
            list($pub_x, $pub_y) = parse_ed521_pem_public_key($pem_data, $debug);
            $compressed_pub = compress_point($pub_x, $pub_y);
            
            // EDGETK-STYLE OUTPUT FOR PUBLIC KEY
            echo "Public-Key: (" . (strlen($compressed_pub)*8) . " bit)\n";
            
            // For consistency with edgetk style, show public key in same format as when parsing private key
            // First line: "pub:" label
            echo "pub:\n";
            
            $hex_str = bin2hex($compressed_pub);
            // Format exactly like private key display - multiple lines with colon-separated bytes
            for ($i = 0; $i < strlen($hex_str); $i += 30) {
                $line_hex = substr($hex_str, $i, 30);
                $formatted = implode(':', str_split($line_hex, 2));
                echo "    " . $formatted . "\n";
            }
            
            echo "ASN1 OID: 1.3.6.1.4.1.44588.2.1\n";
            echo "Curve: E-521\n";
            
            // Calculate fingerprint like edgetk
            $fingerprint = hash('sha256', $compressed_pub);
            echo "\nFingerprint:\n";
            echo "  SHA256: " . $fingerprint . "\n";
            echo "  Short: " . substr($fingerprint, 0, 16) . "\n";
            
            echo "\n✓ Public key parsed successfully\n";
        
        } else {
            echo "✖ Unknown key format\n";
            return 1;
        }
        
        return 0; // Success
        
    } catch (Exception $e) {
        echo "✖ Error: " . $e->getMessage() . "\n";
        return 1;
    }
}

// ====================================================================
// MAIN COMMAND FUNCTIONS
// ====================================================================

function cmd_generate($args) {
    $password = null;
    $output_dir = './';
    $name = 'ed521';
    
    // Parse arguments
    foreach ($args as $arg) {
        if ($arg === '--password') {
            $password = get_password(true);
        } elseif (strpos($arg, '--out=') === 0) {
            $output_dir = substr($arg, 6);
            if (!is_dir($output_dir)) {
                mkdir($output_dir, 0755, true);
            }
        } elseif (strpos($arg, '--name=') === 0) {
            $name = substr($arg, 7);
        }
    }
    
    echo "Generating Ed521 key pair...\n";
    
    // Generate keys
    $private_key = generate_private_key();
    list($pub_x, $pub_y) = get_public_key($private_key);
    
    // Generate filenames
    $private_file = rtrim($output_dir, '/') . '/' . $name . '_private.pem';
    $public_file = rtrim($output_dir, '/') . '/' . $name . '_public.pem';
    
    // Save keys
    $private_pem = ed521_private_to_pem_pkcs8($private_key, $password);
    $public_pem = ed521_public_to_pem($pub_x, $pub_y);
    
    file_put_contents($private_file, $private_pem);
    file_put_contents($public_file, $public_pem);
    
    echo "✓ Key pair generated successfully:\n";
    echo "  Private: $private_file " . ($password ? "(encrypted)" : "") . "\n";
    echo "  Public:  $public_file\n";
    
    // Show fingerprint like edgetk
    $compressed = compress_point($pub_x, $pub_y);
    $fingerprint = hash('sha256', $compressed);
    echo "\nFingerprint (SHA256):\n";
    echo "  " . $fingerprint . "\n";
    echo "  Short: " . substr($fingerprint, 0, 16) . "\n";
    
    return 0;
}

function cmd_sign($args) {
    $key_file = null;
    $input_file = null;
    $input_text = null;
    $output_file = null;
    $password = null;
    
    // Parse arguments
    foreach ($args as $arg) {
        if (strpos($arg, '--key=') === 0) {
            $key_file = substr($arg, 6);
        } elseif (strpos($arg, '--file=') === 0) {
            $input_file = substr($arg, 7);
        } elseif (strpos($arg, '--text=') === 0) {
            $input_text = substr($arg, 7);
        } elseif (strpos($arg, '--out=') === 0) {
            $output_file = substr($arg, 6);
        }
    }
    
    // Validate arguments
    if (!$key_file) {
        echo "ERROR: Private key file not specified (use --key=FILE)\n";
        return 1;
    }
    
    if (!$input_file && !$input_text) {
        echo "ERROR: No input specified for signing\n";
        echo "       Use --file=FILE or --text=TEXT\n";
        return 1;
    }
    
    // Load private key
    echo "Loading private key...\n";
    $pem_data = file_get_contents($key_file);
    if (!$pem_data) {
        echo "ERROR: Cannot read key file: $key_file\n";
        return 1;
    }
    
    try {
        // Check if key is encrypted
        $is_encrypted = false;
        $lines = explode("\n", trim($pem_data));
        foreach ($lines as $line) {
            if (strpos($line, "Proc-Type:") === 0 && strpos($line, "ENCRYPTED") !== false) {
                $is_encrypted = true;
                break;
            }
        }
        
        if ($is_encrypted) {
            // Ask for password if key is encrypted
            echo "Enter password to decrypt private key: ";
            system('stty -echo');
            $password = trim(fgets(STDIN));
            system('stty echo');
            echo "\n";
            
            // Decrypt the key
            $der_data = decrypt_private_key_pem($pem_data, $password);
            echo "✓ Private key decrypted successfully\n";
            
            // Convert decrypted DER back to PEM for parsing
            $b64_der = base64_encode($der_data);
            $pem_lines = str_split($b64_der, 64);
            
            $pem_data = "-----BEGIN PRIVATE KEY-----\n" . 
                       implode("\n", $pem_lines) . "\n" .
                       "-----END PRIVATE KEY-----\n";
        }
        
        // Now parse the (possibly decrypted) key
        $private_key = parse_ed521_pem_private_key($pem_data);
        echo "✓ Private key loaded\n";
    } catch (Exception $e) {
        echo "ERROR: Failed to load private key: " . $e->getMessage() . "\n";
        if ($is_encrypted) {
            echo "       Make sure you entered the correct password.\n";
        }
        return 1;
    }
    
    // Load data to sign
    if ($input_file) {
        echo "Reading file to sign: $input_file\n";
        $message = file_get_contents($input_file);
        if (!$message) {
            echo "ERROR: Cannot read file: $input_file\n";
            return 1;
        }
        echo "✓ File read (" . strlen($message) . " bytes)\n";
    } else {
        $message = $input_text;
        echo "✓ Text to sign (" . strlen($message) . " bytes)\n";
    }
    
    // Sign the message
    echo "\nSigning...\n";
    $signature = sign($private_key, $message);
    
    echo "✓ Signature generated (" . strlen($signature) . " bytes)\n";
    
    // Save or display signature
    if ($output_file) {
        file_put_contents($output_file, $signature);
        echo "\n✓ Signature saved to: $output_file\n";
        
        // Also save as hex for convenience
        $hex_file = $output_file . '.hex';
        file_put_contents($hex_file, bin2hex($signature));
        echo "  Hex saved to: $hex_file\n";
        
        // Show signature in edgetk style
        echo "\nSignature (hex):\n";
        $hex_str = bin2hex($signature);
        echo "    " . implode(':', str_split($hex_str, 2)) . "\n";
    } else {
        echo "\nSignature (hexadecimal):\n";
        $hex_str = bin2hex($signature);
        echo $hex_str . "\n";
    }
    
    return 0;
}

function cmd_verify($args) {
    $key_file = null;
    $input_file = null;
    $input_text = null;
    $sig_file = null;
    $sig_hex = null;
    
    // Parse arguments
    foreach ($args as $arg) {
        if (strpos($arg, '--key=') === 0) {
            $key_file = substr($arg, 6);
        } elseif (strpos($arg, '--file=') === 0) {
            $input_file = substr($arg, 7);
        } elseif (strpos($arg, '--text=') === 0) {
            $input_text = substr($arg, 7);
        } elseif (strpos($arg, '--sig=') === 0) {
            $sig_file = substr($arg, 6);
        } elseif (strpos($arg, '--sig-hex=') === 0) {
            $sig_hex = substr($arg, 10);
        }
    }
    
    // Validate arguments
    if (!$key_file) {
        echo "ERROR: Public key file not specified (use --key=FILE)\n";
        return 1;
    }
    
    if (!$input_file && !$input_text) {
        echo "ERROR: No input specified for verification\n";
        echo "       Use --file=FILE or --text=TEXT\n";
        return 1;
    }
    
    if (!$sig_file && !$sig_hex) {
        echo "ERROR: No signature specified\n";
        echo "       Use --sig=FILE or --sig-hex=HEX\n";
        return 1;
    }
    
    // Load public key
    echo "Loading public key...\n";
    $pem_data = file_get_contents($key_file);
    if (!$pem_data) {
        echo "ERROR: Cannot read key file: $key_file\n";
        return 1;
    }
    
    try {
        list($pub_x, $pub_y) = parse_ed521_pem_public_key($pem_data);
        echo "✓ Public key loaded\n";
    } catch (Exception $e) {
        echo "ERROR: Failed to load public key: " . $e->getMessage() . "\n";
        return 1;
    }
    
    // Load data to verify
    if ($input_file) {
        echo "Reading file to verify: $input_file\n";
        $message = file_get_contents($input_file);
        if (!$message) {
            echo "ERROR: Cannot read file: $input_file\n";
            return 1;
        }
        echo "✓ File read (" . strlen($message) . " bytes)\n";
    } else {
        $message = $input_text;
        echo "✓ Text to verify (" . strlen($message) . " bytes)\n";
    }
    
    // Load signature
    if ($sig_file) {
        echo "Reading signature: $sig_file\n";
        $signature = file_get_contents($sig_file);
        if (!$signature) {
            echo "ERROR: Cannot read signature: $sig_file\n";
            return 1;
        }
        echo "✓ Signature read (" . strlen($signature) . " bytes)\n";
    } else {
        $signature = hex2bin($sig_hex);
        if (!$signature) {
            echo "ERROR: Invalid hexadecimal signature\n";
            return 1;
        }
        echo "✓ Signature decoded from hex (" . strlen($signature) . " bytes)\n";
    }
    
    // Verify signature
    echo "\nVerifying signature...\n";
    $valid = verify($pub_x, $pub_y, $message, $signature);
    
    if ($valid) {
        echo "✓ SIGNATURE VALID\n";
        echo "\nThe signature is valid and matches the message and public key.\n";
        
        // Show signature components like edgetk
        $R = substr($signature, 0, 66);
        $s = substr($signature, 66);
        
        echo "\nSignature components:\n";
        echo "  R (compressed): " . bin2hex($R) . "\n";
        echo "  s (scalar):     " . bin2hex($s) . "\n";
        
        return 0;
    } else {
        echo "✖ SIGNATURE INVALID\n";
        echo "\nThe signature is NOT valid. Possible reasons:\n";
        echo "1. The message has been modified\n";
        echo "2. The signature is corrupted\n";
        echo "3. Wrong public key used for verification\n";
        echo "4. Different algorithm was used for signing\n";
        return 1;
    }
}

function cmd_parse($args) {
    $key_file = null;
    $debug = false;
    
    // Parse arguments
    foreach ($args as $arg) {
        if (strpos($arg, '--key=') === 0) {
            $key_file = substr($arg, 6);
        } elseif ($arg === '--debug') {
            $debug = true;
        }
    }
    
    if (!$key_file) {
        echo "ERROR: Key file not specified (use --key=FILE)\n";
        return 1;
    }
    
    // Parse and display key info in edgetk style
    return edgetk_style_parse_key($key_file, $debug);
}

// ====================================================================
// MAIN ENTRY POINT
// ====================================================================

function main() {
    global $argc, $argv;
    
    // Check if we have at least one argument
    if ($argc < 2) {
        show_help();
        return 1;
    }
    
    $command = $argv[1];
    $args = array_slice($argv, 2);
    
    // Set BC scale for high precision
    bcscale(0);
    
    // Execute command
    try {
        switch ($command) {
            case 'help':
                show_help();
                return 0;
                
            case 'version':
                show_version();
                return 0;
                
            case 'generate':
                return cmd_generate($args);
                
            case 'sign':
                return cmd_sign($args);
                
            case 'verify':
                return cmd_verify($args);
                
            case 'parse':
                return cmd_parse($args);
                
            default:
                echo "ERROR: Unknown command: $command\n";
                echo "       Use 'php ed521_cli.php help' for available commands.\n";
                return 1;
        }
    } catch (Exception $e) {
        echo "ERROR: " . $e->getMessage() . "\n";
        return 1;
    }
}

// Execute main function if run from command line
if (PHP_SAPI === 'cli' && basename(__FILE__) === basename($_SERVER['PHP_SELF'])) {
    exit(main());
}

// If included as a library, don't execute
return;
