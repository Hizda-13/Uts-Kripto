<?php
// ============================================
// UTS KRIPTOGRAFI - SUPER APP (Single File)
// PJBL Outcome-Based Education
// Alur RSA & Digital Signature Lengkap
// ============================================

session_start();

// --- Konfigurasi & Inisialisasi ---
$action = isset($_GET['action']) ? $_GET['action'] : 'home';
$result = '';
$error = '';
$success = '';
$input_text = '';
$input_key = '';
$shift = 3;

// Inisialisasi session untuk RSA keys
if (!isset($_SESSION['rsa_private'])) {
    $_SESSION['rsa_private'] = '';
    $_SESSION['rsa_public'] = '';
    $_SESSION['rsa_generated'] = false;
}

// --- Routing Utama dengan switch-case ---
switch ($action) {
    // ==================== HOME ====================
    case 'home':
    default:
        $page_title = 'Beranda';
        break;

    // ==================== CAESAR CIPHER ====================
    case 'caesar':
        $page_title = 'Caesar Cipher';
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $input_text = $_POST['text'] ?? '';
            $shift = isset($_POST['shift']) ? (int)$_POST['shift'] : 3;
            $mode = $_POST['mode'] ?? 'encrypt';
            
            if ($input_text !== '') {
                if ($mode === 'encrypt') {
                    $result = caesarEncrypt($input_text, $shift);
                } else {
                    $result = caesarDecrypt($input_text, $shift);
                }
            } else {
                $error = 'Masukkan teks terlebih dahulu.';
            }
        }
        break;

    // ==================== XOR CIPHER ====================
    case 'xor':
        $page_title = 'XOR Cipher (Bin2Hex)';
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $input_text = $_POST['text'] ?? '';
            $input_key = $_POST['key'] ?? '';
            $mode = $_POST['mode'] ?? 'encrypt';
            
            if ($input_text !== '' && $input_key !== '') {
                if ($mode === 'encrypt') {
                    $xor_result = xorCipher($input_text, $input_key);
                    $result = bin2hex($xor_result);
                } else {
                    $raw = @hex2bin($input_text);
                    if ($raw === false) {
                        $error = 'Input hex tidak valid.';
                    } else {
                        $result = xorCipher($raw, $input_key);
                    }
                }
            } else {
                $error = 'Teks dan kunci harus diisi.';
            }
        }
        break;

    // ==================== SHA-256 HASH ====================
    case 'sha256':
        $page_title = 'SHA-256 Hashing Generator';
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $input_text = $_POST['text'] ?? '';
            if ($input_text !== '') {
                $result = hash('sha256', $input_text);
            } else {
                $error = 'Masukkan teks untuk di-hash.';
            }
        }
        break;

    // ==================== RSA GENERATOR & ENCRYPT ====================
    case 'rsa':
        $page_title = 'RSA Generator & Encrypt (OpenSSL)';
        
        // Generate RSA Key Pair
        if (isset($_POST['generate_rsa'])) {
            $rsa_config = [
                "private_key_bits" => 2048,
                "private_key_type" => OPENSSL_KEYTYPE_RSA,
            ];
            $res = openssl_pkey_new($rsa_config);
            if ($res) {
                openssl_pkey_export($res, $privKey);
                $pubKey = openssl_pkey_get_details($res)['key'];
                $_SESSION['rsa_private'] = $privKey;
                $_SESSION['rsa_public'] = $pubKey;
                $_SESSION['rsa_generated'] = true;
                $success = '✅ RSA Key Pair 2048-bit berhasil dibuat!';
            } else {
                $error = 'Gagal membuat RSA Key Pair.';
            }
        }
        
        // Enkripsi RSA
        if (isset($_POST['encrypt_rsa'])) {
            $plaintext = $_POST['plaintext'] ?? '';
            $public_key = $_POST['public_key'] ?? $_SESSION['rsa_public'];
            
            if (empty($plaintext)) {
                $error = 'Masukkan plaintext terlebih dahulu.';
            } elseif (strlen($plaintext) > 245) {
                $error = 'Plaintext maksimal 245 bytes.';
            } elseif (empty($public_key)) {
                $error = 'Public key tidak tersedia. Generate RSA Key Pair terlebih dahulu.';
            } else {
                $encrypted = '';
                if (openssl_public_encrypt($plaintext, $encrypted, $public_key)) {
                    $result = base64_encode($encrypted);
                    $success = '✅ Enkripsi berhasil!';
                } else {
                    $error = 'Gagal melakukan enkripsi. Pastikan public key valid.';
                }
            }
        }
        
        // Dekripsi RSA
        if (isset($_POST['decrypt_rsa'])) {
            $ciphertext = $_POST['ciphertext'] ?? '';
            $private_key = $_POST['private_key'] ?? $_SESSION['rsa_private'];
            
            if (empty($ciphertext)) {
                $error = 'Masukkan ciphertext (Base64) terlebih dahulu.';
            } elseif (empty($private_key)) {
                $error = 'Private key tidak tersedia. Generate RSA Key Pair terlebih dahulu.';
            } else {
                $encrypted = base64_decode($ciphertext);
                if ($encrypted === false) {
                    $error = 'Ciphertext Base64 tidak valid.';
                } else {
                    $decrypted = '';
                    if (openssl_private_decrypt($encrypted, $decrypted, $private_key)) {
                        $result = $decrypted;
                        $success = '✅ Dekripsi berhasil!';
                    } else {
                        $error = '❌ Private key tidak valid atau ciphertext rusak.';
                    }
                }
            }
        }
        break;

    // ==================== DIGITAL SIGNATURE ====================
    case 'signature':
        $page_title = 'Digital Signature (Sign & Verify)';
        $sign_result = '';
        $verify_result = '';
        
        // Generate RSA Key Pair untuk Signature
        if (isset($_POST['generate_rsa_sig'])) {
            $rsa_config = [
                "private_key_bits" => 2048,
                "private_key_type" => OPENSSL_KEYTYPE_RSA,
            ];
            $res = openssl_pkey_new($rsa_config);
            if ($res) {
                openssl_pkey_export($res, $privKey);
                $pubKey = openssl_pkey_get_details($res)['key'];
                $_SESSION['rsa_private'] = $privKey;
                $_SESSION['rsa_public'] = $pubKey;
                $_SESSION['rsa_generated'] = true;
                $success = '✅ RSA Key Pair 2048-bit berhasil dibuat!';
            } else {
                $error = 'Gagal membuat RSA Key Pair.';
            }
        }
        
        // Sign Document
        if (isset($_POST['sign_doc'])) {
            $document = $_POST['document'] ?? '';
            $private_key = $_POST['private_key_sig'] ?? '';
            
            if (empty($document)) {
                $error = 'Masukkan dokumen/teks terlebih dahulu.';
            } elseif (empty($private_key)) {
                $error = 'Masukkan private key terlebih dahulu.';
            } else {
                $signature = '';
                if (openssl_sign($document, $signature, $private_key, OPENSSL_ALGO_SHA256)) {
                    $sign_result = base64_encode($signature);
                    $success = '✅ Tanda tangan digital berhasil dibuat!';
                } else {
                    $error = '❌ Gagal membuat tanda tangan. Pastikan private key valid.';
                }
            }
        }
        
        // Verify Document
        if (isset($_POST['verify_doc'])) {
            $document = $_POST['document_verify'] ?? '';
            $signature_input = $_POST['signature_verify'] ?? '';
            $public_key = $_POST['public_key_verify'] ?? '';
            
            if (empty($document) || empty($signature_input) || empty($public_key)) {
                $error = 'Lengkapi semua field: dokumen, signature, dan public key.';
            } else {
                $signature = base64_decode($signature_input);
                if ($signature === false) {
                    $error = 'Signature Base64 tidak valid.';
                } else {
                    $verify_ok = openssl_verify($document, $signature, $public_key, OPENSSL_ALGO_SHA256);
                    if ($verify_ok === 1) {
                        $verify_result = '✅ Verifikasi Berhasil! Dokumen asli dan tanda tangan digital valid.';
                    } elseif ($verify_ok === 0) {
                        $verify_result = '❌ Verifikasi Gagal! Dokumen atau tanda tangan tidak valid.';
                    } else {
                        $error = '❌ Terjadi kesalahan saat verifikasi. Pastikan public key valid.';
                    }
                }
            }
        }
        break;
}

// --- Fungsi Bantu ---
function caesarEncrypt($text, $shift) {
    $result = '';
    $shift = $shift % 26;
    for ($i = 0; $i < strlen($text); $i++) {
        $c = $text[$i];
        if (ctype_alpha($c)) {
            $base = ctype_upper($c) ? 'A' : 'a';
            $result .= chr(((ord($c) - ord($base) + $shift) % 26) + ord($base));
        } else {
            $result .= $c;
        }
    }
    return $result;
}

function caesarDecrypt($text, $shift) {
    return caesarEncrypt($text, 26 - ($shift % 26));
}

function xorCipher($text, $key) {
    $out = '';
    $keyLen = strlen($key);
    for ($i = 0; $i < strlen($text); $i++) {
        $out .= $text[$i] ^ $key[$i % $keyLen];
    }
    return $out;
}
?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Kripto Tools - <?php echo $page_title; ?></title>
    <style>
        :root {
            --bg: #0f172a;
            --surface: #1e293b;
            --surface2: #0f172a;
            --border: #334155;
            --text: #e2e8f0;
            --text2: #94a3b8;
            --accent: #0d9488;
            --accent2: #0369a1;
            --success: #10b981;
            --danger: #ef4444;
            --warning: #f59e0b;
            --radius: 12px;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background: var(--bg);
            color: var(--text);
            min-height: 100vh;
            padding: 20px;
        }
        .container {
            max-width: 1000px;
            margin: 0 auto;
            background: var(--surface);
            border-radius: 20px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.5);
            overflow: hidden;
            border: 1px solid var(--border);
        }
        .header {
            background: linear-gradient(135deg, #0f766e, #0d9488);
            padding: 20px 30px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            flex-wrap: wrap;
            gap: 15px;
        }
        .header h1 { font-size: 1.8rem; font-weight: 700; color: white; }
        .status { color: #a7f3d0; font-size: 0.85rem; display: flex; align-items: center; gap: 8px; }
        .status::before { content: ''; width: 10px; height: 10px; background: #10b981; border-radius: 50%; box-shadow: 0 0 10px #10b981; animation: pulse 2s infinite; }
        @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.5} }
        nav {
            background: #0f172a;
            padding: 12px 20px;
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            border-bottom: 1px solid var(--border);
        }
        nav a {
            color: #94a3b8;
            text-decoration: none;
            padding: 10px 16px;
            border-radius: 25px;
            font-weight: 600;
            font-size: 0.85rem;
            transition: all 0.2s;
            white-space: nowrap;
        }
        nav a:hover, nav a.active { background: var(--accent); color: white; }
        .content { padding: 25px; }
        .card {
            background: var(--surface2);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 25px;
            margin-bottom: 20px;
        }
        .card h3 { margin-bottom: 8px; font-size: 1.3rem; }
        .card p.desc { color: var(--text2); margin-bottom: 20px; font-size: 0.9rem; }
        .form-group { margin-bottom: 16px; }
        label { display: block; margin-bottom: 6px; font-weight: 600; color: #cbd5e1; font-size: 0.9rem; }
        textarea, input[type="text"], input[type="number"], select {
            width: 100%;
            padding: 12px 16px;
            background: #1e293b;
            border: 1px solid #475569;
            border-radius: 10px;
            color: #f1f5f9;
            font-size: 0.95rem;
            font-family: 'Courier New', monospace;
            resize: vertical;
        }
        textarea:focus, input:focus { outline: none; border-color: var(--accent); box-shadow: 0 0 0 3px rgba(13,148,136,0.2); }
        .btn {
            padding: 12px 24px;
            border: none;
            border-radius: 25px;
            font-weight: 700;
            cursor: pointer;
            transition: 0.2s;
            font-size: 0.9rem;
            display: inline-flex;
            align-items: center;
            gap: 6px;
        }
        .btn-primary { background: var(--accent); color: white; }
        .btn-primary:hover { background: #0f766e; }
        .btn-secondary { background: #475569; color: white; }
        .btn-secondary:hover { background: #334155; }
        .btn-warning { background: var(--warning); color: #1e293b; }
        .btn-warning:hover { background: #d97706; }
        .btn-danger { background: var(--danger); color: white; }
        .btn-sm { padding: 8px 16px; font-size: 0.8rem; }
        .btn-group { display: flex; flex-wrap: wrap; gap: 10px; margin-top: 10px; }
        .result-box {
            background: #020617;
            border: 1px dashed var(--border);
            padding: 16px;
            border-radius: 10px;
            margin-top: 15px;
            word-break: break-all;
            font-family: 'Courier New', monospace;
            font-size: 0.85rem;
            position: relative;
        }
        .result-box.success { border-color: var(--success); color: #a7f3d0; }
        .result-box.error { border-color: var(--danger); color: #fca5a5; }
        .result-label { font-weight: 700; color: #cbd5e1; margin-bottom: 5px; display: block; }
        .copy-btn {
            position: absolute;
            top: 8px;
            right: 8px;
            background: #334155;
            border: none;
            color: white;
            padding: 5px 12px;
            border-radius: 15px;
            font-size: 0.75rem;
            cursor: pointer;
            transition: 0.2s;
            z-index: 2;
        }
        .copy-btn:hover { background: var(--accent); }
        .alert { padding: 12px 18px; border-radius: 10px; margin-bottom: 15px; font-weight: 600; font-size: 0.9rem; }
        .alert-success { background: #064e3b; color: #a7f3d0; border: 1px solid #10b981; }
        .alert-error { background: #7f1d1d; color: #fca5a5; border: 1px solid #ef4444; }
        .key-display {
            background: #020617;
            padding: 12px;
            border-radius: 8px;
            font-size: 0.7rem;
            color: #94a3b8;
            max-height: 120px;
            overflow-y: auto;
            white-space: pre-wrap;
            word-break: break-all;
            position: relative;
            margin-top: 5px;
            padding-top: 35px;
        }
        hr { border-color: #334155; margin: 20px 0; }
        .row { display: flex; gap: 20px; flex-wrap: wrap; }
        .col { flex: 1; min-width: 280px; position: relative; }
        @media (max-width: 600px) {
            .content { padding: 15px; }
            nav a { flex: 1; text-align: center; font-size: 0.75rem; padding: 8px; }
        }
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <div>
            <h1>🛡️ Kripto Tools</h1>
            <div style="font-size:0.9rem; color:#ccfbf1;">Super App - Proyek PJBL (OBE)</div>
        </div>
        <div class="status">Secure Encryption Active</div>
    </div>
    <nav>
        <a href="?action=home" class="<?= $action=='home'?'active':'' ?>">🏠 Home</a>
        <a href="?action=caesar" class="<?= $action=='caesar'?'active':'' ?>">🔐 Caesar</a>
        <a href="?action=xor" class="<?= $action=='xor'?'active':'' ?>">⚡ XOR</a>
        <a href="?action=sha256" class="<?= $action=='sha256'?'active':'' ?>">🔒 SHA-256</a>
        <a href="?action=rsa" class="<?= $action=='rsa'?'active':'' ?>">🔑 RSA</a>
        <a href="?action=signature" class="<?= $action=='signature'?'active':'' ?>">✍️ Signature</a>
    </nav>
    <div class="content">
        <?php if (!empty($success)): ?>
            <div class="alert alert-success"><?= $success ?></div>
        <?php endif; ?>
        <?php if (!empty($error)): ?>
            <div class="alert alert-error"><?= $error ?></div>
        <?php endif; ?>

        <?php if ($action === 'home'): ?>
            <div class="card">
                <h2>Selamat Datang di Kripto Tools Super App</h2>
                <p style="margin-top:10px; color:#94a3b8;">Pilih alat kriptografi dari menu di atas. Aplikasi ini dibuat untuk UTS berbasis proyek (PjBL OBE).</p>
                <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(130px,1fr)); gap:15px; margin-top:25px;">
                    <div style="background:#0f766e; padding:20px; border-radius:12px; text-align:center; font-weight:700;">🔐<br>Caesar Cipher</div>
                    <div style="background:#0369a1; padding:20px; border-radius:12px; text-align:center; font-weight:700;">⚡<br>XOR Cipher</div>
                    <div style="background:#7c3aed; padding:20px; border-radius:12px; text-align:center; font-weight:700;">🔒<br>SHA-256</div>
                    <div style="background:#b45309; padding:20px; border-radius:12px; text-align:center; font-weight:700;">🔑<br>RSA</div>
                    <div style="background:#be123c; padding:20px; border-radius:12px; text-align:center; font-weight:700;">✍️<br>Digital Sign</div>
                </div>
            </div>
        <?php elseif ($action === 'caesar'): ?>
            <div class="card">
                <h3>🔐 Caesar Cipher</h3>
                <p class="desc">Enkripsi tertua dengan pergeseran huruf. Contoh: "KRIPTO" shift 3 → "NULSWR"</p>
                <form method="post">
                    <div class="form-group"><label>Masukkan Teks</label><textarea name="text" rows="3"><?= htmlspecialchars($input_text) ?></textarea></div>
                    <div class="row">
                        <div class="form-group col"><label>Shift (Pergeseran)</label><input type="number" name="shift" value="<?= $shift ?>" min="1" max="25"></div>
                        <div class="form-group col"><label>Mode</label><select name="mode"><option value="encrypt">Enkripsi</option><option value="decrypt">Dekripsi</option></select></div>
                    </div>
                    <button type="submit" class="btn btn-primary">Proses</button>
                </form>
                <?php if ($result !== ''): ?>
                    <div class="result-box success">
                        <span class="result-label">Hasil:</span>
                        <span id="caesarResult"><?= htmlspecialchars($result) ?></span>
                        <button class="copy-btn" onclick="copyText('caesarResult', this)">📋 Copy</button>
                    </div>
                <?php endif; ?>
            </div>
        <?php elseif ($action === 'xor'): ?>
            <div class="card">
                <h3>⚡ XOR Cipher (dengan output Hex)</h3>
                <p class="desc">Enkripsi berbasis XOR, hasil ditampilkan dalam heksadesimal. Dekripsi masukkan hex.</p>
                <form method="post">
                    <div class="form-group"><label>Teks / Hex</label><textarea name="text" rows="3"><?= htmlspecialchars($input_text) ?></textarea></div>
                    <div class="form-group"><label>Kunci</label><input type="text" name="key" value="<?= htmlspecialchars($input_key) ?>"></div>
                    <div class="form-group"><label>Mode</label><select name="mode"><option value="encrypt">Enkripsi (ke Hex)</option><option value="decrypt">Dekripsi (dari Hex)</option></select></div>
                    <button type="submit" class="btn btn-primary">Proses</button>
                </form>
                <?php if ($result !== ''): ?>
                    <div class="result-box success">
                        <span class="result-label">Hasil:</span>
                        <span id="xorResult"><?= htmlspecialchars($result) ?></span>
                        <button class="copy-btn" onclick="copyText('xorResult', this)">📋 Copy</button>
                    </div>
                <?php endif; ?>
            </div>
        <?php elseif ($action === 'sha256'): ?>
            <div class="card">
                <h3>🔒 SHA-256 Hashing Generator</h3>
                <form method="post">
                    <div class="form-group"><label>Teks untuk di-Hash</label><textarea name="text" rows="3"><?= htmlspecialchars($input_text) ?></textarea></div>
                    <button type="submit" class="btn btn-primary">Generate Hash</button>
                </form>
                <?php if ($result !== ''): ?>
                    <div class="result-box success">
                        <span class="result-label">SHA-256:</span>
                        <span id="shaResult"><?= htmlspecialchars($result) ?></span>
                        <button class="copy-btn" onclick="copyText('shaResult', this)">📋 Copy</button>
                    </div>
                <?php endif; ?>
            </div>
        <?php elseif ($action === 'rsa'): ?>
            <!-- RSA SECTION -->
            <div class="card">
                <h3>🔑 RSA Key Generator</h3>
                <p class="desc">Generate RSA Key Pair 2048-bit untuk enkripsi/dekripsi.</p>
                <form method="post">
                    <button type="submit" name="generate_rsa" class="btn btn-warning">🔄 Generate RSA Key Pair (2048-bit)</button>
                </form>
                <?php if ($_SESSION['rsa_generated']): ?>
                <div class="row" style="margin-top:15px;">
                    <div class="col">
                        <strong>Private Key:</strong>
                        <div class="key-display" id="rsaPrivateKey"><?= htmlspecialchars($_SESSION['rsa_private']) ?></div>
                        <button class="btn btn-sm btn-secondary copy-btn" style="position:static;margin-top:5px;" onclick="copyText('rsaPrivateKey', this)">📋 Copy Private Key</button>
                    </div>
                    <div class="col">
                        <strong>Public Key:</strong>
                        <div class="key-display" id="rsaPublicKey"><?= htmlspecialchars($_SESSION['rsa_public']) ?></div>
                        <button class="btn btn-sm btn-secondary copy-btn" style="position:static;margin-top:5px;" onclick="copyText('rsaPublicKey', this)">📋 Copy Public Key</button>
                    </div>
                </div>
                <?php endif; ?>
            </div>

            <div class="card">
                <h3>🔐 Enkripsi RSA</h3>
                <p class="desc">Masukkan plaintext (max 245 bytes) dan gunakan public key.</p>
                <form method="post">
                    <div class="form-group"><label>Plaintext (max 245 bytes)</label><textarea name="plaintext" rows="3" placeholder="Masukkan teks yang akan dienkripsi..."><?= htmlspecialchars($_POST['plaintext'] ?? '') ?></textarea></div>
                    <div class="form-group"><label>Public Key</label><textarea name="public_key" rows="5" placeholder="Tempel public key di sini..."><?= htmlspecialchars($_POST['public_key'] ?? $_SESSION['rsa_public']) ?></textarea></div>
                    <button type="submit" name="encrypt_rsa" class="btn btn-primary">🔒 Enkripsi dengan RSA</button>
                </form>
                <?php if (isset($_POST['encrypt_rsa']) && $result !== ''): ?>
                    <div class="result-box success">
                        <span class="result-label">Hasil Enkripsi RSA (Base64):</span>
                        <span id="rsaEncryptResult"><?= htmlspecialchars($result) ?></span>
                        <button class="copy-btn" onclick="copyText('rsaEncryptResult', this)">📋 Copy</button>
                    </div>
                <?php endif; ?>
            </div>

            <div class="card">
                <h3>🔓 Dekripsi RSA</h3>
                <p class="desc">Masukkan ciphertext (Base64) dan private key.</p>
                <form method="post">
                    <div class="form-group"><label>Ciphertext (Base64)</label><textarea name="ciphertext" rows="3" placeholder="Tempel ciphertext Base64..."><?= htmlspecialchars($_POST['ciphertext'] ?? '') ?></textarea></div>
                    <div class="form-group"><label>Private Key</label><textarea name="private_key" rows="5" placeholder="Tempel private key di sini..."><?= htmlspecialchars($_POST['private_key'] ?? $_SESSION['rsa_private']) ?></textarea></div>
                    <button type="submit" name="decrypt_rsa" class="btn btn-primary">🔓 Dekripsi dengan RSA</button>
                </form>
                <?php if (isset($_POST['decrypt_rsa']) && $result !== ''): ?>
                    <div class="result-box success">
                        <span class="result-label">Hasil Dekripsi (Plaintext):</span>
                        <span id="rsaDecryptResult"><?= htmlspecialchars($result) ?></span>
                        <button class="copy-btn" onclick="copyText('rsaDecryptResult', this)">📋 Copy</button>
                    </div>
                <?php endif; ?>
            </div>
        <?php elseif ($action === 'signature'): ?>
            <!-- DIGITAL SIGNATURE SECTION -->
            <div class="card">
                <h3>🔑 RSA Key Generator (untuk Signature)</h3>
                <p class="desc">Generate RSA Key Pair 2048-bit untuk tanda tangan digital.</p>
                <form method="post">
                    <button type="submit" name="generate_rsa_sig" class="btn btn-warning">🔄 Generate RSA Key Pair (2048-bit)</button>
                </form>
                <?php if ($_SESSION['rsa_generated']): ?>
                <div class="row" style="margin-top:15px;">
                    <div class="col">
                        <strong>Private Key:</strong>
                        <div class="key-display" id="sigPrivateKey"><?= htmlspecialchars($_SESSION['rsa_private']) ?></div>
                        <button class="btn btn-sm btn-secondary copy-btn" style="position:static;margin-top:5px;" onclick="copyText('sigPrivateKey', this)">📋 Copy Private Key</button>
                    </div>
                    <div class="col">
                        <strong>Public Key:</strong>
                        <div class="key-display" id="sigPublicKey"><?= htmlspecialchars($_SESSION['rsa_public']) ?></div>
                        <button class="btn btn-sm btn-secondary copy-btn" style="position:static;margin-top:5px;" onclick="copyText('sigPublicKey', this)">📋 Copy Public Key</button>
                    </div>
                </div>
                <?php endif; ?>
            </div>

            <div class="card">
                <h3>✍️ Sign Document (Tanda Tangani)</h3>
                <p class="desc">Masukkan dokumen dan private key untuk membuat tanda tangan digital.</p>
                <form method="post">
                    <div class="form-group"><label>Dokumen (Teks)</label><textarea name="document" rows="3" placeholder="Contoh: Transfer ke Andi: 100.000"><?= htmlspecialchars($_POST['document'] ?? '') ?></textarea></div>
                    <div class="form-group"><label>Private Key</label><textarea name="private_key_sig" rows="5" placeholder="Tempel private key di sini..."><?= htmlspecialchars($_POST['private_key_sig'] ?? '') ?></textarea></div>
                    <button type="submit" name="sign_doc" class="btn btn-primary">✍️ Jalankan Proses (Sign)</button>
                </form>
                <?php if (!empty($sign_result)): ?>
                    <div class="result-box success">
                        <span class="result-label">Signature (Base64):</span>
                        <span id="signResult"><?= htmlspecialchars($sign_result) ?></span>
                        <button class="copy-btn" onclick="copyText('signResult', this)">📋 Copy Signature</button>
                    </div>
                <?php endif; ?>
            </div>

            <div class="card">
                <h3>🔍 Verify Document (Verifikasi)</h3>
                <p class="desc">Verifikasi tanda tangan digital dengan dokumen, signature, dan public key.</p>
                <form method="post">
                    <div class="form-group"><label>Dokumen (Teks Asli)</label><textarea name="document_verify" rows="3" placeholder="Masukkan teks dokumen asli..."><?= htmlspecialchars($_POST['document_verify'] ?? $_POST['document'] ?? '') ?></textarea></div>
                    <div class="form-group"><label>Signature (Base64)</label><textarea name="signature_verify" rows="3" placeholder="Tempel signature Base64..."><?= htmlspecialchars($_POST['signature_verify'] ?? '') ?></textarea></div>
                    <div class="form-group"><label>Public Key</label><textarea name="public_key_verify" rows="5" placeholder="Tempel public key di sini..."><?= htmlspecialchars($_POST['public_key_verify'] ?? '') ?></textarea></div>
                    <button type="submit" name="verify_doc" class="btn btn-warning">🔍 Verifikasi</button>
                </form>
                <?php if (!empty($verify_result)): ?>
                    <div class="result-box <?= strpos($verify_result, '✅') !== false ? 'success' : 'error' ?>">
                        <span id="verifyResult"><?= $verify_result ?></span>
                    </div>
                <?php endif; ?>
            </div>
        <?php endif; ?>
    </div>
</div>

<script>
function copyText(elementId, btnElement) {
    const element = document.getElementById(elementId);
    if (!element) return;
    
    const text = element.innerText || element.textContent;
    
    navigator.clipboard.writeText(text).then(() => {
        // Efek feedback pada tombol yang diklik
        if (btnElement) {
            const originalText = btnElement.innerText;
            btnElement.innerText = '✅ Tersalin!';
            btnElement.style.background = '#10b981';
            setTimeout(() => {
                btnElement.innerText = originalText;
                btnElement.style.background = ''; // Kembali ke style default
            }, 1500);
        }
    }).catch(err => {
        alert('Gagal menyalin: ' + err);
    });
}
</script>
</body>
</html>
