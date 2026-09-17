<?php
/**
 * Contact form handler for Hotel Alpenblick
 * Uses PHPMailer via mx.rhone.ch SMTP
 * Credentials: /var/www/alpenblick.swiss/smtp-config.php (outside document root, not in repo)
 *
 * Anti-spam layers:
 *   1. Honeypot fields (website, company) — must stay empty.
 *   2. CSRF-style token fetched from this endpoint — prevents direct POSTs without session.
 *   3. Minimum/maximum token age — bots are fast, replays are old.
 *   4. Per-session rate limiting — max 5 submissions per hour, min 15 s apart.
 *   5. URL / shortener filter in message/subject/name/phone — blocks most spam links.
 */

require __DIR__ . '/vendor/autoload.php';

// SMTP-Konfiguration: mehrere Kandidaten (Plesk private/, DocRoot)
// smtp-config.php wird NICHT ins Deploy-Repo committet (enthält Credentials)
$_smtp_configs = [
    __DIR__ . '/../private/smtp-config.php',  // Plesk: vhost/private/ (nicht web-erreichbar)
    __DIR__ . '/smtp-config.php',             // Fallback: DocRoot (durch .htaccess + PHP-Ausführung geschützt)
];
$_smtp_loaded = false;
foreach ($_smtp_configs as $_cfg) {
    if (file_exists($_cfg)) { require $_cfg; $_smtp_loaded = true; break; }
}
if (!$_smtp_loaded) {
    error_log('smtp-config.php nicht gefunden');
    http_response_code(500);
    exit('Configuration error.');
}

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

const TOKEN_MIN_AGE     = 3;     // seconds — form must be open at least this long
const TOKEN_MAX_AGE     = 3600;  // seconds — token expires after this long
const RATE_LIMIT_HOUR   = 5;     // max submissions per session per hour
const RATE_LIMIT_DELAY  = 15;    // seconds between two submissions

session_start();

// --------------------------------------------------------------------------
// Token endpoint (called by JS when the contact page loads)
// --------------------------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'GET' && ($_GET['action'] ?? '') === 'token') {
    header('Content-Type: text/plain; charset=utf-8');
    $token = bin2hex(random_bytes(16));
    $_SESSION['contact_token']      = $token;
    $_SESSION['contact_token_time'] = time();
    echo $token;
    exit;
}

// Only accept POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: /ueber-uns/kontakt/');
    exit;
}

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------
function redirect_error(string $error, string $lang): void {
    $base = match ($lang) {
        'fr' => '/fr/a-propos/contact/',
        'en' => '/en/about/contact/',
        default => '/ueber-uns/kontakt/',
    };
    header('Location: ' . $base . '?error=' . $error);
    exit;
}

function redirect_danke(string $lang): void {
    $danke = match ($lang) {
        'fr' => '/fr/merci/',
        'en' => '/en/thank-you/',
        default => '/danke/',
    };
    header('Location: ' . $danke);
    exit;
}

function is_spam_text(string $text): bool {
    if ($text === '') {
        return false;
    }
    $text = strip_tags($text);
    $patterns = [
        '#https?://#i',
        '#www\.#'
    ];
    // Common URL shorteners / redirect services
    $shorteners = [
        'is\.gd', 'bit\.ly', 'tinyurl', 't\.co', 'rb\.gy', 'cutt\.ly',
        'shorturl', 'ow\.ly', 'short\.link', 'goo\.gl', 'buff\.ly',
        'rebrand\.ly', 'bl\.ink', 'lnkd\.in', 'short\.io', 't1p\.de',
        'qr\.ae', 'urls\.im', 'v\.gd', 'po\.st', 'tr\.im',
    ];
    foreach ($shorteners as $s) {
        $patterns[] = '#\b' . $s . '\b#i';
    }
    foreach ($patterns as $pattern) {
        if (preg_match($pattern, $text)) {
            return true;
        }
    }
    return false;
}

function is_rate_limited(): bool {
    $now = time();
    $submissions = $_SESSION['contact_submissions'] ?? [];
    // drop older than 1 hour
    $submissions = array_filter($submissions, fn($t) => ($now - $t) <= 3600);
    if (count($submissions) >= RATE_LIMIT_HOUR) {
        return true;
    }
    $last = end($submissions);
    if ($last !== false && ($now - $last) < RATE_LIMIT_DELAY) {
        return true;
    }
    return false;
}

function record_submission(): void {
    $submissions = $_SESSION['contact_submissions'] ?? [];
    $submissions[] = time();
    $_SESSION['contact_submissions'] = $submissions;
}

// --------------------------------------------------------------------------
// Anti-spam checks
// --------------------------------------------------------------------------

// 1. Honeypots
if (!empty($_POST['website']) || !empty($_POST['company'])) {
    // Silently drop — show the spammer a success page so they don't retry.
    $lang = htmlspecialchars(trim($_POST['lang'] ?? 'de'), ENT_QUOTES, 'UTF-8');
    redirect_danke($lang);
}

// 2. CSRF token
$lang = htmlspecialchars(trim($_POST['lang'] ?? 'de'), ENT_QUOTES, 'UTF-8');
$token = $_POST['csrf_token'] ?? '';
$expected = $_SESSION['contact_token'] ?? '';
$tokenTime = $_SESSION['contact_token_time'] ?? 0;

if (!is_string($token) || !hash_equals($expected, $token)) {
    redirect_error('spam', $lang);
}

$age = time() - $tokenTime;
if ($age < TOKEN_MIN_AGE || $age > TOKEN_MAX_AGE) {
    redirect_error('spam', $lang);
}

// One-time token
unset($_SESSION['contact_token'], $_SESSION['contact_token_time']);

// 3. Rate limit
if (is_rate_limited()) {
    redirect_error('spam', $lang);
}

// --------------------------------------------------------------------------
// Sanitize inputs
// --------------------------------------------------------------------------
$name      = htmlspecialchars(trim($_POST['name']      ?? ''), ENT_QUOTES, 'UTF-8');
$email     = filter_var(trim($_POST['email']           ?? ''), FILTER_SANITIZE_EMAIL);
$telefon   = htmlspecialchars(trim($_POST['telefon']   ?? ''), ENT_QUOTES, 'UTF-8');
$betreff   = htmlspecialchars(trim($_POST['betreff']   ?? ''), ENT_QUOTES, 'UTF-8');
$nachricht = htmlspecialchars(trim($_POST['nachricht'] ?? ''), ENT_QUOTES, 'UTF-8');

// Validate required fields
if (empty($name) || empty($email) || empty($nachricht)) {
    redirect_error('missing', $lang);
}

if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    redirect_error('email', $lang);
}

// 4. URL / link spam filter
if (is_spam_text($nachricht) || is_spam_text($betreff) || is_spam_text($telefon) || is_spam_text($name)) {
    redirect_error('spam', $lang);
}

// --------------------------------------------------------------------------
// Build message body
// --------------------------------------------------------------------------
$body  = "Neue Kontaktanfrage über die Website:\n\n";
$body .= "Name:      $name\n";
$body .= "E-Mail:    $email\n";
if ($telefon)  $body .= "Telefon:   $telefon\n";
if ($betreff)  $body .= "Betreff:   $betreff\n";
$body .= "\nNachricht:\n$nachricht\n";
$body .= "\n---\nGesendet am " . date('d.m.Y H:i') . " Uhr\n";

$subject = '[Alpenblick Website] ' . ($betreff ?: 'Kontaktanfrage von ' . $name);

// --------------------------------------------------------------------------
// Send via PHPMailer
// --------------------------------------------------------------------------
$mail = new PHPMailer(true);
try {
    $mail->isSMTP();
    $mail->Host       = SMTP_HOST;
    $mail->Port       = SMTP_PORT;
    $mail->SMTPAuth   = true;
    $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
    $mail->Username   = SMTP_USER;
    $mail->Password   = SMTP_PASS;
    $mail->CharSet    = 'UTF-8';

    $mail->setFrom(SMTP_FROM, SMTP_FROM_NAME);
    $mail->addReplyTo($email, $name);
    $mail->addAddress(MAIL_TO);

    $mail->Subject = $subject;
    $mail->Body    = $body;

    $mail->send();
    record_submission();
    redirect_danke($lang);
} catch (Exception $e) {
    error_log('PHPMailer error: ' . $mail->ErrorInfo);
    redirect_error('send', $lang);
}
