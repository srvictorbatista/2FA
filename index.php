<?php
/**
 * Sistema de Autenticação API (single-file)
 * --------------------------------------------------------------------------------------------------------------------------------------------------
 * Recursos:
 * - Configurações no topo (DB, chaves, diretórios).
 * - Criação automática do banco de dados e das tabelas na 1ª execução.
 * - Cadastro e ativação de usuários.
 * - Login com validação via banco (PDO) + geração de código 2FA (6 dígitos).
 * - Códigos 2FA salvos como arquivos cifrados em pasta reservada; nomes aleatórios.
 * - Os arquivos não contêm metadados legíveis que relacionem usuário; payload cifrado com APP_SECRET.
 * - Códigos válidos por 120 minutos; limpeza automática (garbage collector) em cada requisição.
 * - Ao validar o 2º passo, o arquivo é excluído sem deixar rastro do número.
 * - Logs completos em tabela 'logs' (eventos, timestamps, user_id quando possível). NÃO gravamos o valor do OTP em logs.
 * - Sessões por token seguro; tokens retornados ao cliente (Bearer token). Sessões expiram por inatividade após 4 horas.
 * - Opção "lembrar-me": sessão persistente até logout explícito (apenas para a máquina que recebeu o token).
 * - Endpoints REST JSON; todas as respostas são JSON.
 * - Front-end mínimo em dark-mode (HTML+JS) que usa a API via fetch.
 *
 * Segurança / Produção (observações — não implementadas por padrão):
 * - Use HTTPS obrigatório em produção.
 * - Mantenha APP_SECRET fora do controle de versão (ex.: vault / variáveis de ambiente).
 * - Proteja a pasta OTP fora do webroot; configure regras de servidor para negar acesso direto.
 * - Considere HSM ou KMS para chaves; rate limiting; proteção contra brute-force OTP.
 * - Em escala, indexar OTPs de modo seguro (ex.: chave derivada) para evitar varredura linear.
 * - Para envio dos códigos use canal seguro (e-mail, SMS, app) em vez de retorná-los na API.
 *
 * Exemplos de uso (Insomnia / curl):
 * AVISO: Não use curl -k (ignogar certificados) para hosts em produção
 *
 * 1) Registrar (exige nivel de acesso):
 *    POST /register  { "username":"joao","email":"j@d.com","password":"SenhaForte123!" }
 *    curl -k -X POST <url>/register -H "Content-Type: application/json" -H "Authorization: Bearer <token>" -d "{\"username\":\"usuario1\",\"email\":\"usuario1@local.com\",\"phone\":\"5591999999999\",\"password\":\"senha1234\"}"
 *
 * 2) Ativar:
 *    POST /activate  { "username":"joao","activation_token":"<token_recebido>" }
 *    curl -k -X POST <url>/activate -H "Content-Type: application/json" -d "{\"username\":\"usuario1\",\"activation_token\":\"47cf0a\"}"
{"success":true,"message":"Conta ativada com sucesso"}
 *
 * 3) Login (senha):
 *    POST /login     { "username":"joao","password":"SenhaForte123!" }
 *    -> Resposta contém o código 6 dígitos (apenas para demonstração; em produção enviar por e-mail/SMS)
 *    curl -k -X <url>/login -H "Content-Type: application/json" -d "{\"username\":\"admin\",\"password\":\"admin123\"}"
 *
 * 4) Verificar 2FA:
 *    POST /verify-otp { "code":"123456" } -> responde com { "token": "<session_token>" }
 *    curl -k -X POST <url>/verify-otp -H "Content-Type: application/json" -d "{\"code\":\"569379\",\"remember_me\":true}"
 *
 * Endpoints protegidos (exemplo GET /me /logout): Authorization: Bearer <token>
 * 6) Logout via GET (considere o ususario já logado):
 *    GET /logout?token=<token>  (ou via header Authorization)
 *
 *    Exemplo do endpoint "/logout" em cURL
 *    curl -k -G <url>/logout --data-urlencode "token=<token>"
 *
 *    Exemplo do endpoint "/me" em cURL (considere o ususario já logado)
 *    curl -k -H "Authorization: Bearer <token>"  <url>/me
 *
 *
 * Observações: 
 * Ajuste as variáveis de configuração para produção (APP_SECRET, DB_*).
 * Considerer sempre o envio de tokens e codigos por canais seguors em produção (WhatsApp, SMS, email). 
 * Registro de logs, sempre ativo a acda evento.
 * Mensagens de erro retornam JSON.
 *
 *
 * Recursos:
 * - Criação automática de .htaccess (raiz) e .htaccess na pasta OTP (nega acesso).
 * - CORS / preflight OPTIONS tratado.
 * - Criação de DB/tabelas e usuário administrador (admin / admin123) na 1ª execução.
 * - Registro de eventos (logs).
 * - Login com 2FA via arquivo cifrado (AES-256-GCM) em pasta protegida.
 * - Sessões por token (Bearer) com timeout por inatividade; opção lembrar-me.
 * - Front-end dark-mode, salva token em localStorage + cookie e exibe debug do token.
 *
 */


// ini_set('display_errors', 1); error_reporting(E_ALL);
declare(strict_types=1);
date_default_timezone_set('America/Belem');


/* --------------------------------------------------------------------
   CONFIGURAÇÃO (editar antes de uso)
   -------------------------------------------------------------------- */
$config = [
  'DB_HOST' => 'SEU_SERVIDOR_MYSQL',
  'DB_NAME' => '_NOME_DO_BANCO_PRETENDIDO', // Não precisa estar criado
  'DB_USER' => 'SEU_USUARIO',
  'DB_PASS' => 'SUA_SENHA_SEGURA',
  'APP_SECRET' => '2DD916FEDF509A33AAB0708D77C125E5D2BC708292F70D3053108DE25D96CC43_Dev!',
  'OTP_DIR' => __DIR__ . '/.otp_secret',
  'OTP_TTL' => 20 * 60,                   // Tempo de expiração do OTP (20 minutos)
  'SESSION_IDLE_TIMEOUT' => 4 * 3600,     // Inatividade 4 horas (sem lembrar-me)
  'FRONT_END' => true, // USe: silent (permite include) | 1/true (exibir) | 0/false (desativar) frond end com exemplos de uso
  'COOKIE_NAME' => 'AFABB-AUTH_SESSION',
  'CIPHER' => 'aes-256-gcm'
];



/* --------------------------------------------------------------------
   CORS / Preflight
   -------------------------------------------------------------------- */
function send_cors_headers(): void {
  header('Access-Control-Allow-Origin: *'); // * permite todas as origens
  header('Access-Control-Allow-Methods: GET, POST, OPTIONS, PUT, DELETE');
  header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With');
  header('Access-Control-Expose-Headers: Content-Length, Content-Range');
  header('Access-Control-Max-Age: 600');
}
if($_SERVER['REQUEST_METHOD'] === 'OPTIONS'){
  send_cors_headers();http_response_code(204);exit();
}
send_cors_headers();

/* --------------------------------------------------------------------
   .htaccess automático (raiz) e proteção da pasta OTP
   -------------------------------------------------------------------- */
$scriptDir = rtrim(str_replace('\\','/', dirname($_SERVER['SCRIPT_NAME'])), '/');
$rewriteBase = ($scriptDir === '' || $scriptDir === '/') ? '/' : ($scriptDir . '/');
$rootHt = __DIR__ . '/.htaccess';
$rootHtContent = <<<HT
# [ 2FA API ]
# Gerado automaticamente pelo sistema. tenha cuidado ao editar!

RewriteEngine On
RewriteCond %{HTTP:Authorization} ^(.*)
RewriteRule ^ - [E=HTTP_AUTHORIZATION:%1]

Options -MultiViews -Indexes
<IfModule mod_headers.c>
  Header set Access-Control-Allow-Origin "*"
  Header set Access-Control-Allow-Methods "GET, POST, OPTIONS, PUT, DELETE"
  Header set Access-Control-Allow-Headers "Content-Type, Authorization, X-Requested-With"
  Header always set Access-Control-Max-Age "600"
</IfModule>
RewriteEngine On
RewriteBase {$rewriteBase}
RewriteCond %{REQUEST_METHOD} OPTIONS
RewriteRule ^(.*)$ $1 [R=200,L]
RewriteCond %{REQUEST_FILENAME} -f [OR]
RewriteCond %{REQUEST_FILENAME} -d
RewriteRule ^ - [L]
RewriteRule ^ index.php [QSA,L]
HT;
if (!file_exists($rootHt)){ @file_put_contents($rootHt, $rootHtContent); @chmod($rootHt, 0644); }

if (!is_dir($config['OTP_DIR'])) @mkdir($config['OTP_DIR'], 0700, true);
$otp_ht = rtrim($config['OTP_DIR'],'/') . '/.htaccess';
$otpHtContent = <<<OTP
<IfModule mod_authz_core.c>
  Require all denied
</IfModule>
<IfModule !mod_authz_core.c>
  Deny from all
</IfModule>
OTP;
if (!file_exists($otp_ht)){ @file_put_contents($otp_ht, $otpHtContent); @chmod($otp_ht, 0600); }

/* ===========================
   FUNÇÕES: helpers, DB, API
   =========================== */

function json_response($data, int $status = 200): string { http_response_code($status); header('Content-Type: application/json; charset=utf-8'); return json_encode($data, JSON_UNESCAPED_UNICODE); }

function db_connect(){
  global $config;
  $host = $config['DB_HOST']; $db = trim($config['DB_NAME']); $user = $config['DB_USER']; $pass = $config['DB_PASS'];
  $dsnNoDb = "mysql:host=$host;charset=utf8mb4";
  try {
    $pdo = new PDO($dsnNoDb, $user, $pass, [PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false]);
    $dbEsc = preg_replace('/[^a-zA-Z0-9_]/','',$db) ?: 'appdb';
    $pdo->exec("CREATE DATABASE IF NOT EXISTS `$dbEsc` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
    $pdo->exec("USE `$dbEsc`");
    return $pdo;
  } catch (PDOException $e){ echo json_response(['error'=>'Erro de conexão com o banco: '.$e->getMessage()],500); exit; }
}

function ensure_schema(PDO $pdo){
  $pdo->exec("CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    email VARCHAR(255) NULL,
    phone VARCHAR(20) NULL,
    password_hash VARCHAR(255) NOT NULL,
    active TINYINT(1) DEFAULT 0,
    level SMALLINT UNSIGNED DEFAULT 1,
    created_at DATETIME NOT NULL,
    activated_at DATETIME NULL,
    activation_token_hash VARCHAR(255) NULL
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
  $pdo->exec("CREATE TABLE IF NOT EXISTS sessions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    token_hash VARCHAR(255) NOT NULL,
    created_at DATETIME NOT NULL,
    last_activity DATETIME NOT NULL,
    remember_me TINYINT(1) DEFAULT 0,
    ip VARCHAR(45) NULL,
    user_agent TEXT NULL,
    INDEX (token_hash),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
  $pdo->exec("CREATE TABLE IF NOT EXISTS logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NULL,
    event VARCHAR(128) NOT NULL,
    meta JSON NULL,
    created_at DATETIME NOT NULL
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
}

function create_default_admin(PDO $pdo){
  if(!$pdo->query("SELECT 1 FROM users WHERE username='admin' LIMIT 1")->fetch()){
    $pdo->prepare("INSERT INTO users (username,email,phone,password_hash,active,level,created_at,activated_at) VALUES (?,?,?,?,?,?,NOW(),NOW())")
        ->execute([
          'admin',
          'admin@local',
          '55919999999999',
          password_hash('admin123', PASSWORD_DEFAULT),
          1,
          999
        ]);
  }
}

function log_event(PDO $pdo, ?int $user_id, string $event, array $meta = []){
  $stmt = $pdo->prepare("INSERT INTO logs (user_id,event,meta,created_at) VALUES (?,?,?,NOW())");
  $stmt->execute([$user_id, $event, json_encode($meta, JSON_UNESCAPED_UNICODE)]);
}

/* OTP helpers */
function generate_otp(int $length = 6): string { return str_pad((string)random_int(0, (int)str_repeat('9',$length)), $length, '0', STR_PAD_LEFT); }
function encrypt_payload(array $payload): string {
  global $config;
  $plaintext = json_encode($payload, JSON_UNESCAPED_UNICODE);
  $key = hash('sha256',$config['APP_SECRET'],true);
  $cipher = $config['CIPHER'];
  $ivlen = openssl_cipher_iv_length($cipher);
  $iv = random_bytes($ivlen);
  $tag = '';
  $ciphertext = openssl_encrypt($plaintext,$cipher,$key,OPENSSL_RAW_DATA,$iv,$tag);
  if ($ciphertext === false) throw new RuntimeException('Erro na cifragem');
  return base64_encode($iv . $tag . $ciphertext);
}
function decrypt_payload(string $blob): array {
  global $config;
  $data = base64_decode($blob, true);
  if ($data === false) throw new RuntimeException('Blob inválido');
  $cipher = $config['CIPHER'];
  $ivlen = openssl_cipher_iv_length($cipher);
  $taglen = 16;
  $iv = substr($data,0,$ivlen);
  $tag = substr($data,$ivlen,$taglen);
  $ciphertext = substr($data,$ivlen+$taglen);
  $key = hash('sha256',$config['APP_SECRET'],true);
  $plaintext = openssl_decrypt($ciphertext,$cipher,$key,OPENSSL_RAW_DATA,$iv,$tag);
  if ($plaintext === false) throw new RuntimeException('Decifragem falhou');
  $arr = json_decode($plaintext,true);
  if (!is_array($arr)) throw new RuntimeException('JSON inválido no payload decifrado');
  return $arr;
}
function save_otp_file(array $payload): string {
  global $config;
  $filename = bin2hex(random_bytes(16)) . '.otp';
  $path = rtrim($config['OTP_DIR'],'/') . '/' . $filename;
  $cipher = encrypt_payload($payload);
  file_put_contents($path, $cipher, LOCK_EX);
  chmod($path, 0600);
  return $path;
}
function find_otp_by_code(string $code): ?array {
  global $config;
  $dir = rtrim($config['OTP_DIR'],'/') . '/';
  foreach (new DirectoryIterator($dir) as $file){
    if ($file->isFile() && $file->getExtension() === 'otp'){
      $path = $file->getPathname();
      try {
        $blob = file_get_contents($path);
        $pl = decrypt_payload($blob);
        if (isset($pl['code']) && $pl['code'] === $code) return [$path,$pl];
      } catch (Throwable $e){ @unlink($path); }
    }
  }
  return null;
}
function delete_otp_file(string $path): void { @unlink($path); }
function gc_otps(array $config): void {
  $dir = rtrim($config['OTP_DIR'],'/') . '/';
  $ttl = $config['OTP_TTL'];
  $now = time();
  foreach (new DirectoryIterator($dir) as $file){
    if ($file->isFile() && $file->getExtension()==='otp'){
      $path = $file->getPathname();
      try {
        $blob = file_get_contents($path);
        $pl = decrypt_payload($blob);
        $created = isset($pl['created_at']) ? strtotime($pl['created_at']) : filemtime($path);
        if (($now - $created) > $ttl){ @unlink($path); }
      } catch (Throwable $e){ @unlink($path); }
    }
  }
}

/* Sessões */
function generate_session_token(int $length = 32): string{
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'; $max = strlen($alphabet) - 1;$token = '';
    for ($i = 0; $i < $length; $i++){ $token .= $alphabet[random_int(0, $max)]; }
    return $token;
}
function token_hash(string $token): string { global $config; return rtrim(strtoupper(hash_hmac('sha256',$token,$config['APP_SECRET']))); }

function get_bearer_token(): ?string {
  $hdr = $_SERVER['HTTP_AUTHORIZATION'] ?? ($_SERVER['Authorization'] ?? null);
  if ($hdr && preg_match('/Bearer\s+(.+)$/i',$hdr,$m)) return $m[1];
  if (!empty($_GET['token'])) return $_GET['token'];
  return null;
}
function auth_by_token(PDO $pdo, array $config): ?array {
  $token = get_bearer_token(); if (!$token) return null;
  $th = token_hash($token); error_log("auth_by_token: token=$token th=$th");
  $stmt = $pdo->prepare("SELECT s.*, u.id as user_id, u.username, u.email, u.phone, u.level FROM sessions s JOIN users u ON u.id=s.user_id WHERE u.active>0 AND s.token_hash=? LIMIT 1");
  $stmt->execute([$th]); $row = $stmt->fetch(PDO::FETCH_ASSOC);
  if (!$row) return null;
  $idle = $config['SESSION_IDLE_TIMEOUT'];
  $last_activity = strtotime($row['last_activity']);
  if (!$row['remember_me'] && (time() - $last_activity) > $idle){
    $pdo->prepare("DELETE FROM sessions WHERE id=?")->execute([$row['id']]);
    log_event($pdo, (int)$row['user_id'], 'sessao_expirada_por_inatividade', ['session_id'=>$row['id']]);
    return null;
  }
  $pdo->prepare("UPDATE sessions SET last_activity=NOW() WHERE id=?")->execute([$row['id']]);
  return $row;
}

// Verifica se a Maquina Remota esta Autenticada
function rma(): ?array {
  global $pdo, $config;
  $token = get_bearer_token() ?: ($_COOKIE['AFABB-AUTH_SESSION'] ?? null);
  if (!$token) return null;
  $th = token_hash($token);
  //$stmt = $pdo->prepare("SELECT s.*, u.id AS user_id, u.username, u.email, u.phone FROM sessions s JOIN users u ON u.id=s.user_id WHERE u.active>0 AND s.token_hash=? LIMIT 1");
  $stmt = $pdo->prepare("SELECT s.*, u.id as user_id, u.username, u.email, u.phone, u.level FROM sessions s JOIN users u ON u.id=s.user_id WHERE u.active>0 AND s.token_hash=? LIMIT 1");
  $stmt->execute([$th]); $row = $stmt->fetch(PDO::FETCH_ASSOC);
  if (!$row) return null;
  $idle = $config['SESSION_IDLE_TIMEOUT'];
  if (!$row['remember_me'] && (time() - strtotime($row['last_activity'])) > $idle){ $pdo->prepare("DELETE FROM sessions WHERE id=?")->execute([$row['id']]); log_event($pdo,(int)$row['user_id'],'sessão_expirada_por_inatividade',['session_id'=>$row['id']]); return null; }
  $pdo->prepare("UPDATE sessions SET last_activity=NOW() WHERE id=?")->execute([$row['id']]);
  return $row;
}

// verificação de nivel de acesso
function check_level(?string $token=null): ?int {
    global $pdo;
    if(!$token){$token = ($_COOKIE['AFABB-AUTH_SESSION'] ?? null) ?: get_bearer_token();} // Se token do ambiente invalido a prioridade será: cookie, se vazio/indefinido, usa header
    if(!$token){echo json_response(['error'=>'autenticação/token não pode ser vazio'],400); return null;}
    $stmt=$pdo->prepare("SELECT u.level FROM sessions s JOIN users u ON u.id=s.user_id WHERE u.active>0 AND s.token_hash=? LIMIT 1");
    $stmt->execute([token_hash($token)]);
    $level=$stmt->fetchColumn();
    if($level===false){return 0;}
    return (int)$level;
}

/* --------------------------------------------------------------------
   ENDPOINTS
   -------------------------------------------------------------------- */

function api_register(PDO $pdo, array $config){
  if((($nivel = check_level()) ?? 0) < 5){ echo json_response(['error'=>"Não autorizado"],403); return; }
  $body = json_decode(file_get_contents('php://input'), true);
  $username = trim($body['username'] ?? '');
  $phone = trim($body['phone'] ?? '');
  $email = trim($body['email'] ?? '');
  $password = $body['password'] ?? '';
  if (!$username || !$phone || !$password){ echo json_response(['error'=>'username, telefone e password obrigatórios'],400); return; }
  if ($email && !filter_var($email, FILTER_VALIDATE_EMAIL)){ echo json_response(['error'=>'email inválido'],400); return; }
  if (strlen($password) < 8){ echo json_response(['error'=>'password deve ter ao menos 8 caracteres'],400); return; }
  $stmt = $pdo->prepare("SELECT id FROM users WHERE username=? LIMIT 1");
  $stmt->execute([$username]); if ($stmt->fetch()){ echo json_response(['error'=>'Usuário já cadastrado'],409); return; }
  $pwdHash = password_hash($password, PASSWORD_DEFAULT);
  $activation_token = rtrim(strtoupper(bin2hex(random_bytes(3))));
  $activation_hash  = strtoupper(hash_hmac('sha256', $activation_token, $config['APP_SECRET']));
  $stmt = $pdo->prepare("INSERT INTO users (username,email,phone,password_hash,active,created_at,activation_token_hash) VALUES (?,?,?,?,0,NOW(),?)");
  $stmt->execute([$username,$email,$phone,$pwdHash,$activation_hash]);
  $userId = (int)$pdo->lastInsertId();
  log_event($pdo,$userId,'usuario_cadastrado',['username'=>$username,'email'=>$email,'phone'=>$phone]);
  echo json_response(['success'=>true,'message'=>'Usuário cadastrado. Ative sua conta via "activate"','activation_token'=>$activation_token]);
}

function api_activate(PDO $pdo, array $config){
  $body = json_decode(file_get_contents('php://input'), true);
  $username = $body['username'] ?? $body['email'] ?? '';
  $token = strtoupper($body['activation_token']) ?? '';
  if (!$username || !$token){ echo json_response(['error'=>'username e activation_token são obrigatórios'],400); return; }
  $stmt = $pdo->prepare("SELECT id,activation_token_hash,active FROM users WHERE username=? OR email=? LIMIT 1");
  $stmt->execute([$username,$username]); $u = $stmt->fetch(PDO::FETCH_ASSOC);
  if (!$u){ echo json_response(['error'=>'Usuário não encontrado'],404); return; }
  if ($u['active']){ echo json_response(['message'=>'Conta já ativada']); return; }
  if (strtoupper(hash_hmac('sha256', $token, $config['APP_SECRET'])) !== $u['activation_token_hash']){ log_event($pdo,$u['id'],'activation_token_invalido',['username'=>$username]);echo json_response(['error'=>'Token de ativação inválido'],403); return; }
  $pdo->prepare("UPDATE users SET active=1, activated_at=NOW(), activation_token_hash=NULL WHERE id=?")->execute([$u['id']]);
  log_event($pdo,$u['id'],'usuario_ativado',['username'=>$username]);
  echo json_response(['success'=>true,'message'=>'Conta ativada com sucesso']);
}

function api_login(PDO $pdo, array $config){
  $body = json_decode(file_get_contents('php://input'), true);
  $username = $body['username'] ?? $body['email'] ?? '';
  $password = $body['password'] ?? '';
  if (!$username || !$password){ echo json_response(['error'=>'username e password obrigatórios'],400); return; }

  $stmt = $pdo->prepare("SELECT id,password_hash,active FROM users WHERE username=? OR email=? LIMIT 1");
  $stmt->execute([$username,$username]); $u = $stmt->fetch(PDO::FETCH_ASSOC);
  if (!$u){ log_event($pdo,null,'falha_login_usuario_desconhecido',['username'=>$username]); echo json_response(['error'=>'Credenciais inválidas'],401); return; }
  if (!password_verify($password,$u['password_hash'])){ log_event($pdo,(int)$u['id'],'falha_login_senha_incorreta',[]); echo json_response(['error'=>'Credenciais inválidas'],401); return; }
  if (!(int)$u['active']){ echo json_response(['error'=>'Conta desativada'],403); return; }

  $code = generate_otp(6);
  $payload = ['user_id'=>(int)$u['id'],'code'=>$code,'created_at'=>date('c'),'expires_at'=>date('c', time()+$config['OTP_TTL'])];
  $path = save_otp_file($payload);
  log_event($pdo,(int)$u['id'],'codigo_otp_gerado',['otp_file'=>basename($path),'ttl_seconds'=>$config['OTP_TTL']]);
  // Em produção: envie o código via WhatsApp; aqui retornamos para demonstração
  echo json_response(['success'=>true,'message'=>'Código 2FA; valide via "verify-otp"','code'=>$code]);
  log_event($pdo,(int)$u['id'],'codigo_otp_enviado',['otp_file'=>basename($path),'ttl_seconds'=>$config['OTP_TTL']]);
}

function api_verify_otp(PDO $pdo, array $config){
  $body = json_decode(file_get_contents('php://input'), true);
  $code = trim((string)($body['code'] ?? ''));
  $remember = !empty($body['remember_me']);
  if (!$code || !preg_match('/^\d{6}$/',$code)){ echo json_response(['error'=>'Código inválido (6 dígitos)'],400); return; }
  $found = find_otp_by_code($code);
  if (!$found){ log_event($pdo,null,'codigo_otp_invalido_ou_expirado',['IP'=>$_SERVER['REMOTE_ADDR'] ?? null,'USER_AGENT'=>$_SERVER['HTTP_USER_AGENT'] ?? null]); echo json_response(['error'=>'Código inválido ou expirado'],401); return; }
  [$path,$payload] = $found;
  if (strtotime($payload['expires_at']) < time()){ delete_otp_file($path); log_event($pdo,(int)$payload['user_id'],'codigo_otp_expirado_ao_verificar',[]); echo json_response(['error'=>'Código expirado'],401); return; }
  delete_otp_file($path);
  log_event($pdo,(int)$payload['user_id'],'codigo_otp_verificado',[]);
  $token = generate_session_token();
  $th = token_hash($token);
  $stmt = $pdo->prepare("INSERT INTO sessions (user_id,token_hash,created_at,last_activity,remember_me,ip,user_agent) VALUES (?,?,?,?,?,?,?)");
  $stmt->execute([(int)$payload['user_id'],$th,date('c'),date('c'),$remember,$_SERVER['REMOTE_ADDR'] ?? null, $_SERVER['HTTP_USER_AGENT'] ?? null]);
  $sessionId = (int)$pdo->lastInsertId();
  log_event($pdo,(int)$payload['user_id'],'sessão_criada',['session_id'=>$sessionId,'remember_me'=>$remember,'IP'=>$_SERVER['REMOTE_ADDR'] ?? null,'USER_AGENT'=>$_SERVER['HTTP_USER_AGENT'] ?? null]);
  if (php_sapi_name() !== 'cli' && headers_sent() === false){
    // cookie com SameSite=Lax; em produção adicionar 'secure' quando usar HTTPS
    //setcookie($config['COOKIE_NAME'],$token, ['expires'=> $remember ? time()+60*60*24*365*10 : 0, 'path'=>'/','domain'=>'','secure'=>true,'httponly'=>true,'samesite'=>'Lax']); // Desenvolvimento (HTTP / HTTPS)
    setcookie($config['COOKIE_NAME'],$token,['expires'=>$remember?time()+60*60*24*365*10:0,'path'=>'/','domain'=>$_SERVER['HTTP_HOST'],'secure'=>!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS']!=='off','httponly'=>true,'samesite'=>'Strict']); // Somente HTTPS (no mesmo dominio), SameSite=Lax/Strict
  }
  echo json_response(['success'=>true,'token'=>$token,'message'=>'Autenticado com sucesso']);
}

function api_logout(PDO $pdo, array $config){
  $token = get_bearer_token();
  if (!$token){ echo json_response(['error'=>'Token não informado'],400); return; }
  $th = token_hash($token);
  $stmt = $pdo->prepare("SELECT id,user_id FROM sessions WHERE token_hash=? LIMIT 1"); $stmt->execute([$th]); $s = $stmt->fetch(PDO::FETCH_ASSOC);
  if ($s){
    $pdo->prepare("DELETE FROM sessions WHERE id=?")->execute([$s['id']]);
    setcookie('AFABB-AUTH_SESSION', '', time() - 3600, '/', '', true, true); // limpa token do cookie
    log_event($pdo,(int)$s['user_id'],'logout_de_sessão',[]);
    echo json_response(['success'=>true,'message'=>'Logout realizado']);
  } else { echo json_response(['error'=>'Sessão não encontrada'],404); }
}

function api_me(PDO $pdo, array $config){
  $user = auth_by_token($pdo,$config);
  if (!$user){ echo json_response(['error'=>'Não autenticado'],401); return; }
  //echo json_response($user); exit;
  echo json_response([
    'id' => $user['user_id'],
    'username' => $user['username'],
    'email' => $user['email'],
    'phone' => $user['phone'],
    'level' => $user['level']
  ]);
}















/* --------------------------------------------------------------------
   FRONTEND (dark-mode) - função que retorna HTML completo.
   CSS e JS: modularizados. Inclui tela de login e painel
   -------------------------------------------------------------------- */

$CSS = <<<'CSS'
<style>
:root{--bg:#0F1720;--card:#111827;--text:#E6EEF3;--muted:#9AA6B2;--accent:#0033A0} *{box-sizing:border-box;}
body{margin:0;padding:20px;font-family:Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial;background:var(--bg);color:var(--text);display:flex;flex-direction:column;align-items:center;gap:20px;min-height:100vh;overflow:auto;}
.card{background:var(--card);border-radius:12px;padding:22px;box-shadow:0 6px 24px #02061799;width:480px; max-width:100%;}
.h{font-size:28px;margin:0 0 12px 0}
.small{font-size:13px;color:var(--muted);margin-bottom:12px}
.input:focus{outline:none;border-color:#2563EB;box-shadow:0 0 0 2px #2563EB33;}
.input{font-size:25px; width:100%;padding:10px;border-radius:8px;border:1px solid #0A0A0A;background:#081018;color:var(--text);margin-bottom:10px;box-sizing:border-box;}
.btn{width:100%;padding:16px 10px;border-radius:10px;border:0;background:var(--accent);color:white;cursor:pointer}
.row{display:flex;gap:10px}
.col{flex:1}
.link{color:var(--accent);cursor:pointer;text-decoration:underline}
.footer{font-size:12px;color:var(--muted);margin-top:10px}
.debug{font-size:12px;color:var(--muted);margin-top:8px;word-break:break-all}
.badge{display:inline-block;padding:4px 8px;border-radius:8px;background:#0B1220;color:var(--muted);font-size:12px;margin-left:8px}
.spinLoad{display:inline-block;width:20px;height:20px;border:3px solid #FFEA0033;border-top:#FFEA00 3px solid;border-radius:50%;animation:sp 0.25s linear infinite;margin:auto;margin: 0px 5px -5px 0px;} @keyframes sp{to{transform:rotate(360deg)}}
</style>
CSS;

$JS = <<<'JS_COMMON'
/* calcula API_BASE corretamente independentemente de subpasta */
(function(){
  const pathname = location.pathname || '/';
  const idx = pathname.toLowerCase().indexOf('/api');
  let prefix = '';
  if (idx >= 0) prefix = pathname.slice(0, idx);
  else prefix = pathname.replace(/\/index\.php$/i,'').replace(/\/$/,'');
  if (prefix === '/') prefix = '';
  window.API_BASE = location.origin + prefix + '/api';
})();

function show(msg, ok = true){ const el=document.getElementById('messages'); el.style.color=ok?'#9EE7A7':'#F7A7A7'; el.innerHTML=msg; updateTokenBadge(); }

/* wrapper fetch robusto */
async function callApi(path, opts = {}){
  const url = window.API_BASE + path;
  const defaultHeaders = {'Accept':'application/json','Content-Type':'application/json'};
  opts.headers = Object.assign({}, defaultHeaders, opts.headers || {});
  try {
    const res = await fetch(url, opts);
    const text = await res.text();
    let data;
    try { data = text ? JSON.parse(text) : {}; } catch (e){ data = {error: text || 'Resposta inválida do servidor'}; }
    return {ok: res.ok, status: res.status, data};
  } catch (err){
    return {ok:false,status:0,data:{error: err.message || 'Falha de rede'}};
  }
}


/* utilities token: tenta ler localStorage e cookie */
function setTokenClient(token, remember = false){
  try { localStorage.setItem('auth', token); } catch(e){}
  // cookie fallback (mesmo host) - SameSite=Lax; em produção adicione secure quando usar HTTPS
  const maxAge = remember ? 60*60*24*365*10 : 0;
  document.cookie = 'AFABB-AUTH_SESSION=' + encodeURIComponent(token) + (maxAge ? '; Max-Age=' + maxAge : '') + '; Path=/; SameSite=Lax';
  updateTokenBadge();
}
function clearTokenClient(){
  try { localStorage.removeItem('auth'); } catch(e){}
  // apagar cookie
  document.cookie = 'AFABB-AUTH_SESSION=; Max-Age=0; Path=/; SameSite=Lax';
  updateTokenBadge();
}
function getTokenClient(){
  try {
    const t = localStorage.getItem('auth');
    if (t) return t;
  } catch(e){}
  // cookie fallback
  const m = document.cookie.match(/(?:^|; )AFABB-AUTH_SESSION=([^;]+)/);
  if (m) return decodeURIComponent(m[1]);
  return null;
}
function scrollToTopSmooth(duration = 1000){
  //window.scrollTo({ top: 0, behavior: 'smooth' });
  const start = window.scrollY;
  const startTime = performance.now();
  function animate(currentTime) {
    const elapsed = currentTime - startTime;
    const progress = Math.min(elapsed / duration, 1);
    const ease = 1 - Math.pow(1 - progress, 3); // easing cubic out
    window.scrollTo(0, start * (1 - ease));
    if (progress < 1) requestAnimationFrame(animate);
  }
  requestAnimationFrame(animate);
}


/* inicializa badge */
function updateTokenBadge(){ 
  const badge=document.getElementById('tokenBadge'); if(!badge){ return;} 
  const t=getTokenClient()||'';
  document.querySelector('.debug').innerHTML=`Token salvo:<span id="tokenBadge" class="badge">${t}</span>`;
} updateTokenBadge();
JS_COMMON;



$HTML_LOGGIM = <<<HTML
<!doctype html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sistema API - Autenticação 2FA</title>
$CSS
</head>
<body>

<div class="card" role="main">
  <h3 class="h">Autenticação 2FA</h3>
  <div class="small">Use os formulários abaixo para logar e validar o código 2FA.</div>
  <div id="messages" class="small" aria-live="polite"></div>
</div>

<div class="card" id="login">
  <h3 class="h">Login</h3>
  <input id="l_username" class="input" placeholder="username" autocomplete="username">
  <input id="l_password" type="password" class="input" placeholder="senha" autocomplete="current-password">
  <div class="row"><div class="col"><label style="cursor:pointer;"><input id="remember" type="checkbox"> lembrar-me <BR>
    <SUP style="color:#9A8A00;">*Use somente em maquinas não compartilhadas.</SUP>
  </label></div></div>
  <BR>
  <button class="btn" onclick="login()">Login (gera 2FA)</button>
</div>

<div class="card" id="verify">
  <h3 class="h">Validar 2FA</h3>
  <input id="otp_code" class="input" placeholder="Código 6 dígitos" inputmode="numeric" pattern="\\d{6}">
  <button class="btn" onclick="verify()">Validar 2FA</button>
  <div class="footer"><STRONG style="font-size:1.2em;">Observação:</STRONG> Em produção o código 2FA deve ser enviado por canal seguro (WhatsApp/SMS/e-mail). Aqui ele é retornado na API apenas para demonstração.</div>
</div>
</body>
<script>
/* ações */
async function login(){
  const username = document.getElementById('l_username').value.trim();
  const password = document.getElementById('l_password').value;
  if (!username || !password){ show('username e password obrigatórios', false); return; }
  const res = await callApi('/login', {method:'POST', body: JSON.stringify({username, password})});
  if (res.ok) show('Código 2FA: ' + (res.data.code || '(não retornado)')); else show(res.data.error || JSON.stringify(res.data), false);
}

async function verify(){
  const code = (document.getElementById('otp_code').value || '').trim();
  const remember = document.getElementById('remember').checked;
  if (!/^\d{6}$/.test(code)){ show('Código inválido (6 dígitos)', false); return; }
  const res = await callApi('/verify-otp', {method:'POST', body: JSON.stringify({code, remember_me: remember})});
  if (res.ok){
    if (!res.data.token){ show('Erro: token não retornado pela API', false); return; }
    setTokenClient(res.data.token, remember);
    show('<SPAN class="spinLoad"></SPAN> Login completo!');
    setTimeout(() => location.reload(), 1000);
  } else {
    show(res.data.error || JSON.stringify(res.data), false);
  }
}
/* atalhos por Enter */
document.addEventListener('keydown', function(e){
  if (e.key === 'Enter'){
    const active = document.activeElement;
    if (!active) return;
    if ((active.id === 'l_username' || active.id === 'l_password') && document.getElementById('l_username').value.trim() && document.getElementById('l_password').value) login();
    if (active.id === 'otp_code' && document.getElementById('otp_code').value.trim()) verify();
  }
});

$JS
</script>

</body>
</html>
HTML;

function frontend_login(): string {
  global $HTML_LOGGIM;
  return $HTML_LOGGIM;
}





$HTML_PAINEL = <<<HTML
<!doctype html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sistema API - Autenticação 2FA</title>
$CSS
</head>
<body>

<div class="card" role="main">
  <h3 class="h">Sistema 2FA (aut)</h3>
  <div class="small">Use os formulários abaixo para criar usuário e ativar contas.</div>
  <div id="messages" class="small" aria-live="polite"></div>
  <div class="debug">Token salvo:<span id="tokenBadge" class="badge">—</span></div>
</div>

<div class="card" id="register">
  <h3 class="h">Registrar <span style="white-space:nowrap;">(Novo Usuário)</span></h3>
  <input id="r_username" class="input" placeholder="username" autocomplete="username">
  <input id="r_email" class="input" placeholder="email (opcional)" autocomplete="email">
  <input id="r_phone" class="input" placeholder="WhatsApp" autocomplete="tel">
  <input id="r_password" type="password" class="input" placeholder="senha" autocomplete="off">
  <button class="btn" onclick="register()">Registrar e Receber Token de Ativação</button>
</div>

<div class="card" id="activate">
  <h3 class="h">Ativar Conta</h3>
  <input id="a_username" class="input" placeholder="username">
  <input id="a_token" class="input" placeholder="token (recebido)">
  <button class="btn" onclick="activate()">Ativar Conta</button>
</div>

<div class="card" id="session_ops">
  <h3 class="h">Sessão</h3>
  <button class="btn" onclick="me()">Me (dados)</button>
  <button class="btn" style="margin-top:6px;background:#EF4444" onclick="logout()">Logout</button>
  <BR><BR>
  <div class="footer"><STRONG style="font-size:1.2em;">Observação:</STRONG> Em produção o código 2FA deve ser enviado por canal seguro (WhatsApp/SMS/e-mail). Aqui ele é retornado na API apenas para demonstração.</div>
</div>
</body>


<script>
/* ações */
async function register(){
  scrollToTopSmooth();
  const username = document.getElementById('r_username').value.trim();
  const email = document.getElementById('r_email').value.trim();
  const phone = document.getElementById('r_phone').value.trim();
  const password = document.getElementById('r_password').value;
  if (!username || !phone || !password){ show('username, whatsapp e password obrigatórios', false); return; }
  const res = await callApi('/register', {method:'POST', body: JSON.stringify({username,email,phone,password})});
  if (res.ok) show('Registrado. Token de Ativação: ' + (res.data.activation_token || '')); else show(res.data.error || JSON.stringify(res.data), false);
}

async function activate(){
  scrollToTopSmooth();
  const username = document.getElementById('a_username').value.trim();
  const token = document.getElementById('a_token').value.trim();
  if (!username || !token){ show('username e token de activação são obrigatórios', false); return; }
  const res = await callApi('/activate', {method:'POST', body: JSON.stringify({username, activation_token: token})});
  if (res.ok) show(res.data.message || 'Conta ativada'); else show(res.data.error || JSON.stringify(res.data), false);
}

async function me(){
  scrollToTopSmooth();
  const token = getTokenClient();
  if (!token){ show('Sem token salvo.', false); setTimeout(() => location.reload(), 1000); return; }
  const res = await callApi('/me', {method:'GET', headers: {'Authorization': 'Bearer ' + token}});
  if (res.ok){ 
    show('Usuário: ' + (res.data.username || '') + ' / email: ' + (res.data.email || '') + ' / telefone: ' + (res.data.phone || '')); 
    // console.log(res.data);
  }else {
    if (res.status === 401){ 
      clearTokenClient(); 
      show('Não autenticado. Token inválido ou expirado.', false); 
    } else show(res.data.error || JSON.stringify(res.data), false);
  }
}

async function logout(){
  scrollToTopSmooth();
  const token = getTokenClient();
  if (!token){ show('Sem token salvo.', false); setTimeout(() => location.reload(), 1000); return; }
  const res = await callApi('/logout?token=' + encodeURIComponent(token), {method:'GET'});
  if (res.ok){ clearTokenClient(); show('<SPAN class="spinLoad"></SPAN> Realizando Logout...'); document.querySelector('.debug').innerHTML=``; setTimeout(() => location.reload(), 3000); } else show(res.data.error || JSON.stringify(res.data), false);
}

/* atalhos por Enter */
document.addEventListener('keydown', function(e){
  if (e.key === 'Enter'){
    const active = document.activeElement;
    if (!active) return;
    if ((active.id === 'r_username' || active.id === 'r_password') && document.getElementById('r_username').value.trim() && document.getElementById('r_password').value) register();
  }
});

$JS
</script>
</body>
</html>
HTML;

function frontend_painel(): string {
  global $HTML_PAINEL;
  return $HTML_PAINEL;
}

function FRONTEND(){
  $user = rma(); // retorna array do usuário (se logado)
  //echo $user ? 'Usuário logado: '.$user['username'].' / tel: '.$user['phone'] : 'NAO LOGADO';
  if($user){
    echo frontend_painel(); exit();
  }else{
    echo frontend_login(); exit();
  }

}

/* --------------------------------------------------------------------
   FIM DO FRONTEND
   -------------------------------------------------------------------- */















/* --------------------------------------------------------------------
   MySQL: PDO, esquema, admin, GC
   -------------------------------------------------------------------- */
$pdo = db_connect();
ensure_schema($pdo);
create_default_admin($pdo);
gc_otps($config);

/* --------------------------------------------------------------------
   ROTEAMENTO
   -------------------------------------------------------------------- */
$routes = [
  'register' => ['POST'],
  'activate' => ['POST'],
  'login' => ['POST'],
  'verify-otp' => ['POST'],
  'logout' => ['GET'],
  'me' => ['GET'],
  '' => ['GET'],
];
$method = $_SERVER['REQUEST_METHOD'];
$requestPath = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH) ?: '/';
$apiPos = stripos($requestPath, '/api');
if ($apiPos === false){
  $scriptDirNormalized = rtrim(str_replace('\\','/', dirname($_SERVER['SCRIPT_NAME'])), '/');
  if ($scriptDirNormalized !== '' && stripos($requestPath, $scriptDirNormalized) === 0){
    $local = substr($requestPath, strlen($scriptDirNormalized));
    $endpoint = ltrim($local, '/');
  } else {
    $endpoint = ltrim($requestPath, '/');
  }
} else {
  $endpoint = ltrim(substr($requestPath, $apiPos + 4), '/');
}
$endpoint = $endpoint === '' ? '' : rtrim($endpoint, '/');


/* examina raiz do endpoint */
$parts = explode('/', $endpoint);
$rootEndpoint = $parts[0];
if (!array_key_exists($rootEndpoint, $routes)){ http_response_code(404); echo json_response(['error'=>'Não permitido'],404); exit; }
$allowed = $routes[$rootEndpoint];
if (!in_array($method, $allowed, true)){ header('Allow: ' . implode(', ', $allowed)); http_response_code(405); echo json_response(['error'=>'Método não permitido para este endpoint','allowed'=>$allowed],405); exit; }


//* dispara handlers
switch ("$method $rootEndpoint"){
  case 'POST register': api_register($pdo,$config); break;
  case 'POST activate': api_activate($pdo,$config); break;
  case 'POST login': api_login($pdo,$config); break;
  case 'POST verify-otp': api_verify_otp($pdo,$config); break;
  case 'GET logout': api_logout($pdo,$config); break;
  case 'GET me': api_me($pdo,$config); break;
  case 'GET ':
        if(!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'){ 
              if(!$config['FRONT_END']){  http_response_code(403);echo json_response(['error'=>'Recurso desabilitado.'],403); 
              }elseif($config['FRONT_END'] === 'silent'){ // Use este opção para include (permite importar todas as funções) de forma silenciosa
              }else{ FRONTEND(); 
              }
        }else{
              http_response_code(403); echo json_response(['error'=>'Acesso somente via HTTPS'],403);
        }break;
  default: http_response_code(500); echo json_response(['error'=>'Erro no roteamento']); break;
}

/* -------------------------------------------------------------------- */




