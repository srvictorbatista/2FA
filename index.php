<?php
/**
 * Sistema de Autenticação API (2FA)
 * --------------------------------------------------------------------------------------------------------------------------------------------------
 * Recursos principais:
 * - Criação automática de .htaccess (raiz) e .htaccess na pasta OTP (nega acesso).
 * - CORS / preflight OPTIONS tratado.
 * - Criação de DB/tabelas e usuário administrador (admin / admin123) na 1ª execução.
 * - Registro de eventos (logs).
 * - Login com 2FA via arquivo cifrado (AES-256-GCM) em pasta protegida.
 * - Sessões por token (Bearer) com timeout por inatividade; opção lembrar-me.
 * - Front-end dark-mode, salva token em localStorage + cookie e exibe debug do token.
 *
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
 * - Endpoints principais:
 *    - POST /register       : cadastro de usuários (exige nível de acesso quando aplicável)
 *    - POST /activate       : ativação de conta via token
 *    - POST /login          : login com senha
 *    - POST /verify-otp     : verificação 2FA + geração de token Bearer
 *    - GET /logout          : logout da sessão atual
 *    - GET /me              : informações do usuário logado
 *    - GET /users           : listar usuários (mínimo nível 5; nível 999 lista usuários inativos e excluídos) 
 *    - POST /change-password: alterar própria senha (exige senha atual)
 *    - POST /user-update    : administrar/editar usuário (regras diferentes para admin e próprio usuário; exclusão via action: delete)
 * - Front-end mínimo em dark-mode (HTML+JS) que consome a API via fetch.
 * - Controle de níveis de acesso (1-10) e restrições específicas por endpoint.
 * - Campos opcionais permanecem inalterados; campos obrigatórios validados conforme contexto.
 * - Exclusão suave de usuários: nível 0 + ativo 0, mantendo integridade histórica.
 * - Registro de logs detalhados mesmo em casos de insucesso ou tentativas de acesso não autorizado.
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
 * 7) Listar usuários (apenas administradores):
 *    GET /users
 *    curl -k -X GET <url>/users -H "Authorization: Bearer <token>" -H "Accept: application/json"
 *    # Retorna JSON: { "success":true, "users":[ { "id":1, "username":"joao", "email":"j@d.com", "phone":"5591999999999", "active":1, "level":5, "created_at":"2025-01-01 12:00:00", "activated_at":"2025-01-01 12:05:00" }, ... ] }
 *    # Nível mínimo: 5; nível 999 inclui usuários com level=0 e active=0
 *
 * 8) Alterar própria senha:
 *    POST /change-password  { "current_password":"SenhaAtual123","new_password":"NovaSenha123!","new_password_confirm":"NovaSenha123!" }
 *    curl -k -X POST <url>/change-password -H "Authorization: Bearer <token>" -H "Content-Type: application/json" -d "{\"current_password\":\"SenhaAtual123\",\"new_password\":\"NovaSenha123!\",\"new_password_confirm\":\"NovaSenha123!\"}"
 *    # Usuário deve enviar senha atual e nova senha com confirmação
 *
 * 9) Administrar/editar usuário:
 *    POST /user-update
 *    curl -k -X POST <url>/user-update -H "Authorization: Bearer <token>" -H "Content-Type: application/json" -d "{\"target_username\":\"usuario1\",\"username\":\"novo_nome\",\"email\":\"novo@local.com\",\"phone\":\"5591988887777\",\"new_password\":\"NovaSenha123!\",\"new_password_confirm\":\"NovaSenha123!\",\"level\":3,\"active\":1,\"authorization\":\"SENHA_DO_ADMIN\"}"
 *    # Regras:
 *    # - Para editar outro usuário: enviar target_username + authorization (senha do admin). Requer nível de acesso
 *    # - Para editar a si mesmo (usuário comum): enviar current_password. Não pode alterar seu próprio level
 *    # - Para admin editar a si mesmo: enviar authorization (senha do admin)
 *    # - Se new_password/new_password_confirm não enviados, a senha permanece
 *    # - Campos omitidos permanecem inalterados
 *    # - Para excluir um usuário: enviar { "target_username":"usuario1", "action":"delete", "authorization":"SENHA_DO_ADMIN" }
 *
 * Endpoints protegidos (exige token Bearer):
 * - GET /users
 * - POST /change-password
 * - POST /user-update
 *
 *
 *
 * Observações: 
 * Ajuste as variáveis de configuração para produção (APP_SECRET, DB_*).
 * Considerer sempre o envio de tokens e codigos por canais seguors em produção (WhatsApp, SMS, email). 
 * Registro de logs, sempre ativo a acda evento.
 * Mensagens de erro retornam JSON.
 * --------------------------------------------------------------------------------------------------------------------------------------------------
 */


declare(strict_types=1);
date_default_timezone_set('America/Belem');
ini_set('display_errors', 1); error_reporting(E_ALL); // força exibição de erros


/* --------------------------------------------------------------------
   CONFIGURAÇÃO (editar antes de uso)
   -------------------------------------------------------------------- */
$config = [
  'DB_HOST' => 'SEU_SERVIDOR_MYSQL',
  'DB_NAME' => '_NOME_DO_BANCO_PRETENDIDO', // Não precisa estar criado
  'DB_USER' => 'SEU_USUARIO',
  'DB_PASS' => 'SUA_SENHA_SEGURA',
  'APP_SECRET' => '2D5D2BC708292FSDDFHDHT34LGGFG5670D3053108DE25D9YEG435BB908FIS6CC43_Dev!',
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
if(!file_exists($rootHt)){ @file_put_contents($rootHt, $rootHtContent); @chmod($rootHt, 0644); }

if(!is_dir($config['OTP_DIR'])) @mkdir($config['OTP_DIR'], 0700, true);
$otp_ht = rtrim($config['OTP_DIR'],'/') . '/.htaccess';
$otpHtContent = <<<OTP
<IfModule mod_authz_core.c>
  Require all denied
</IfModule>
<IfModule !mod_authz_core.c>
  Deny from all
</IfModule>
OTP;
if(!file_exists($otp_ht)){ @file_put_contents($otp_ht, $otpHtContent); @chmod($otp_ht, 0600); }

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
  if($ciphertext === false) throw new RuntimeException('Erro na cifragem');
  return base64_encode($iv . $tag . $ciphertext);
}
function decrypt_payload(string $blob): array {
  global $config;
  $data = base64_decode($blob, true);
  if($data === false) throw new RuntimeException('Blob inválido');
  $cipher = $config['CIPHER'];
  $ivlen = openssl_cipher_iv_length($cipher);
  $taglen = 16;
  $iv = substr($data,0,$ivlen);
  $tag = substr($data,$ivlen,$taglen);
  $ciphertext = substr($data,$ivlen+$taglen);
  $key = hash('sha256',$config['APP_SECRET'],true);
  $plaintext = openssl_decrypt($ciphertext,$cipher,$key,OPENSSL_RAW_DATA,$iv,$tag);
  if($plaintext === false) throw new RuntimeException('Decifragem falhou');
  $arr = json_decode($plaintext,true);
  if(!is_array($arr)) throw new RuntimeException('JSON inválido no payload decifrado');
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
    if($file->isFile() && $file->getExtension() === 'otp'){
      $path = $file->getPathname();
      try {
        $blob = file_get_contents($path);
        $pl = decrypt_payload($blob);
        if(isset($pl['code']) && $pl['code'] === $code) return [$path,$pl];
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
    if($file->isFile() && $file->getExtension()==='otp'){
      $path = $file->getPathname();
      try {
        $blob = file_get_contents($path);
        $pl = decrypt_payload($blob);
        $created = isset($pl['created_at']) ? strtotime($pl['created_at']) : filemtime($path);
        if(($now - $created) > $ttl){ @unlink($path); }
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
  if($hdr && preg_match('/Bearer\s+(.+)$/i',$hdr,$m)) return $m[1];
  if(!empty($_GET['token'])) return $_GET['token'];
  return null;
}
function auth_by_token(PDO $pdo, array $config): ?array {
  $token = get_bearer_token(); if(!$token) return null;
  $th = token_hash($token); error_log("auth_by_token: token=$token th=$th");
  $stmt = $pdo->prepare("SELECT s.*, u.id as user_id, u.username, u.email, u.phone, u.level FROM sessions s JOIN users u ON u.id=s.user_id WHERE u.active>0 AND s.token_hash=? LIMIT 1");
  $stmt->execute([$th]); $row = $stmt->fetch(PDO::FETCH_ASSOC);
  if(!$row) return null;
  $idle = $config['SESSION_IDLE_TIMEOUT'];
  $last_activity = strtotime($row['last_activity']);
  if(!$row['remember_me'] && (time() - $last_activity) > $idle){
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
  if(!$token) return null;
  $th = token_hash($token);
  //$stmt = $pdo->prepare("SELECT s.*, u.id AS user_id, u.username, u.email, u.phone FROM sessions s JOIN users u ON u.id=s.user_id WHERE u.active>0 AND s.token_hash=? LIMIT 1");
  $stmt = $pdo->prepare("SELECT s.*, u.id as user_id, u.username, u.email, u.phone, u.level FROM sessions s JOIN users u ON u.id=s.user_id WHERE u.active>0 AND s.token_hash=? LIMIT 1");
  $stmt->execute([$th]); $row = $stmt->fetch(PDO::FETCH_ASSOC);
  if(!$row) return null;
  $idle = $config['SESSION_IDLE_TIMEOUT'];
  if(!$row['remember_me'] && (time() - strtotime($row['last_activity'])) > $idle){ $pdo->prepare("DELETE FROM sessions WHERE id=?")->execute([$row['id']]); log_event($pdo,(int)$row['user_id'],'sessão_expirada_por_inatividade',['session_id'=>$row['id']]); return null; }
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
  if(!$username || !$phone || !$password){ echo json_response(['error'=>'username, telefone e password obrigatórios'],400); return; }
  if($email && !filter_var($email, FILTER_VALIDATE_EMAIL)){ echo json_response(['error'=>'email inválido'],400); return; }
  if(strlen($password) < 8){ echo json_response(['error'=>'password deve ter ao menos 8 caracteres'],400); return; }
  $stmt = $pdo->prepare("SELECT id FROM users WHERE username=? LIMIT 1");
  $stmt->execute([$username]); if($stmt->fetch()){ echo json_response(['error'=>'Usuário já cadastrado'],409); return; }
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
  if(!$username || !$token){ echo json_response(['error'=>'username e activation_token são obrigatórios'],400); return; }
  $stmt = $pdo->prepare("SELECT id,activation_token_hash,active FROM users WHERE username=? OR email=? LIMIT 1");
  $stmt->execute([$username,$username]); $u = $stmt->fetch(PDO::FETCH_ASSOC);
  if(!$u){ echo json_response(['error'=>'Usuário não encontrado'],404); return; }
  if($u['active']){ echo json_response(['message'=>'Conta já ativada']); return; }
  if(strtoupper(hash_hmac('sha256', $token, $config['APP_SECRET'])) !== $u['activation_token_hash']){ log_event($pdo,$u['id'],'activation_token_invalido',['username'=>$username]);echo json_response(['error'=>'Token de ativação inválido'],403); return; }
  $pdo->prepare("UPDATE users SET active=1, activated_at=NOW(), activation_token_hash=NULL WHERE id=?")->execute([$u['id']]);
  log_event($pdo,$u['id'],'usuario_ativado',['username'=>$username]);
  echo json_response(['success'=>true,'message'=>'Conta ativada com sucesso']);
}

function api_login(PDO $pdo, array $config){
  $body = json_decode(file_get_contents('php://input'), true);
  $username = $body['username'] ?? $body['email'] ?? '';
  $password = $body['password'] ?? '';
  if(!$username || !$password){ echo json_response(['error'=>'username e password obrigatórios'],400); return; }

  $stmt = $pdo->prepare("SELECT id,password_hash,active FROM users WHERE username=? OR email=? LIMIT 1");
  $stmt->execute([$username,$username]); $u = $stmt->fetch(PDO::FETCH_ASSOC);
  if(!$u){ log_event($pdo,null,'falha_login_usuario_desconhecido',['username'=>$username]); echo json_response(['error'=>'Credenciais inválidas'],401); return; }
  if(!password_verify($password,$u['password_hash'])){ log_event($pdo,(int)$u['id'],'falha_login_senha_incorreta',[]); echo json_response(['error'=>'Credenciais inválidas'],401); return; }
  if(!(int)$u['active']){ echo json_response(['error'=>'Conta desativada'],403); return; }

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
  if(!$code || !preg_match('/^\d{6}$/',$code)){ echo json_response(['error'=>'Código inválido (6 dígitos)'],400); return; }
  $found = find_otp_by_code($code);
  if(!$found){ log_event($pdo,null,'codigo_otp_invalido_ou_expirado',['IP'=>$_SERVER['REMOTE_ADDR'] ?? null,'USER_AGENT'=>$_SERVER['HTTP_USER_AGENT'] ?? null]); echo json_response(['error'=>'Código inválido ou expirado'],401); return; }
  [$path,$payload] = $found;
  if(strtotime($payload['expires_at']) < time()){ delete_otp_file($path); log_event($pdo,(int)$payload['user_id'],'codigo_otp_expirado_ao_verificar',[]); echo json_response(['error'=>'Código expirado'],401); return; }
  delete_otp_file($path);
  log_event($pdo,(int)$payload['user_id'],'codigo_otp_verificado',[]);
  $token = generate_session_token();
  $th = token_hash($token);
  $stmt = $pdo->prepare("INSERT INTO sessions (user_id,token_hash,created_at,last_activity,remember_me,ip,user_agent) VALUES (?,?,?,?,?,?,?)");
  $stmt->execute([(int)$payload['user_id'],$th,date('c'),date('c'),$remember,$_SERVER['REMOTE_ADDR'] ?? null, $_SERVER['HTTP_USER_AGENT'] ?? null]);
  $sessionId = (int)$pdo->lastInsertId();
  log_event($pdo,(int)$payload['user_id'],'sessão_criada',['session_id'=>$sessionId,'remember_me'=>$remember,'IP'=>$_SERVER['REMOTE_ADDR'] ?? null,'USER_AGENT'=>$_SERVER['HTTP_USER_AGENT'] ?? null]);
  if(php_sapi_name() !== 'cli' && headers_sent() === false){
    // cookie com SameSite=Lax; em produção adicionar 'secure' quando usar HTTPS
    //setcookie($config['COOKIE_NAME'],$token, ['expires'=> $remember ? time()+60*60*24*365*10 : 0, 'path'=>'/','domain'=>'','secure'=>true,'httponly'=>true,'samesite'=>'Lax']); // Desenvolvimento (HTTP / HTTPS)
    setcookie($config['COOKIE_NAME'],$token,['expires'=>$remember?time()+60*60*24*365*10:0,'path'=>'/','domain'=>$_SERVER['HTTP_HOST'],'secure'=>!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS']!=='off','httponly'=>true,'samesite'=>'Strict']); // Somente HTTPS (no mesmo dominio), SameSite=Lax/Strict
  }
  echo json_response(['success'=>true,'token'=>$token,'message'=>'Autenticado com sucesso']);
}



// Listar usuários
function api_list_users(PDO $pdo, array $config){
  if((($nivel = check_level()) ?? 0) < 5){ echo json_response(['error'=>"Não autorizado"],403); return; }
  $actor = rma(); $actorId = $actor['user_id'] ?? null;
  try {
    if($nivel === 999){
      $stmt = $pdo->query("SELECT id,username,email,phone,active,level,created_at,activated_at FROM users ORDER BY username");
      $users = $stmt->fetchAll(PDO::FETCH_ASSOC);
    } else {
      $stmt = $pdo->prepare("SELECT id,username,email,phone,active,level,created_at,activated_at FROM users WHERE NOT (level=0 AND active=0) AND NOT (level >=999) ORDER BY username");
      $stmt->execute();
      $users = $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
    //log_event($pdo,$actorId,'listar_usuarios',['count'=>count($users),'include_zero_zero'=>$nivel===999]); // comentado para evitar excessos
    echo json_response(['success'=>true,'users'=>$users]);
  } catch (Throwable $e){
    log_event($pdo,$actorId,'erro_listar_usuarios',['msg'=>$e->getMessage()]);
    echo json_response(['error'=>'Erro ao listar usuários'],500);
  }
}

// Troca senha (apenas próprio usuário)
function api_change_password(PDO $pdo, array $config){
  if((($nivel = check_level()) ?? 0) < 1){ echo json_response(['error'=>"Não autorizado"],403); return; }
  $actor = rma(); if(!$actor){ echo json_response(['error'=>'Não autenticado'],401); return; }
  $userId = (int)$actor['user_id'];
  $body = json_decode(file_get_contents('php://input'), true);
  $current = $body['current_password'] ?? '';
  $new = $body['new_password'] ?? '';
  $confirm = $body['new_password_confirm'] ?? '';
  if(!$current || !$new || !$confirm){ log_event($pdo,$userId,'falha_troca_senha_campos_incompletos',[]); echo json_response(['error'=>'current_password, new_password e confirmação obrigatórios'],400); return; }
  if($new !== $confirm){ log_event($pdo,$userId,'falha_troca_senha_confirmacao',[]); echo json_response(['error'=>'Nova senha e confirmação não conferem'],400); return; }
  if(strlen($new) < 8){ log_event($pdo,$userId,'falha_troca_senha_curta',[]); echo json_response(['error'=>'Senha deve ter ao menos 8 caracteres'],400); return; }
  $stmt = $pdo->prepare("SELECT password_hash FROM users WHERE id=? LIMIT 1"); $stmt->execute([$userId]); $hash = $stmt->fetchColumn();
  if(!$hash || !password_verify($current,$hash)){ log_event($pdo,$userId,'falha_troca_senha_senha_atual_invalida',[]); echo json_response(['error'=>'Senha atual inválida'],403); return; }
  $newHash = password_hash($new, PASSWORD_DEFAULT);
  $pdo->prepare("UPDATE users SET password_hash=? WHERE id=?")->execute([$newHash,$userId]);
  log_event($pdo,$userId,'senha_alterada_com_sucesso',[]);
  echo json_response(['success'=>true,'message'=>'Senha alterada']);
}

//-- ----------------------------------------------------------------
// Editar usuário / administrar usuários
//-- ----------------------------------------------------------------
function api_update_user(PDO $pdo, array $config){
  if((($nivel = check_level()) ?? 0) < 1){ echo json_response(['error'=>"Não autorizado"],403); return; }
  $actor = rma(); if(!$actor){ echo json_response(['error'=>'Não autenticado'],401); return; }
  $actorId = (int)$actor['user_id']; $actorLevel = (int)$actor['level'];
  $body = json_decode(file_get_contents('php://input'), true);
  $targetUsername = trim($body['target_username'] ?? $actor['username']);
  if(!$targetUsername){ log_event($pdo,$actorId,'falha_editar_usuario_sem_alvo',[]); echo json_response(['error'=>'target_username obrigatório'],400); return; }

  // busca usuário alvo
  $stmt = $pdo->prepare("SELECT id,username,email,phone,active,level,password_hash FROM users WHERE username=? LIMIT 1");
  $stmt->execute([$targetUsername]); $target = $stmt->fetch(PDO::FETCH_ASSOC);
  if(!$target){ log_event($pdo,$actorId,'falha_editar_usuario_nao_encontrado',['target'=>$targetUsername]); echo json_response(['error'=>'Usuário alvo não encontrado'],404); return; }
  $targetId = (int)$target['id'];
  $isSelf = $actorId === $targetId;

  // autorização
  if($isSelf){
    if($actorLevel >= 5){
      if(empty($body['authorization'])){ log_event($pdo,$actorId,'falha_autorizacao_admin_ao_editar_proprio',['target'=>$targetUsername]); echo json_response(['error'=>'Autorização obrigatória'],403); return; }
      $auth = $body['authorization'];
      $stmt = $pdo->prepare("SELECT password_hash FROM users WHERE id=? LIMIT 1"); $stmt->execute([$actorId]); $hash = $stmt->fetchColumn();
      if(!$hash || !password_verify($auth,$hash)){ log_event($pdo,$actorId,'falha_autorizacao_admin_invalida',['target'=>$targetUsername]); echo json_response(['error'=>'Autorização inválida'],403); return; }
    } else {
      if(empty($body['current_password'])){ log_event($pdo,$actorId,'falha_confirmacao_propria_senha_faltando',['target'=>$targetUsername]); echo json_response(['error'=>'Senha atual obrigatória'],403); return; }
      $cur = $body['current_password'];
      $stmt = $pdo->prepare("SELECT password_hash FROM users WHERE id=? LIMIT 1"); $stmt->execute([$actorId]); $hash = $stmt->fetchColumn();
      if(!$hash || !password_verify($cur,$hash)){ log_event($pdo,$actorId,'falha_confirmacao_senha_atual_invalida',['target'=>$targetUsername]); echo json_response(['error'=>'Senha atual inválida'],403); return; }
      if(isset($body['level']) && (int)$body['level'] !== $target['level']){ log_event($pdo,$actorId,'tentativa_mudar_proprio_nivel_negada',['target'=>$targetUsername]); echo json_response(['error'=>'Não é permitido alterar seu próprio nível'],403); return; }
    }
  } else {
    // editando outro usuário (apenas administradores com autorização e nivel)
    if($actorLevel < 5){ log_event($pdo,$actorId,'nao_autorizado_editar_terceiro',['target'=>$targetUsername]); echo json_response(['error'=>'Não autorizado'],403); return; }
    if(empty($body['authorization'])){ log_event($pdo,$actorId,'falha_autorizacao_admin_faltando',['target'=>$targetUsername]); echo json_response(['error'=>'Autorização obrigatória'],403); return; }
    $auth = $body['authorization'];
    $stmt = $pdo->prepare("SELECT password_hash FROM users WHERE id=? LIMIT 1"); $stmt->execute([$actorId]); $hash = $stmt->fetchColumn();
    if(!$hash || !password_verify($auth,$hash)){ log_event($pdo,$actorId,'falha_autorizacao_admin_invalida',['target'=>$targetUsername]); echo json_response(['error'=>'Autorização inválida'],403); return; }
  }

  if(!empty($body['action']) && $body['action'] === 'delete'){
    try{
      $pdo->prepare("UPDATE users SET level=0, active=0 WHERE id=?")->execute([$targetId]);
      log_event($pdo,$actorId,'usuario_desativado',['target_id'=>$targetId,'target_username'=>$targetUsername]);
      echo json_response(['success'=>true,'message'=>'Usuário desativado (level=0, active=0)']);
    } catch (Throwable $e){
      log_event($pdo,$actorId,'erro_desativar_usuario',['target_id'=>$targetId,'msg'=>$e->getMessage()]);
      echo json_response(['error'=>'Erro ao desativar usuário'],500);
    }
    return;
  }

  // construir update dinâmico (somente campos enviados)
  $fields = [];
  $params = [];
  $changed = [];
  if(isset($body['username']) && trim($body['username']) !== '' && trim($body['username']) !== $target['username']){
    $newu = trim($body['username']);
    // checar unicidade
    $s = $pdo->prepare("SELECT id FROM users WHERE username=? AND id<>? LIMIT 1"); $s->execute([$newu,$targetId]);
    if($s->fetch()){ log_event($pdo,$actorId,'falha_alterar_username_duplicado',['target'=>$targetUsername,'novo'=>$newu]); echo json_response(['error'=>'username já em uso'],409); return; }
    $fields[] = "username=?"; $params[] = $newu; $changed[]='username';
  }
  if(isset($body['email'])){ $fields[]="email=?"; $params[] = trim($body['email']); $changed[]='email'; }
  if(isset($body['phone'])){ $fields[]="phone=?"; $params[] = trim($body['phone']); $changed[]='phone'; }
  if(isset($body['active'])){ $fields[]="active=?"; $params[] = (int)$body['active']; $changed[]='active'; }
  if(isset($body['level'])){
    // somente admins (já autorizados) podem alterar level; se self and admin then ok
    if($actorLevel < 5 && $isSelf){ log_event($pdo,$actorId,'tentativa_alterar_level_sem_permissao',['target'=>$targetUsername]); echo json_response(['error'=>'Não autorizado alterar level'],403); return; }
    $fields[] = "level=?"; $params[] = (int)$body['level']; $changed[]='level';
  }
  if(!empty($body['new_password']) || !empty($body['new_password_confirm'])){
    $np = $body['new_password'] ?? ''; $nc = $body['new_password_confirm'] ?? '';
    if($np === '' || $nc === ''){ log_event($pdo,$actorId,'falha_senha_campos_incompletos',['target'=>$targetUsername]); echo json_response(['error'=>'new_password e new_password_confirm obrigatórios para trocar a senha'],400); return; }
    if($np !== $nc){ log_event($pdo,$actorId,'falha_senha_confirmacao',['target'=>$targetUsername]); echo json_response(['error'=>'Nova senha e confirmação não conferem'],400); return; }
    if(strlen($np) < 8){ log_event($pdo,$actorId,'falha_senha_curta',['target'=>$targetUsername]); echo json_response(['error'=>'Senha deve ter ao menos 8 caracteres'],400); return; }
    $fields[] = "password_hash=?"; $params[] = password_hash($np, PASSWORD_DEFAULT); $changed[]='password';
  }

  if(empty($fields)){ log_event($pdo,$actorId,'nenhuma_alteracao_informada',['target'=>$targetUsername]); echo json_response(['error'=>'Nenhum campo para alterar'],400); return; }

  try{
      if (isset($body['active']) && (int)$body['active'] > 0){
          $fields[] = "activation_token_hash=NULL";
          $fields[] = "activated_at=NOW()";
          log_event($pdo, $actorId, 'usuario_ativado', ['target_id'=>$targetId,'target_username'=>$targetUsername]);
      }
      if (isset($body['active']) && (int)$body['active'] == 0){
          $fields[] = "activation_token_hash=NULL";
          log_event($pdo, $actorId, 'usuario_desativado', ['target_id'=>$targetId,'target_username'=>$targetUsername]);
      }

      $params[] = $targetId;
      $sql = "UPDATE users SET ".implode(', ',$fields)." WHERE id=?";
      $pdo->prepare($sql)->execute($params);
      log_event($pdo,$actorId,'usuario_editado',['target_id'=>$targetId,'target_username'=>$targetUsername,'changed'=>$changed]);
      echo json_response(['success'=>true,'message'=>'Usuário atualizado','changed'=>$changed]);
  } catch (Throwable $e){
      log_event($pdo,$actorId,'erro_atualizar_usuario',['target_id'=>$targetId,'msg'=>$e->getMessage()]);
      echo json_response(['error'=>'Erro ao atualizar usuário'],500);
  }
}
//-- ----------------------------------------------------------------






function api_logout(PDO $pdo, array $config){
  $token = get_bearer_token();
  if(!$token){ echo json_response(['error'=>'Token não informado'],400); return; }
  $th = token_hash($token);
  $stmt = $pdo->prepare("SELECT id,user_id FROM sessions WHERE token_hash=? LIMIT 1"); $stmt->execute([$th]); $s = $stmt->fetch(PDO::FETCH_ASSOC);
  if($s){
    $pdo->prepare("DELETE FROM sessions WHERE id=?")->execute([$s['id']]);
    setcookie('AFABB-AUTH_SESSION', '', time() - 3600, '/', '', true, true); // limpa token do cookie
    log_event($pdo,(int)$s['user_id'],'logout_de_sessão',[]);
    echo json_response(['success'=>true,'message'=>'Logout realizado']);
  } else { echo json_response(['error'=>'Sessão não encontrada'],404); }
}

function api_me(PDO $pdo, array $config){
  $user = auth_by_token($pdo,$config);
  if(!$user){ echo json_response(['error'=>'Não autenticado'],401); return; }
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
  let prefix = pathname.replace(/\/index\.php$/i,'').replace(/\/$/,'');
  if(prefix === '/') prefix = '';
  window.API_BASE = location.origin + prefix + '/';
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
    if(t) return t;
  } catch(e){}
  // cookie fallback
  const m = document.cookie.match(/(?:^|; )AFABB-AUTH_SESSION=([^;]+)/);
  if(m) return decodeURIComponent(m[1]);
  return null;
}
function scrollToTopSmooth(duration = 1000){
  //window.scrollTo({ top: 0, behavior: 'smooth' });
  const start = window.scrollY;
  const startTime = performance.now();
  function animate(currentTime){
    const elapsed = currentTime - startTime;
    const progress = Math.min(elapsed / duration, 1);
    const ease = 1 - Math.pow(1 - progress, 3); // easing cubic out
    window.scrollTo(0, start * (1 - ease));
    if(progress < 1) requestAnimationFrame(animate);
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
  if(!username || !password){ show('username e password obrigatórios', false); return; }
  const res = await callApi('/login', {method:'POST', body: JSON.stringify({username, password})});
  if(res.ok) show('Código 2FA: ' + (res.data.code || '(não retornado)')); else show(res.data.error || JSON.stringify(res.data), false);
}

async function verify(){
  const code = (document.getElementById('otp_code').value || '').trim();
  const remember = document.getElementById('remember').checked;
  if(!/^\d{6}$/.test(code)){ show('Código inválido (6 dígitos)', false); return; }
  const res = await callApi('/verify-otp', {method:'POST', body: JSON.stringify({code, remember_me: remember})});
  if(res.ok){
    if(!res.data.token){ show('Erro: token não retornado pela API', false); return; }
    setTokenClient(res.data.token, remember);
    show('<SPAN class="spinLoad"></SPAN> Login completo!');
    setTimeout(() => location.reload(), 1000);
  } else {
    show(res.data.error || JSON.stringify(res.data), false);
  }
}
/* atalhos por Enter */
document.addEventListener('keydown', function(e){
  if(e.key === 'Enter'){
    const active = document.activeElement;
    if(!active) return;
    if((active.id === 'l_username' || active.id === 'l_password') && document.getElementById('l_username').value.trim() && document.getElementById('l_password').value) login();
    if(active.id === 'otp_code' && document.getElementById('otp_code').value.trim()) verify();
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

<div class="card" id="card_change_own_password">
  <h3 class="h">Trocar minha senha</h3>
  <input id="cp_current_password" class="input" type="password" placeholder="Senha atual">
  <input id="cp_new_password" class="input" type="password" placeholder="Nova senha">
  <input id="cp_new_password_confirm" class="input" type="password" placeholder="Repita (nova senha)">
  <button class="btn" onclick="changeOwnPassword()">Alterar senha</button>
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

<div class="card" id="card_admin_users" style="display:none;">
  <h3 class="h">Admin: Gerenciar usuários</h3>
  <div class="small">Selecione usuário para editar (somente admins).</div>
  <select id="adm_user_select" class="input" onchange="admFillUser()"><option value="">Carregando...</option></select>
  <input id="adm_username" class="input" placeholder="username (trocar)">
  <input id="adm_email" class="input" placeholder="e-mail (opcional)">
  <input id="adm_phone" class="input" placeholder="WhatsApp">
  <input id="adm_new_password" class="input" type="password" placeholder="nova senha">
  <input id="adm_new_password_confirm" class="input" type="password" placeholder="nova senha (confirm)">
  <label class="small">Nível
    <select id="adm_level" class="input" style="padding:8px;">
      <option value="0" disabled hidden selected>0</option><option value="1">1</option><option value="2">2</option>
      <option value="3">3</option><option value="4">4</option><option value="5">5</option><option value="6">6</option>
      <option value="7">7</option><option value="8">8</option><option value="9">9</option><option value="10">10</option>
    </select>
  </label>
  <label style="display:flex;align-items:center;margin-top:8px;">
    <input id="adm_active" type="checkbox" style="margin-right:8px;"> Ativo
  </label><BR>
  <input id="adm_authorization" class="input" type="password" placeholder="Autorização (ADM)*">
  <div class="row" style="margin-top:8px">
    <button class="btn" onclick="adminUpdateUser()">Salvar alterações</button>
    <button class="btn" style="background:#EF4444" onclick="adminDeleteUser()">Remover</button>
  </div>
</div>



<div class="card" id="session_ops">
  <h3 class="h">Sessão</h3>
  <button class="btn" onclick="me()">Me (meus dados)</button>
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
  if(!username || !phone || !password){ show('username, whatsapp e password obrigatórios', false); return; }
  const res = await callApi('/register', {method:'POST', body: JSON.stringify({username,email,phone,password})});
  if(res.ok) show('Registrado. Token de Ativação: ' + (res.data.activation_token || '')); else show(res.data.error || JSON.stringify(res.data), false);
}

async function activate(){
  scrollToTopSmooth();
  const username = document.getElementById('a_username').value.trim();
  const token = document.getElementById('a_token').value.trim();
  if(!username || !token){ show('username e token de activação são obrigatórios', false); return; }
  const res = await callApi('/activate', {method:'POST', body: JSON.stringify({username, activation_token: token})});
  if(res.ok) show(res.data.message || 'Conta ativada'); else show(res.data.error || JSON.stringify(res.data), false);
}

async function me(){
  scrollToTopSmooth();
  const token = getTokenClient();
  if(!token){ show('Sem token salvo.', false); setTimeout(() => location.reload(), 1000); return; }
  const res = await callApi('/me', {method:'GET', headers: {'Authorization': 'Bearer ' + token}});
  if(res.ok){ 
    show('Usuário: ' + (res.data.username || '') + ' / email: ' + (res.data.email || '') + ' / telefone: ' + (res.data.phone || '')); 
    // console.log(res.data);
  }else {
    if(res.status === 401){ 
      clearTokenClient(); 
      show('Não autenticado. Token inválido ou expirado.', false); 
    } else show(res.data.error || JSON.stringify(res.data), false);
  }
}

async function changeOwnPassword(){
  scrollToTopSmooth();
  show('<SPAN class="spinLoad"></SPAN> Aguarde...');
  const token = getTokenClient(); if(!token){ show('Sem token salvo.', false); return; }
  const cur = document.getElementById('cp_current_password').value.trim();
  const np = document.getElementById('cp_new_password').value;
  const nc = document.getElementById('cp_new_password_confirm').value;
  if(!cur||!np||!nc){ show('Preencha todos os campos', false); return; }
  const res = await callApi('/change-password', { method:'POST', headers:{ 'Authorization':'Bearer '+token }, body: JSON.stringify({ current_password: cur, new_password: np, new_password_confirm: nc }) });
  if(res.ok){ show(res.data.message || 'Senha alterada'); document.getElementById('cp_current_password').value=''; document.getElementById('cp_new_password').value=''; document.getElementById('cp_new_password_confirm').value=''; }
  else show(res.data.error || JSON.stringify(res.data), false);
}


////////////////////////////////////////////////////
let ADM_USERS_CACHE = [];

async function loadAdminUsersCard(){
  const t = getTokenClient(); if(!t) return;
  const res = await callApi('/users', { method:'GET', headers: { 'Authorization':'Bearer '+t } });
  if(!res.ok){ return; }
  ADM_USERS_CACHE = res.data.users || [];
  const sel = document.getElementById('adm_user_select'); sel.innerHTML = '<option value="">-- selecione --</option>';
  ADM_USERS_CACHE.forEach(u => { const opt = document.createElement('option'); opt.value = u.username; opt.textContent = u.username + ' ('+(u.phone? ''+u.phone:'')+')'; sel.appendChild(opt); });
  document.querySelectorAll('#card_admin_users input, #card_admin_users select').forEach(el=>{if(el.type==='checkbox'){el.checked=false;}else{el.value='';}});
  document.getElementById('adm_level').value='';
  document.getElementById('card_admin_users').style.display = 'block';
} window.addEventListener('load',()=>loadAdminUsersCard().catch(()=>{}));

function admFillUser(){
  const sel = document.getElementById('adm_user_select'); const v = sel.value;
  const u = ADM_USERS_CACHE.find(x => x.username === v);
  if(!u){ document.getElementById('adm_username').value=''; document.getElementById('adm_email').value=''; document.getElementById('adm_phone').value=''; document.getElementById('adm_level').value=''; document.getElementById('adm_active').checked=false; return; }
  document.getElementById('adm_username').value = u.username;
  document.getElementById('adm_email').value = u.email || '';
  document.getElementById('adm_phone').value = u.phone || '';
  document.getElementById('adm_level').value = u.level || 0;
  document.getElementById('adm_active').checked = u.active==1 || u.active=='1';
  document.getElementById('adm_new_password').value=''; document.getElementById('adm_new_password_confirm').value='';
}

async function adminUpdateUser(){
  scrollToTopSmooth();
  show('<SPAN class="spinLoad"></SPAN> Aguarde...');
  const token = getTokenClient(); if(!token){ show('Sem token salvo.', false); return; }
  const target = document.getElementById('adm_user_select').value; if(!target){ show('Selecione um usuário', false); return; }
  const body = { target_username: target };
  const u = document.getElementById('adm_username').value.trim();
  if(u) body.username = u;
  const e = document.getElementById('adm_email').value.trim(); if(e) body.email = e;
  const p = document.getElementById('adm_phone').value.trim(); if(p) body.phone = p;
  const np = document.getElementById('adm_new_password').value;
  const nc = document.getElementById('adm_new_password_confirm').value;
  if(np || nc){ body.new_password = np; body.new_password_confirm = nc; }
  body.level = parseInt(document.getElementById('adm_level').value,10);
  body.active = document.getElementById('adm_active').checked ? 1 : 0;
  const auth = document.getElementById('adm_authorization').value;
  if(!auth){ show('Autorização (senha do admin) é obrigatória', false); return; }
  body.authorization = auth;
  const res = await callApi('/user-update', { method:'POST', headers:{ 'Authorization':'Bearer '+token }, body: JSON.stringify(body) });
  if(res.ok){ show(res.data.message || 'Usuário atualizado'); loadAdminUsersCard(); } else show(res.data.error || JSON.stringify(res.data), false);
}

async function adminDeleteUser(){
  if((u=document.getElementById('adm_user_select').value.trim()) && !confirm(`Confirma remoção do usuário "\${u}"?`)) return;
  const token = getTokenClient(); if(!token){ show('Sem token salvo.', false); return; }
  const target = document.getElementById('adm_user_select').value; if(!target){  scrollToTopSmooth(); show('Selecione um usuário', false); return; }
  const auth = document.getElementById('adm_authorization').value; if(!auth){  scrollToTopSmooth(); show('Autorização é obrigatória', false); return; }
  const res = await callApi('/user-update', { method:'POST', headers:{ 'Authorization':'Bearer '+token }, body: JSON.stringify({ target_username: target, action: 'delete', authorization: auth }) });
  if(res.ok){ show(res.data.message || 'Usuário desativado'); loadAdminUsersCard(); } else  scrollToTopSmooth(); show(res.data.error || JSON.stringify(res.data), false);
}
////////////////////////////////////////////////////

async function logout(){
  scrollToTopSmooth();
  const token = getTokenClient();
  if(!token){ show('Sem token salvo.', false); setTimeout(() => location.reload(), 1000); return; }
  const res = await callApi('/logout?token=' + encodeURIComponent(token), {method:'GET'});
  if(res.ok){ clearTokenClient(); show('<SPAN class="spinLoad"></SPAN> Realizando Logout...'); document.querySelector('.debug').innerHTML=``; setTimeout(() => location.reload(), 3000); } else show(res.data.error || JSON.stringify(res.data), false);
}

/* atalhos por Enter */
document.addEventListener('keydown', function(e){
  if(e.key === 'Enter'){
    const active = document.activeElement;
    if(!active) return;
    if((active.id === 'r_username' || active.id === 'r_password') && document.getElementById('r_username').value.trim() && document.getElementById('r_password').value) register();
    if((active.id === 'cp_current_password' || active.id === 'cp_new_password' || active.id === 'cp_new_password_confirm') && document.getElementById('cp_current_password').value.trim() && document.getElementById('cp_new_password').value && document.getElementById('cp_new_password_confirm').value) changeOwnPassword();
    if((active.id === 'adm_username' || active.id === 'adm_email' || active.id === 'adm_phone' || active.id === 'adm_new_password' || active.id === 'adm_new_password_confirm' || active.id === 'adm_level' || active.id === 'adm_authorization')){ adminUpdateUser(); }
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
  'users' => ['GET'],
  'user-update' => ['POST'],
  'change-password' => ['POST'],
  '' => ['GET']
];
$method = $_SERVER['REQUEST_METHOD'];
$requestPath = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH) ?: '/';
$apiPos = stripos($requestPath, '/'.basename(__DIR__));
if($apiPos === false){
  $scriptDirNormalized = rtrim(str_replace('\\','/', dirname($_SERVER['SCRIPT_NAME'])), '/');
  if($scriptDirNormalized !== '' && stripos($requestPath, $scriptDirNormalized) === 0){
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
if(!array_key_exists($rootEndpoint, $routes)){ http_response_code(404); echo json_response(['error'=>'Não permitido'],404); exit; }
$allowed = $routes[$rootEndpoint];
if(!in_array($method, $allowed, true)){ header('Allow: ' . implode(', ', $allowed)); http_response_code(405); echo json_response(['error'=>'Método não permitido para este endpoint','allowed'=>$allowed],405); exit; }


//* dispara handlers
switch ("$method $rootEndpoint"){
  case 'POST register': api_register($pdo,$config); break;
  case 'POST activate': api_activate($pdo,$config); break;
  case 'POST login': api_login($pdo,$config); break;
  case 'POST verify-otp': api_verify_otp($pdo,$config); break;
  case 'GET logout': api_logout($pdo,$config); break;
  case 'GET me': api_me($pdo,$config); break;
  case 'GET users': api_list_users($pdo,$config); break;
  case 'POST user-update': api_update_user($pdo,$config); break;
  case 'POST change-password': api_change_password($pdo,$config); break;
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





