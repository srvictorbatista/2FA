# Meu 2FA (base)
### API de autenticação 2FA implementado em um único arquivo PHP. 
**Aqui apresento seus recursos, endpoints, exemplos de uso (cURL/Insomnia) e recomendações de segurança.** 

## Descrição
> Tráta-se de um sistema de autenticação em 2 fatores base, para implementação (após modificação). Inclui endpoints principais (API), frontend e orientações de uso e configurações iniciais. Após informado os dados de conexão ao banco de dados (MySQL) o restante do ambiente é criado e configurado (automaticamente) pelo próprio script. Deixando o sistema pronto para uma demonstração incial (básica).

<BR><BR>





[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](#licença)                          [![GitHub Repository](https://img.shields.io/badge/github%20-%20Repository-%23D8B00??style=for-the-badge&logo=github&logoColor=white)](https://github.com/srvictorbatista/2FA)

**Made Withe:**

 [![ApiKey](https://img.shields.io/badge/ApiKey%20-%20WEB%20Security%20-%23FC6D26??style=for-the-badge&logo=caddy&logoColor=white)](#)                          [![Json](https://img.shields.io/badge/json%20-%20Web%20Response%20-%231B1C30??style=for-the-badge&logo=json&logoColor=white)](#)                          [![JavaScript](https://img.shields.io/badge/JavaScript%20-%20In%20Fronend%20-%23007808??style=for-the-badge&logo=javascript&logoColor=white)](#)                          [![PHP 8.2 / ++](https://img.shields.io/badge/PHP%208.2-%20In%20Backend-%23777BB4??style=for-the-badge&logo=php&logoColor=white)](#)                          

**RESTs exemples** (Oaut-opts):

[![cURL BASH](https://img.shields.io/badge/cURL%20-%20BASH-%23EEEEEE??style=for-the-badge&logo=curl&logoColor=white)](#)         [![cURL CMD](https://img.shields.io/badge/cURL%20-%20CMD-%23EEEEEE??style=for-the-badge&logo=curl&logoColor=white)](#)         [![Insomnia](https://img.shields.io/badge/Insomnia-%23AD29B6??style=for-the-badge&logo=insomnia&logoColor=white)](#)       [![Postman](https://img.shields.io/badge/Postman-%23FC6D26??style=for-the-badge&logo=postman&logoColor=white)](#)              
[![PHP 8.2 / ++](https://img.shields.io/badge/PHP%20-%208.2%20/++-%23777BB4??style=for-the-badge&logo=php&logoColor=white)](#)                          [![JS All Versions](https://img.shields.io/badge/javascript%20-%20In%20Client%20Web-%23F7DF1E??style=for-the-badge&logo=javascript&logoColor=white)](#)                          [![Web Forms](https://img.shields.io/badge/HTML%20Forms%20-%20Responsive-%23007808??style=for-the-badge&logo=semanticweb&logoColor=white)](#)                                                   




## Índice

- [Descrição](#descrição)
- [Recursos principais](#recursos-principais)
- [Recursos adicionais](#recursos-adicionais)
- [Endpoints principais](#endpoints-principais)
- [Regras e autorizações](#regras-importantes-e-autorizações)
- [Exemplos de uso](#exemplos-de-uso--curl-e-notas)
- [Observações e recomendações](#observações-e-recomendações-importantes)
- [Integração com o frontend](#integração-com-o-frontend-incluído)
- [Logs e auditoria](#logs-e-auditoria)
- [Contato / suporte](#contato--suporte)

---

## Recursos principais

* Criação automática de `.htaccess` (raiz) e `.htaccess` na pasta OTP (nega acesso).
* CORS / preflight `OPTIONS` tratado.
* Criação de banco de dados, tabelas e usuário administrador (`admin` / `admin123`) na primeira execução.
* Registro de eventos em tabela `logs` (eventos, timestamps, `user_id` quando possível). **NÃO** grava o valor dos OTPs em logs.
* Login com 2FA via arquivo cifrado (AES-256-GCM) em pasta protegida, por padrão; nomes de arquivos randômicos.
* Payload dos arquivos OTP cifrado com `APP_SECRET` — sem metadados legíveis que os relacionem ao usuário.
* TTL dos OTPs: 120 minutos; limpeza automática (garbage collector) a cada requisição.
* Ao validar o 2º passo (verify-otp), o arquivo OTP e seu respectivo arquivo são excluídos sem deixarem rastros.
* Sessões por token (Bearer) com timeout por inatividade (4 horas) e opção `lembrar-me` (persistência até logout explícito, na máquina que recebeu o token).
* Endpoints REST JSON; todas as respostas retornam `Content-Type: application/json`.
* Front-end para demonstração mínima em (HTML + JS) que consome a API via `fetch` e salva token em `localStorage` e cookie.
* O token local é sempre diferente do token remoto. Ambos são combinados, em tempo real (a cada sessão) resultando em uma hash de sessão única. A mesma lógica é aplicada para tokens de ativação.
* Uma vez enviado ao usuário, o servidor se livra de qualquer rastro do token de ativação. Uma vez ativada a conta (ao seu respectivo hash e usuário), o servidor também se livra do hash de ativação, permanentemente.


## Recursos adicionais

* Configurações no topo do arquivo (variáveis DB, `APP_SECRET`, diretórios OTP, TTLs).
* Controle de níveis de acesso (1..10) e regras específicas por endpoint.
* Campos opcionais mantendo valores atuais quando omitidos; alterações parciais suportadas.
* Exclusão suave de usuários: define `level = 0` e `active = 0` (soft delete) preservando histórico.
* Registro de logs detalhados mesmo em casos de insucesso (tentativas de acesso, erros de validação, autorizações inválidas).

## Endpoints principais

* `POST /register`       : cadastro de usuário (exige nível de acesso para criar usuários em certos fluxos).
* `POST /activate`       : ativação de conta via token de ativação.
* `POST /login`          : login com usuário/senha (gera código 2FA; em demonstração o código é retornado no JSON — em produção enviar via canal seguro).
* `POST /verify-otp`     : validação do código 2FA e criação de sessão (retorna token Bearer).
* `GET  /logout`         : logout da sessão atual (pode receber `?token=` ou header `Authorization`).
* `GET  /me`             : informações do usuário autenticado.
* `GET  /users`          : listar usuários (mínimo nível 5). Nível 999 inclui usuários `level=0 AND active=0`.
* `POST /change-password`: alterar própria senha (exige `current_password`).
* `POST /user-update`    : editar/administrar usuário (regras distintas para admin vs usuário próprio; exclusão via `action: "delete"`).

> Todos os endpoints retornam JSON e registram eventos em `logs`.

## Regras importantes e autorizações

* **Uso do `check_level()`**: todas as funções administrativas devem usar exatamente a verificação no início da função:

```php
if((($nivel = check_level()) ?? 0) < 5){ echo json_response(['error'=>"Não autorizado"],403); return; }
```

* **Listar usuários (`GET /users`)**: nível mínimo `5`; se `nivel === 999` inclui usuários `level=0` e `active=0`.
* **Alterar próprio usuário**:

  * Usuário comum (nivel < 5) exige envio de `current_password` para confirmar a operação; **não** pode alterar seu próprio `level`.
  * Administrador (nivel >= 5) pode alterar seus próprios dados, inclusive `level`, desde que confirme a operação com `authorization` (sua senha atual).
* **Editar outro usuário**: requer `authorization` (senha do admin que está executando) e `actor` com nível >= 5.
* **Trocar senha**: `current_password`, `new_password` e `new_password_confirm` obrigatórios para troca; `new_password` deve ter ao menos 8 caracteres.
* **Exclusão**: `POST /user-update` com `action: "delete"` realiza soft delete (`level=0, active=0`).
* **Campos omitted**: se um campo não for enviado, permanece inalterado. Se `new_password`/`confirm` não enviados, a senha permanece.
* **Logs**: toda tentativa (sucesso ou falha) deve gerar um evento em `logs` sem armazenar senhas em texto.

## Exemplos de uso — cURL e notas

> **AVISO:** Não use `curl -k` (ignorar verificação de certificados) em hosts de produção.
> ```-k``` ignora a verificação de certificados auto-assinados (use com cautela em ambientes de desenvolvimento). 

### 1) Registrar

```bash
curl -k -X POST "<URL_BASE>/register" -H "Content-Type: application/json" -H "Authorization: Bearer <TOKEN>" -d '{"username":"usuario1","email":"usuario1@local.com","phone":"5591999999999","password":"senha1234"}'
```

Notas:

* `<URL_BASE>` exemplo: `https://localhost/api`.
* Requer token com nível suficiente quando o fluxo exigir criação protegida.


### 2) Ativar

```bash
curl -k -X POST "<URL_BASE>/activate" -H "Content-Type: application/json" -d '{"username":"usuario1","activation_token":"47CF0A"}'
```

Resposta (exemplo): `{"success":true,"message":"Conta ativada com sucesso"}`

### 3) Login (senha) — gera 2FA

```bash
curl -k -X POST "<URL_BASE>/login" -H "Content-Type: application/json" -d '{"username":"admin","password":"admin123"}'
```

Notas:

* Em demonstração o código 2FA é retornado no JSON; em produção **não** retorne o código em API — envie por canal seguro (SMS/WhatsApp/e-mail/app).

### 4) Verificar 2FA

```bash
curl -k -X POST "<URL_BASE>/verify-otp" -H "Content-Type: application/json" -d '{"code":"569379","remember_me":true}'
```
Resposta (exemplo): `{"success":true,"token":"<SESSION_TOKEN>","message":"Autenticado com sucesso"}`

<BR> 

### Login em uma linha (via terminal) 
Quando em terminais (prompts BASH/ASH/CMD/PowerShell) o token de sessão pode ser armazenado em variavel de ambiente a critério do utilizador. Embora este recurso esteja disponível, seu uso em produção não é recomendado.

*Em prompts CMD é necessário ter <a href="https://jqlang.org/download/" target="_blank">JQ para Windows</a> instalado e disponivel no ambiente, por dependência.
Em ambientes Mac e Debian, JQ já vem incluso nativamente.

Exemplo de login completo em uma linha:

**PowerShell:**
```powershell
powershell -NoProfile -Command "[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}; $body=@{username='admin';password='admin123'}|ConvertTo-Json; $r=Invoke-RestMethod -Uri '<URL_BASE>/login' -Method Post -ContentType 'application/json' -Body $body; $code=$r.code; $v=@{code=$code;remember_me=$true}|ConvertTo-Json; Invoke-RestMethod -Uri '<URL_BASE>/verify-otp' -Method Post -ContentType 'application/json' -Body $v | ConvertTo-Json -Compress"
```


**BASH:**
```bash
curl -sk -H "Content-Type: application/json" -d '{"username":"admin","password":"admin123"}' <URL_BASE>/login | jq -r '.code' | xargs -I{} curl -sk -H "Content-Type: application/json" -d '{"code":"{}","remember_me":true}' <URL_BASE>/verify-otp | jq -c .
``` 


**CMD** (requer ambiente Windows com JQ instalado):
```bash
for /f "delims=" %c in ('curl -s -k -H "Content-Type: application/json" -d "{\"username\":\"admin\",\"password\":\"admin123\"}" "<URL_BASE>/login" ^| jq -r ".code"') do @curl -s -k -H "Content-Type: application/json" -d "{\"code\":\"%c\",\"remember_me\":true}" "<URL_BASE>/verify-otp" ^| jq -c .
```

**NOTA:** Neste comando CMD, o JQ é o responsável por compirmir o retorno json, usado para extrair os dados de resposta. Caso não possua <a href="https://jqlang.org/download/" target="_blank">JQ para Windows</a> instalado em seu ambiente. Use a autenticação normal (em duas etapas). Ou uma das outras duas alternativas (PorwerShell/BASH).
Caso deseje instalar JQ em seu **terminal CMD**, por linha de comando e adiciona-lo automaticamente ao seu ambiente Windows, use: 
``` 
winget install jqlang.jq -h
```
Após executar este comando é necessário fechar e reabrir o seu terminal CMD.

<BR>



### 5) Logout (GET)

```bash
curl -k -G "<URL_BASE>/logout" --data-urlencode "token=<SESSION_TOKEN>"
```

Ou via header:

```bash
curl -k -X GET "<URL_BASE>/logout" -H "Authorization: Bearer <SESSION_TOKEN>"
```

### 6) Me (usuário autenticado)

```bash
curl -k -H "Authorization: Bearer <SESSION_TOKEN>" "<URL_BASE>/me"
```

### 7) Listar usuários (apenas administradores)

```bash
curl -k -X GET "<URL_BASE>/users" -H "Authorization: Bearer <SESSION_TOKEN>" -H "Accept: application/json"
```

Retorno: JSON com lista de usuários. Nível mínimo 5; nível 999 inclui `level=0` e `active=0`.

### 8) Alterar própria senha

```bash
curl -k -X POST "<URL_BASE>/change-password" -H "Authorization: Bearer <SESSION_TOKEN>" -H "Content-Type: application/json" -d '{"current_password":"SenhaAtual123","new_password":"NovaSenha123!","new_password_confirm":"NovaSenha123!"}'
```

### 9) Administrar / editar usuário

```bash
curl -k -X POST "<URL_BASE>/user-update" -H "Authorization: Bearer <SESSION_TOKEN>" -H "Content-Type: application/json" -d '{"target_username":"usuario1","username":"novo_nome","email":"novo@local.com","phone":"5591988887777","new_password":"NovaSenha123!","new_password_confirm":"NovaSenha123!","level":3,"active":1,"authorization":"SENHA_DO_ADMIN"}'
```

Regras resumidas:

* Para editar outro usuário: enviar `target_username` + `authorization` (senha do admin que executa); requer nível adequado.
* Para editar a si mesmo (usuário comum): enviar `current_password`; não é possível alterar o próprio `level`.
* Para admin editar a si mesmo: enviar `authorization`.
* Para excluir: enviar `{ "target_username":"usuario1", "action":"delete", "authorization":"SENHA_DO_ADMIN" }`.


## OBSERVAÇÕES E RECOMENDAÇÕES IMPORTANTES

### Considerações importantes para produção:
* **Dependências:** Servidor **MySQL** e **PHP** com SSL/HTTPS (**HTTPS obrigatório**).
* Mantenha `APP_SECRET` fora do controle de versão (variáveis de ambiente, vault, KMS/HSM quando possível).
* Proteja a pasta OTP fora do `webroot` e garanta regras de servidor que neguem acesso direto.
* Considere mecanismos de monitoramento para OTPs.
* Em produção **não retorne OTPs diretamente na resposta da API** — envie por canal seguro.
* Recomenda-se (em produção), ocultar a interface web embutida. Setando a variável  **```FRONT_END```** como ``'silent'``, ``0`` ou ``false``. Veja mais detalhes sobre o que representa cada valor,  no próprio script.
* Em alta escala, avalie armazenamento físico de OTPs. Por padrão este projeto já evita indexação simples e varredura linear.
* Para produção, **deve ser implementado um canal seguro** para envio de códigos OTPs. **Recomendo SMS, WhatsApp**. Embora possa ser implementado e-mail (a critério do desenvolvedor), não é uma recomendação ou conceito fim deste projeto.
* **Este script exige servidor WEB com HTTPS mesmo em localhost (ambiente de desenvolvimento).** 
* No cabeçalho do script, inclui instruções adicionais para consulta rápida e testes em ambiente local (requestes e command cURL) com conexão SSL (certificado auto-assinado). Não use **`` cURL -k ``** para testes em produção.
* Ainda mais detalhes podem ser consultados, no cabeçalho do próprio script.

---

## Integração com o frontend (incluído)

* Trata-se de uma maneira simples e rápida de "copiar e colar" em seu próprio projeto, adaptando conforme seu uso/objetivo.
*  **O objetivo deste frontend embutido, é prover uma demonstração e entendimento, instantâneo e prático do que esta sendo disponibilizado ao levantar este projeto. Não é aconselhável, seu uso/exibição em produção.**  
* O frontend de demonstração pode (em alguns casos, deve), ser ocultado ou desativado em produção.  Logo no inicio do script, há opções de como fazer isto. Setando a variável  **```FRONT_END```** como ``'silent'``, ``0`` ou ``false``. Veja mais detalhes sobre o que representa cada valor,  no próprio script.
* A interface HTML  usa `callApi()` e funções utilitárias (`getTokenClient()`, `setTokenClient()`, `clearTokenClient()`) para comunicar com os endpoints.
* Os cards administrativos e de troca de senha, consomem os endpoints `POST /change-password`, `GET /users` e `POST /user-update` conforme especificado. 
<BR> Em analogia: Considere este FRONTEND como um kit completo de pincéis e tinha, onde o pintor é você!

---

## Logs e auditoria

* Eventos importantes e tentativas falhas são registrados em `logs` com `user_id` quando possível e metadados (`meta`) em JSON que não incluem senhas literais.
* Exemplos de eventos: 
 `usuario_cadastrado`, `usuario_ativado`, `falha_login_senha_incorreta`, `codigo_otp_gerado`, `codigo_otp_verificado`, `sessao_criada`, `listar_usuarios`, `usuario_editado`, `usuario_desativado`, `senha_alterada_com_sucesso`.
-- Embora seja relativamente simples implementar novos logs a seu critério por ```log_event()``` . Novos eventos e ações podem ser catalogados a qualquer momento. 

---

## Contato / suporte

Para reports, dúvidas ou sugestões de melhorias, entre em contato com  o autor.

---

### Autor

**<a href="https://t.me/LevyMac" target="_blank">Sr. Victor Batista</a>**


