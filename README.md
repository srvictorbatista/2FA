# Meu 2FA (base)

Trata-se de um sistema de autenticação em 2 fatores base, para implementação (após modificação).
Inclui endpoints principais (API), frontend e orientações de uso e configurações iniciais.
Após informado os dados de conexão ao banco de dados (MySQL) o restante do ambiente é criado e configurado (inicialmente) pelo próprio script. Deixando o sistema pronto para uma demonstração incial (básica).

## *Observações:* 
Para produção, deve ser implementado um canal seguro para envio de códigos OTP.  Recomendo SMS, WhatsApp.

Dependencias:
Servidor MySQL e PHP com SSL/HTTPS. 
O script exige servidor WEB com HTTPS (mesmo em localhost). No cabeçalho, inclui instrções para testes em ambiente local (requestes e command cURL) com conexão SSL (certificado auto-assinado).

Mais detalhes, no cabeçalho do próprio script.
