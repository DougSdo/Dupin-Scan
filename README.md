# Dupin-Scan

Ferramenta de **triagem** de ameaças para Windows e Linux, com interface gráfica e linha de comando:
varredura de arquivos (hash, YARA, heurísticas, conteúdo de scripts), persistência (e o executável que ela
aponta), processos suspeitos e **artefatos forenses** (logs de eventos, `auth.log`, históricos de shell, Prefetch;
também `.evtx`, Amcache e Shimcache exportados), com **quarentena reversível**. Cada achado é mapeado para uma
técnica **MITRE ATT&CK**; o que já foi visto e o que o usuário marcou como esperado é lembrado entre varreduras;
os resultados saem em JSON, HTML, CSV e linha do tempo; e as detecções podem ser exportadas como regras
**Sigma** e **YARA**.

> Não substitui antivírus/EDR. Achados são indícios: confirme antes de agir.
> Leia [O que o Dupin-Scan não detecta](#o-que-o-dupin-scan-não-detecta) antes de confiar num resultado "limpo".

## Executar a partir do código
Windows: dê duplo clique em `run_windows.bat` (cria uma venv local e abre o app).

Qualquer sistema:
```
pip install -r requirements.txt
python run_dupin_scan.py        # interface (ou: python -m dupin_scan)
python -m dupin_scan scan ...   # linha de comando (ver abaixo)
```
`python -m dupin_scan arquivo.exe pasta\` abre a interface já apontada para esses alvos.

## Usar a interface
- **Varredura:** escolha o que verificar (arquivos, persistência, processos, artefatos forenses) e os alvos
  (pastas **e arquivos avulsos**). Dá para **arrastar e soltar** arquivos/pastas na janela. O botão
  *Analisar artefato exportado…* abre um `.evtx`, hive, `auth.log`, histórico ou `.pf` copiado de outra máquina.
- **Resultados:** tabela por gravidade, técnica ATT&CK e coluna **Novo** (primeira vez que o achado aparece);
  o filtro *Só os novos* esconde o resto. Em cada achado: detalhes, confiança do binário, *Ignorar este achado*,
  *Consultar VirusTotal* (só o hash, só depois de confirmar), quarentena (arquivos) e *Exportar relatório…*
  (JSON, HTML, CSV ou linha do tempo).
- **Configurações:** fontes de detecção, inteligência de ameaças (opcional), regras Sigma/YARA e a lista de
  itens ignorados (dá para desfazer).
- O instalador do Windows pode adicionar **"Varrer com o Dupin-Scan"** ao menu de contexto de arquivos e pastas.

## Linha de comando
Própria para agendar e automatizar. Funciona sem ambiente gráfico (a interface nem é importada).
```
python -m dupin_scan scan --out relatorio.json --fail-on ALTO         # código de saída 2 se houver achado ALTO
python -m dupin_scan scan --modules files,forensics --targets C:\Users\eu\Downloads --out rel.html
python -m dupin_scan scan --track --use-intel --out rel.json          # ignorados + "novo" + hashes/regras baixados
python -m dupin_scan analyze Security.evtx auth.log.1.gz --out artefatos.html
python -m dupin_scan timeline relatorio.json --out linha-do-tempo.csv
python -m dupin_scan export-rules --out regras
python -m dupin_scan ignored list | remove CHAVE | add CHAVE --report relatorio.json
python -m dupin_scan intel status | update-hashes | update-yara | vt SHA256
```
- Códigos de saída: `0` sem achados no limite pedido, `1` erro, `2` achados em `--fail-on` ou acima.
- `scan` **nunca usa a rede**. Só `intel ...` acessa a internet, e por comando explícito.
- Chaves de API **só por variável de ambiente** (`ABUSECH_AUTH_KEY`, `VT_API_KEY`): argumentos aparecem na lista de
  processos, então a CLI nem os aceita.
- `--out` escolhe o formato pelo sufixo: `.json`, `.html`, `.csv` (achados) ou `.timeline.csv`; `-` imprime JSON.
- Instalada pelo instalador, a CLI fica em `dupin-scan-cli.exe` (opção de adicionar ao PATH).

## Mapeamento MITRE ATT&CK
Cada achado traz as técnicas associadas (coluna **ATT&CK** nos resultados e campo `attack` no JSON exportado).
O catálogo, com nomes e táticas conferidos em attack.mitre.org, está em [dupin_scan/attack.py](dupin_scan/attack.py).

| Detecção | Técnica |
|---|---|
| Chaves `Run`/`RunOnce` (HKCU/HKLM, inclusive `WOW6432Node`) com comando suspeito | T1547.001 Registry Run Keys / Startup Folder |
| Executável na pasta Startup | T1547.001 |
| Tarefa agendada (Windows) | T1053.005 Scheduled Task |
| Entradas de cron, `anacrontab`, `cron.{hourly,daily,weekly,monthly}` | T1053.003 Cron |
| Jobs do `at` (Linux) | T1053.002 At |
| Serviço acionado por timer do systemd | T1053.006 Systemd Timers |
| `/etc/rc.local`, scripts de `/etc/init.d` | T1037.004 RC Scripts |
| `.bashrc`, `.profile`, `.zshrc`, `/etc/profile.d` | T1546.004 Unix Shell Configuration Modification |
| Serviços systemd (`*.service`) e drop-ins (`*.d/*.conf`) | T1543.002 Systemd Service |
| Serviços do Windows (início boot/sistema/automático) | T1543.003 Windows Service |
| Autostart XDG (`*.desktop`) | T1547.013 XDG Autostart Entries |
| Regras udev com comando (`RUN+=`) | T1546.017 Udev Rules |
| `/etc/ld.so.preload` não vazio | T1574.006 Dynamic Linker Hijacking |
| `authorized_keys` com `command=` (comando forçado) | T1098.004 SSH Authorized Keys |
| Winlogon `Shell`/`Userinit` alterados | T1547.004 Winlogon Helper DLL |
| IFEO com `Debugger` | T1546.012 Image File Execution Options Injection |
| `AppInit_DLLs` não vazio | T1546.010 AppInit DLLs |
| Assinatura WMI permanente (CommandLine/ActiveScript) | T1546.003 WMI Event Subscription |
| PowerShell codificado/oculto | T1059.001 PowerShell + T1027.010 Command Obfuscation |
| `curl`/`wget` direto no shell | T1105 Ingress Tool Transfer + T1059.004 Unix Shell |
| `base64 -d` em comando | T1140 Deobfuscate/Decode Files or Information |
| `netcat -e`, `bash -i >& /dev/tcp` | T1059.004 Unix Shell |
| `mshta`, `regsvr32 scrobj`, `rundll32 javascript` | T1218.005, T1218.010, T1218.011 |
| `certutil -urlcache` / `bitsadmin /transfer` | T1105 / T1197 BITS Jobs |
| Binário PE/ELF com extensão de documento | T1036.008 Masquerade File Type |
| Dupla extensão (`fatura.pdf.exe`) | T1036.007 Double File Extension |
| Entropia alta em binário | T1027.002 Software Packing |
| Processo com nome de binário do Windows fora do lugar, ou nome parecido (`scvhost.exe`) | T1036.005 Match Legitimate Resource Name or Location |
| Office/leitor de PDF iniciando `cmd`/PowerShell/`mshta`... | T1204.002 User Execution: Malicious File |
| Servidor web (IIS, nginx, apache, php-fpm) iniciando shell | T1505.003 Web Shell |
| Processo cujo binário foi apagado do disco (Linux) | T1070.004 File Deletion |
| *Forense:* muitas falhas de login do mesmo endereço (SSH, 4625) | T1110 Brute Force |
| *Forense:* login bem-sucedido do mesmo endereço depois das falhas; root via SSH de IP público | T1078 Valid Accounts |
| *Forense:* conta criada (`useradd`, 4720) | T1136.001 Local Account |
| *Forense:* usuário no grupo `sudo`/`wheel`/Administradores (4732) | T1098 Account Manipulation |
| *Forense:* log Security (1102) ou System (104) apagado | T1685.005 Clear Windows Event Logs |
| *Forense:* `history -c`, `HISTFILE=/dev/null`, `Clear-History` e similares | T1070.003 Clear Command History |
| *Forense:* tarefa criada de pasta suspeita (4698); script PowerShell suspeito (4104) | T1053.005 / T1059.001 |
| *Forense:* Prefetch, Amcache ou Shimcache de `mimikatz`, `procdump` | T1003.001 OS Credential Dumping: LSASS Memory |
| *Forense:* Prefetch, Amcache ou Shimcache de `PsExec` | T1569.002 Service Execution |
| *Forense:* Prefetch, Amcache ou Shimcache de `LaZagne` / `Rubeus` | T1555 Credentials from Password Stores / T1558 Steal or Forge Kerberos Tickets |

A T1070.001 (apagar logs do Windows) foi movida no ATT&CK atual para **T1685.005**; o Dupin-Scan usa o ID novo.
A tática *Defense Evasion* chama-se hoje *Stealth*, e o catálogo segue os nomes do site.

Sem técnica associada (são indicadores, não comportamentos): hash conhecido, regra YARA do usuário,
pasta comumente abusada e conexão externa. Para tarefas agendadas e cron usamos as subtécnicas
(T1053.005 / T1053.003), não a T1053 genérica.

## Persistência e processos
**Segue o executável.** Para cada entrada de persistência (chave Run, tarefa, serviço, `ExecStart`, cron...), o Dupin-Scan
extrai o caminho do executável e o analisa como qualquer arquivo (hash, YARA, heurísticas, confiança). Uma tarefa de
aparência inofensiva que chama um binário suspeito agora gera achado; antes só o texto do comando era julgado.

- **Windows:** `Run`/`RunOnce` (inclusive 32 bits), pasta Startup, tarefas agendadas, **serviços**, Winlogon
  (`Shell`/`Userinit`), IFEO (`Debugger`), `AppInit_DLLs` e **assinaturas WMI** (estas exigem administrador).
- **Linux:** cron (e `anacrontab`, `cron.*`), `at`, `rc.local`, `init.d`, perfis de shell, `profile.d`, systemd
  (serviços, **drop-ins** e **timers**), autostart XDG, **udev**, `ld.so.preload` e **`authorized_keys`** com
  comando forçado (o conteúdo da chave nunca é guardado).
- **Processos:** além de linha de comando e pasta, analisa o **executável do processo**, nomes de binários do Windows
  fora do lugar (`svchost.exe` fora do `System32`) ou parecidos (`svch0st`, `scvhost`) e a **relação pai-filho**
  (Office/IIS gerando interpretadores; servidor web gerando shell).
- **Conteúdo de scripts** (`.ps1 .vbs .js .bat .cmd .sh .py .pl .hta .wsf`, até o primeiro 1 MiB, UTF-8 ou UTF-16):
  as mesmas regras de comando suspeito são aplicadas ao texto do arquivo.

## Confiança no binário (menos falsos positivos)
Para os achados que envolvem um binário, o Dupin-Scan consulta se ele é **confiável** e abate só as heurísticas fracas:
- **Windows:** assinatura digital válida (`Get-AuthenticodeSignature`, que entende assinaturas embutidas e de catálogo
  do Windows). O fabricante e "binário do Windows" aparecem nos detalhes.
- **Linux:** o arquivo pertence a um pacote (`dpkg -S` / `rpm -qf`) e, no dpkg, o MD5 bate com o `md5sums` do pacote.
  Um binário de pacote **modificado** não é confiável e o motivo diz isso.
- **O que é abatido:** os motivos baseados só na **pasta** ("roda de AppData", "caminho temporário") e as heurísticas
  fracas de arquivo (entropia, pasta). **Nunca** são abrandados: hash conhecido, regra YARA e qualquer motivo de
  **comando** (um `powershell.exe` assinado com `-enc` continua suspeito).
- Só é consultado para o que já gerou achado (cada consulta leva cerca de 0,3 s no Windows), com cache por arquivo.
- Em uma máquina de teste isso reduziu a persistência de 11 para 2 achados e os processos de 24 para 6.

## Lista de ignorados e "novo desde a última vez"
- **Ignorar** marca um achado como esperado. A chave inclui o hash do arquivo: se ele mudar, volta a aparecer.
  Desfaz-se em Configurações ou com `dupin-scan ignored remove`.
- **Baseline:** o Dupin-Scan lembra o que já viu (`state.json` na pasta de dados). Na segunda varredura em diante cada
  achado fica marcado como **novo** ou não. Na primeira varredura de cada tipo nada é marcado, para não pintar tudo igual.
- A varredura **cancelada** não grava nada. A API (`core.run_scan`) não tem efeitos colaterais por padrão
  (`track=False`); a interface e `--track` ligam.

## Linha do tempo e relatórios
Cada achado tem um horário quando há um: modificação do arquivo, início do processo, evento do log. A **linha do tempo**
junta tudo em ordem. Formatos de saída (interface e `--out`):
- **JSON** completo; **HTML** autocontido (sem JavaScript, sem recursos externos, com tema claro/escuro e impressão);
  **CSV** de achados; **CSV** da linha do tempo.
- Tudo que vem de arquivos, logs e comandos é tratado como **dado de atacante**: o HTML escapa tudo, os links ATT&CK
  só existem para IDs válidos e o CSV neutraliza células que começam com `= + - @` (injeção de fórmulas).

## Artefatos forenses
Módulo **Artefatos forenses** da varredura (janela padrão: últimos 30 dias). Lê o que o sistema já registrou;
não altera nada. Achados aparecem como tipo *Artefato*, com **Fonte** e **Quando**.

| SO | Fonte | O que procura |
|---|---|---|
| Windows | Logs de eventos (via `wevtutil`, nativo) | logs apagados (1102, 104), contas criadas (4720), membros em Administradores (4732), tarefas (4698) e serviços (7045) de pastas suspeitas, script blocks suspeitos do PowerShell (4104), força bruta (4625) seguida de logon de rede/RDP (4624) |
| Windows | Histórico do PowerShell (PSReadLine) | comandos suspeitos e limpeza de histórico |
| Windows | Prefetch | execução de ferramentas conhecidas de ataque, **só pelo nome do arquivo** `.pf` (a data do arquivo aproxima a última execução) |
| Linux | `auth.log` / `secure` (inclui rotacionados `.gz`) e, se não houver arquivo, o **journald** | força bruta de SSH, login após as falhas, root via IP público, contas criadas, grupos administrativos, comandos suspeitos via `sudo` |
| Linux | `.bash_history`, `.zsh_history`, `.sh_history`, `fish_history` (todos os usuários, se root) | comandos suspeitos, limpeza de histórico, histórico apontando para `/dev/null` |

**Artefatos exportados (forense offline)** — para analisar o que foi coletado de outra máquina
(`dupin-scan analyze ...` ou *Analisar artefato exportado…*):

| Arquivo | Como | Dependência opcional |
|---|---|---|
| `.evtx` | mesmas regras dos logs de eventos ao vivo | `python-evtx` |
| `Amcache.hve` | programas executados (entradas de `InventoryApplicationFile`) em pastas suspeitas ou ferramentas conhecidas | `regipy` |
| hive `SYSTEM` | Shimcache (AppCompatCache), com a data de modificação do arquivo, **não** a da execução | `regipy` |
| `auth.log*`, históricos, `ConsoleHost_history.txt`, `.pf` | mesmas regras do módulo ao vivo | — |

Para coletar esses arquivos numa máquina Windows, rode `tools\coletar_artefatos.ps1` num PowerShell **como
administrador**: ele só lê o sistema e grava numa pasta nova (`dupin_scan_coleta`), sem senhas, navegador nem documentos
(o resultado revela quais programas foram executados e logons: trate como dado sensível e apague depois).

Requisitos de privilégio: o log **Security** e o Prefetch só são legíveis como administrador; sem isso o Dupin-Scan
segue com o resto e avisa nas notas do relatório o que ficou de fora. Os logs *System* e
*PowerShell/Operational* costumam ser legíveis sem elevação. O log de eventos do PowerShell (4104) só existe se o
*Script Block Logging* estiver ligado, e a 4698 só se a auditoria de tarefas estiver ativa.

## Inteligência de ameaças (opcional, usa a internet)
O Dupin-Scan funciona **100% offline**. Estas funções só acessam a rede por ação explícita e confirmada
(botões em Configurações, ou `dupin-scan intel ...`):
- **Lista de hashes (MalwareBazaar):** exige uma **Auth-Key gratuita** da abuse.ch (https://auth.abuse.ch/). O endpoint
  público antigo (`bazaar.abuse.ch/export/...`) responde *410 Gone*. A lista baixada é ativada automaticamente.
- **Regras YARA (signature-base):** baixa o repositório, extrai só `.yar/.yara` (com proteção contra zip-slip e zip
  bomb), valida cada regra e descarta as inválidas; a pasta antiga só é trocada se tudo der certo.
- **VirusTotal:** consulta **um hash** por vez, depois da sua confirmação. Só o hash SHA-256 sai da máquina: nunca o
  arquivo nem o caminho. A VirusTotal registra a consulta, e "não encontrado" não significa que seja seguro.
- Chaves: na interface ficam salvas **sem criptografia** nas configurações do usuário (o campo é mascarado); prefira as
  variáveis de ambiente. As chaves nunca aparecem em mensagens de erro, em `meta.json` nem nas listas baixadas.

## Exportar regras (Sigma e YARA)
As regras saem das mesmas tabelas que o scanner usa, então não divergem do app:
```
python -m dupin_scan export-rules --out dupin-scan-rules       # sigma/*.yml + dupin-scan.yar
python -m dupin_scan export-rules --format sigma
```
Ou em **Configurações → Exportar regras de detecção**.

- **Sigma** (`process_creation`, `registry_set`, `file_event`): linhas de comando suspeitas, chave Run, pasta
  Startup, `schtasks /create` apontando para pasta suspeita e escrita em `/etc/ld.so.preload`. Cada regra leva
  as tags `attack.*`. As regexes usam `|re|i`.
- **YARA** (`dupin-scan.yar`): disfarce de documento, dupla extensão e entropia alta (usam a variável externa
  `filename`, que o Dupin-Scan já declara ao carregar regras) e uma regra por padrão de comando, para varrer scripts.
- Só viram regra as detecções com técnica ATT&CK; "pasta suspeita" sozinha é ruído demais para caça de ameaças.
- São **pontos de partida**: ajuste e meça falsos positivos no seu ambiente antes de usar em produção. Não
  carregue as regras exportadas no próprio Dupin-Scan junto com as heurísticas se não quiser achados duplicados.

## Laboratório de testes
`lab/run_lab.py` cria artefatos **inofensivos** que disparam cada detecção e confere o achado e a técnica ATT&CK:
```
python lab/run_lab.py               # seguro: arquivos numa pasta temporária
python lab/run_lab.py --registry    # Windows: também uma chave Run (HKCU) e uma tarefa agendada de teste
```
- Sem amostras de malware (e sem EICAR, para não acionar o antivírus). Arquivos são texto ou cabeçalho `MZ`.
- A persistência de usuário é simulada numa pasta temporária (`HOME`/`USERPROFILE`/`APPDATA` redirecionados) e o
  estado (ignorados/baseline) fica numa pasta de dados temporária.
- A parte forense analisa `auth.log`, históricos, Prefetch e eventos **sintéticos** (no formato real do `wevtutil`)
  em qualquer SO; no Windows também faz uma consulta real, somente leitura, ao `wevtutil`, exporta o log *System*
  para `.evtx` e confere a assinatura digital do `notepad.exe`.
- Cobre ainda: segue-o-binário, nomes parecidos e pai-filho, baseline e ignorados, relatórios com nomes hostis e a CLI
  (código de saída por gravidade) em processo separado.
- Com `--registry`, os itens usam `cmd.exe /c rem ...` (não executam nada) e são removidos ao final, mesmo
  em caso de erro. Prefira uma VM de laboratório para essa parte.
- Testa que cada regra dispara e que o mapeamento está certo. **Não** mede taxa de detecção real nem falsos
  positivos em escala.

## Desenvolvimento
```
pip install -r requirements-dev.txt
python -m pytest
```
`python-evtx` e `regipy` são opcionais; sem eles os testes correspondentes são ignorados e o Dupin-Scan avisa
"instale X" quando a função é pedida.

## Gerar o instalador

### Windows (.exe instalável)
Requisitos: Python 3.10+ e [Inno Setup 6](https://jrsoftware.org/isinfo.php) (com `iscc` no PATH).
```
packaging\build_windows.bat
```
Saídas, todas dentro do projeto:

| Arquivo | O que é |
|---|---|
| `Output\Dupin-Scan-Portatil.exe` | **interface em um único arquivo**: não instala nada, serve para pendrive ou para enviar a alguém |
| `Output\dupin-scan-cli-portatil.exe` | linha de comando em um único arquivo (sem o Qt) |
| `Output\Dupin-Scan-Setup-1.0.0.exe` | **instalador** (atalhos, menu de contexto, PATH, desinstalador) |
| `Output\SHA256SUMS.txt` | checksums dos três |
| `dist\Dupin-Scan\Dupin-Scan.exe` + `_internal\` | a mesma interface em **pasta** (abre mais rápido; não separe o `.exe` da pasta) |
| `dist\dupin-scan-cli\` | a CLI em pasta (é o que o instalador embute) |

O `.exe` único se descompacta em `%TEMP%` a cada execução (abre em cerca de 2 a 3 s; fechando normalmente ele limpa o
que criou). Encerrá-lo à força deixa uma pasta `_MEI*` no `%TEMP%`, que pode ser apagada à mão. Executáveis únicos
costumam atrair mais falsos positivos de antivírus do que os de pasta, e ainda mais sem assinatura de código.

O instalador oferece o menu de contexto **"Varrer com o Dupin-Scan"** e a CLI no PATH (ambos removidos ao desinstalar).

**Assinatura de código (opcional):** defina `DUPIN_SCAN_SIGN_CERT_NAME` com o nome de um certificado já instalado e deixe o
`signtool` no PATH; os executáveis e o instalador são assinados. Sem isso nada é assinado e o SmartScreen vai avisar.
A senha de um `.pfx` não é aceita pelo script de propósito (apareceria na lista de processos).

Sem Windows à mão ou sem querer instalar nada: suba o projeto no GitHub e rode a ação
**Build Windows** (aba Actions → Run workflow). O instalador sai como artefato para download.

### Linux (.deb)
Requisitos: Debian/Ubuntu ou derivados, python3-venv.
```
bash packaging/build_linux.sh
sudo apt install ./build/dupin-scan_1.0.0_amd64.deb
```
Instala em `/opt/dupin-scan`, cria os comandos `dupin-scan` e `dupin-scan-cli`, entrada no menu e o lançador `dupin-scan-root`.

## Privilégios
Sem Administrador/root, processos de outros usuários e pastas do sistema ficam ilegíveis.
- Windows: botão direito → Executar como administrador (ou adicione `--uac-admin` no PyInstaller).
- Linux: `dupin-scan-root` (pkexec) ou `sudo -E dupin-scan`.

## Fontes de detecção
Em **Configurações**: lista de SHA-256 (aceita CSV) e pasta com regras YARA, escolhidas por você ou baixadas pela
[inteligência de ameaças](#inteligência-de-ameaças-opcional-usa-a-internet).
O Dupin-Scan **não traz** base de assinaturas: sem essas duas fontes, só as heurísticas atuam.

## O que o Dupin-Scan não detecta
Conhecer o limite da ferramenta faz parte de usá-la bem. Um resultado sem achados **não** significa máquina limpa.

**Natureza da ferramenta**
- É uma foto do momento, não monitoramento: nada em tempo real, nada sobre o que já aconteceu e foi apagado.
- As heurísticas são óbvias por construção. Quem conhece o Dupin-Scan as contorna: sair das pastas listadas,
  ofuscar o comando, renomear, assinar o binário. Ela serve para triagem inicial e estudo, não contra um adversário dedicado.
- Há falsos positivos esperados (AppData, `/tmp`, AppImage/snap, instaladores) e falsos negativos.

**Confiança no binário**
- **Assinado não é seguro:** malware também é assinado (certificados roubados ou comprados). A confiança só abate
  heurísticas fracas; por isso hash conhecido, YARA e comandos suspeitos nunca são abrandados.
- Um binário legítimo **sem** assinatura (ferramentas internas, software livre) continua gerando alerta.
- No Linux, `rpm` só confirma a **propriedade** (não verifica a integridade), e a verificação do `dpkg` depende de o
  pacote ter `md5sums`. Binários fora de pacote (compilados localmente, AppImage) não ganham confiança.
- Cada consulta no Windows cria um subprocesso do PowerShell (cerca de 0,3 s): varreduras com muitos achados em
  binários ficam mais lentas.

**Arquivos**
- Só varre as alvos escolhidos (padrão: Downloads, Desktop, Temp e AppData no Windows; home e `/tmp` no Linux), não o disco todo.
- Ignora arquivos acima de 100 MB e links simbólicos. Magic number, entropia e conteúdo de script usam só o primeiro 1 MiB.
- Não abre compactados (zip, 7z, rar, iso) nem analisa macros de Office ou exploits em PDF.
- O conteúdo de scripts é verificado por **expressões regulares fixas**: não decodifica base64, não desofusca e não
  distingue comando executável de comentário (um script com o comando só em comentário também gera achado).
- Sem lista de hashes ou regras YARA, não reconhece malware conhecido.

**Persistência**
- O caminho do executável é extraído por **heurística de texto** (aspas, extensões conhecidas, caminhos absolutos).
  Comandos que montam o caminho em tempo de execução, variáveis não expandidas ou executáveis resolvidos pelo PATH
  não são seguidos. No Windows só extensões executáveis são seguidas (`.exe .dll .bat .cmd .ps1 .vbs .js .jar .msi .com .scr .sys .cpl .hta`).
- Windows: **não** cobre Active Setup, COM/DLL hijacking, BITS jobs persistentes, extensões de shell, provedores
  de autenticação, drivers filtrados nem o conteúdo de `.lnk` (um atalho na pasta Startup é apontado, mas o alvo dele não é lido).
  A leitura de WMI exige administrador (senão aparece só uma nota).
- Linux: **não** cobre PAM, módulos do kernel, geradores/`systemd-run` transitórios, `LD_PRELOAD` em variáveis de
  ambiente, `ld.so.conf`, hooks de APT/YUM, `sudoers` nem `~/.ssh/rc`. De `authorized_keys` só olha `command=`.
- Serviços do Windows são verificados pelo `ImagePath` do registro; serviços instalados em pastas de aplicativos
  (`ProgramData`) de software legítimo não assinado geram aviso BAIXO.

**Processos**
- A lista de nomes do Windows verificados contra o local esperado, a de nomes "parecidos" e as de relações
  pai-filho são **curtas e fixas**. Não analisa a memória (injeção, process hollowing, malware sem arquivo) nem rootkits que
  escondem processos. Um processo do sistema só é checado se o seu caminho for legível (administrador).
- Conexões de rede são checadas só para processos já suspeitos. Não há captura de tráfego, DNS nem logs de rede.

**Forense**
- *Cobertura parcial, por escolha:* o Prefetch é lido **só pelo nome** do arquivo (sem contagem de execuções,
  horários exatos nem arquivos carregados) e só reconhece uma lista curta de ferramentas conhecidas. Interpretar o
  conteúdo exige descompressão XPRESS Huffman e um parser de formato; não foi feito porque não pôde ser validado
  contra amostras reais.
- **Amcache e Shimcache:** a lógica sobre as entradas foi testada com a saída simulada do `regipy` e com um hive real
  que contém a estrutura do Amcache, **mas nunca com um `Amcache.hve` ou `SYSTEM` reais** (exigem administrador).
  Trate o resultado como não validado até testar com os seus artefatos. O Shimcache dá a data de modificação do
  arquivo, **não** a de execução.
- **`.evtx` exportado:** o `python-evtx` falhou em cerca de 5% dos registros de um log *System* real (eventos de hardware/WHEA,
  com erro de decodificação interno; o Dupin-Scan conta e avisa) e processa cerca de 150 a 180 eventos por segundo (21 MB levam
  uns 2,5 min): prefira `--days` ou exporte já filtrado. Eventos de segurança reais (1102, 4624, 4625, 4698, 4720) nunca foram
  testados com esse leitor. Sem `--days`, a janela é infinita para arquivos exportados.
- Logs de eventos ao vivo: não cobrem criação de processo (4688), Sysmon, WMI-Activity, RDP/WinRM detalhados nem
  Kerberos/NTLM. Há limite de eventos por consulta (o Dupin-Scan avisa quando é atingido) e a janela padrão é de 30 dias.
- Sem Administrador, o log **Security** (logons, contas, grupos, tarefas, limpeza de log) e o Prefetch ficam de fora.
  O Dupin-Scan só avisa nas notas: um relatório sem achados forenses pode significar "não consegui ler".
- Se o *Script Block Logging* ou a auditoria de tarefas/contas estiverem desligados, os eventos correspondentes
  simplesmente não existem: ausência de evento não é ausência de atividade.
- **Linux:** o journald e o `auth.log` foram testados só com `subprocess` e arquivos simulados (não havia Linux real).
  Não lê `wtmp`/`btmp`/`lastlog`, auditd nem logs de aplicações.
- A força bruta é medida por contagem simples (10 falhas do mesmo endereço); ataques lentos, distribuídos entre
  vários IPs ou por outros serviços (FTP, web, RDP via gateway) não aparecem.
- Históricos de shell dependem de o usuário ter ligado e salvo o histórico; shells que não gravam (ou limpos antes de
  sair) não deixam rastro. Comandos digitados em sessões ainda abertas não estão no arquivo.
- Não cobre MFT/USN, SRUM, artefatos de navegador, memória nem imagens de disco.

**Estado entre varreduras**
- "Novo" significa "nunca visto **por este Dupin-Scan neste computador**". Mudar de máquina, apagar `state.json` ou a pasta de
  dados zera o histórico. A chave de arquivos inclui caminho e hash: renomear ou mover um arquivo o torna "novo".
- Ignorar é por achado exato, não por regra: um mesmo programa em outro caminho volta a aparecer.

**Inteligência de ameaças**
- A lista da MalwareBazaar exige chave; o formato do CSV com chave **não foi verificado** (o código aceita qualquer
  token de 64 hex por linha). A resposta da VirusTotal segue a documentação da API v3, e **nunca foi chamada de verdade**
  nos testes (exige chave do usuário).
- **Regras do `signature-base`: verificado com o download real** (`intel update-yara`, 2026-11-11): 754 arquivos aceitos
  e nenhum descartado, com **5.941 regras** no total; compilam em cerca de 1,3 s. Num controle positivo (texto inofensivo
  com as strings do mimikatz) a regra `Mimikatz_Memory_Rule_1` disparou e o achado saiu ALTO. Em 299 binários do
  `System32` (arquivos limpos do Windows) houve **0 falsos positivos**, a cerca de 23 ms por arquivo. É uma amostra
  pequena de arquivos limpos de uma única máquina: não prova a taxa de falsos positivos em outros ambientes.
- A VirusTotal e a abuse.ch podem limitar, mudar ou encerrar esses serviços.

**Resposta**
- A quarentena move o arquivo; não encerra o processo, não remove a persistência e não faz remediação completa.
- macOS não é suportado (tratado como Linux).

**Regras exportadas**
- Sigma só vale onde há telemetria correspondente (ex.: Sysmon/auditoria de registro e processo).
- As regexes são as mesmas do scanner, escritas em Python: o motor do seu SIEM pode divergir em casos extremos.
  O laboratório valida o comportamento do Dupin-Scan, não o das regras em outros motores.

**Empacotamento**
- **Construídos e testados** (PyInstaller, Windows 11): o executável da **interface** (119 MB; abre, responde, recebe um
  caminho como argumento e roteia os subcomandos para a CLI mesmo sem console) e o executável da **CLI** (24 MB, sem Qt).
  Isso pegou um defeito real (a CLI quebrava sem `stdout`/`stderr`), já corrigido e coberto por teste.
- **Compilado, mas nunca executado:** o instalador do Inno Setup. O `dupin-scan.iss` (tarefas, menu de contexto, PATH e a
  seção `[Code]`) compila sem avisos com o Inno Setup 6.7.3 e gera um `Dupin-Scan-Setup-1.0.0.exe` de 43 MB, não assinado.
  O que ele faz ao ser **executado** (criar as chaves do menu de contexto, mexer no PATH, desinstalar e limpar tudo)
  não foi testado: exige administrador, e um erro no PATH do sistema é difícil de desfazer. Teste numa VM primeiro.
- **Não construídos nem testados:** a assinatura de código (`signtool` e certificado não estão disponíveis aqui) e o `.deb`
  (`packaging/build_linux.sh` foi atualizado para a CLI e o `dupin-scan-cli`, mas nunca foi executado: exige Debian/Ubuntu).
- A interface só foi vista renderizada em modo offscreen (com as fontes do Windows), nunca usada por uma pessoa numa
  sessão real, e os executáveis congelados não foram exercitados clicando na interface.

## Estrutura
```
dupin_scan/core.py          núcleo (varredura de arquivos, contexto, quarentena) - sem dependência de interface
dupin_scan/persist.py       persistência (e o binário que ela aponta) e processos
dupin_scan/forensics.py     artefatos forenses: logs ao vivo, históricos, Prefetch e artefatos exportados
tools/                 coletar_artefatos.ps1: copia Prefetch, Amcache, SYSTEM e logs de eventos (roda como administrador)
dupin_scan/trust.py         confiança no binário (assinatura digital / pacote)
dupin_scan/state.py         lista de ignorados e histórico de achados vistos
dupin_scan/timeline.py      linha do tempo e CSV (com proteção contra injeção de fórmulas)
dupin_scan/report.py        relatórios JSON, HTML e CSV
dupin_scan/intel.py         inteligência de ameaças opcional (rede só por ação explícita)
dupin_scan/attack.py        catálogo MITRE ATT&CK
dupin_scan/export_rules.py  exportação Sigma/YARA
dupin_scan/cli.py           linha de comando
dupin_scan/launcher.py      ponto de entrada: subcomandos -> CLI; o resto -> interface
dupin_scan/gui.py           interface PySide6
lab/run_lab.py         laboratório de testes com artefatos inofensivos
tests/                 testes (pytest)
packaging/             scripts de build, Inno Setup, gerador de ícones
```

## Dados do usuário
Pasta de dados: `%LOCALAPPDATA%\Dupin-Scan` (Windows) / `~/.local/share/dupin-scan` (Linux).
- `quarantine/` quarentena e índice
- `state.json` lista de ignorados e histórico de achados vistos
- `intel/` hashes e regras baixados (`hashes.txt`, `yara/`, `meta.json`)

Se o `index.json` ou o `state.json` estiverem corrompidos, o arquivo é preservado como `*.corrompido-<data>.json`
em vez de sobrescrito.

**Antes era "Vigil".** Este programa se chamou Vigil nas primeiras versões. Na primeira execução com o nome novo:
- a pasta de dados antiga (`%LOCALAPPDATA%\Vigil` / `~/.local/share/vigil`) é **renomeada** para a nova, com a
  quarentena, o histórico e as listas baixadas dentro. Se não for possível mover (arquivo em uso, sem permissão), a
  pasta antiga continua sendo usada e nada se perde;
- as configurações da interface (caminhos de hashes/YARA, chaves) são **copiadas** da chave antiga do registro
  (`HKCU\Software\Vigil`), reescrevendo os caminhos que apontavam para a pasta antiga. A chave antiga **não** é
  apagada: pode removê-la à mão se quiser.
