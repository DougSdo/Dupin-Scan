<#
.SYNOPSIS
  Coleta artefatos forenses do Windows para o Dupin-Scan analisar (comando "dupin-scan analyze") ou para validar os parsers.

.DESCRIPTION
  Execute no PowerShell COMO ADMINISTRADOR. O script so LE o sistema e so ESCREVE na pasta de destino.
  Copia:
    - Prefetch\*.pf                       programas executados (nome, data)
    - Amcache.hve (+ logs de transacao)   inventario de programas executados (copia via snapshot VSS)
    - SYSTEM                              hive com o Shimcache (AppCompatCache) - via "reg save"
    - Security.evtx, System.evtx, PowerShell-Operational.evtx   somente os ultimos N dias
  NAO copia: senhas, navegadores, documentos, NTUSER.DAT, SAM, SECURITY, memoria.

  ATENCAO A PRIVACIDADE: o resultado mostra quais programas voce executou e quando, nomes de usuario e logons.
  Fica so no seu computador (nada e enviado a lugar nenhum). Apague a pasta quando terminar.

.PARAMETER Destino
  Pasta de saida. Deve NAO existir (o script nunca sobrescreve). Padrao: dupin_scan_coleta na Area de Trabalho.

.PARAMETER Dias
  Janela dos logs de eventos (padrao 30).

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\coletar_artefatos.ps1
#>
param(
    [string]$Destino = (Join-Path ([Environment]::GetFolderPath('Desktop')) 'dupin_scan_coleta'),
    [int]$Dias = 30
)
$ErrorActionPreference = 'Continue'

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) {
    Write-Host "ERRO: execute este script em um PowerShell aberto como Administrador." -ForegroundColor Red
    exit 1
}
if (Test-Path $Destino) {
    Write-Host "ERRO: '$Destino' ja existe. Escolha outro -Destino ou apague a pasta (o script nao sobrescreve)." -ForegroundColor Red
    exit 1
}
New-Item -ItemType Directory -Path $Destino | Out-Null
$log = Join-Path $Destino 'coleta.log'
function Registrar($msg) { $l = "{0:s}  {1}" -f (Get-Date), $msg; Write-Host $l; Add-Content -Path $log -Value $l }

Registrar "Coleta iniciada. Destino: $Destino | janela dos logs: $Dias dias"
$ms = [int64]$Dias * 86400000
$xpath = "*[System[TimeCreated[timediff(@SystemTime) <= $ms]]]"

# 1) Prefetch
try {
    $pf = Join-Path $Destino 'Prefetch'
    New-Item -ItemType Directory -Path $pf | Out-Null
    $arqs = Get-ChildItem "$env:SystemRoot\Prefetch" -Filter *.pf -ErrorAction Stop
    $arqs | Copy-Item -Destination $pf
    Registrar "Prefetch: $($arqs.Count) arquivos .pf copiados"
} catch { Registrar "Prefetch: FALHOU - $($_.Exception.Message)" }

# 2) Amcache.hve (arquivo em uso: copia pelo snapshot VSS com o esentutl, que ja vem no Windows)
foreach ($nome in 'Amcache.hve', 'Amcache.hve.LOG1', 'Amcache.hve.LOG2') {
    $origem = "$env:SystemRoot\appcompat\Programs\$nome"
    if (-not (Test-Path $origem)) { if ($nome -eq 'Amcache.hve') { Registrar "Amcache: $nome nao encontrado" }; continue }
    $saida = & esentutl.exe /y $origem /vss /d (Join-Path $Destino $nome) 2>&1
    if ($LASTEXITCODE -eq 0 -and (Test-Path (Join-Path $Destino $nome))) { Registrar "Amcache: $nome copiado" }
    else { Registrar "Amcache: $nome FALHOU - $($saida | Select-Object -Last 2 | Out-String)".Trim() }
}

# 3) hive SYSTEM (Shimcache)
$sys = Join-Path $Destino 'SYSTEM'
& reg.exe save HKLM\SYSTEM $sys /y 2>&1 | Out-Null
if ($LASTEXITCODE -eq 0 -and (Test-Path $sys)) { Registrar "SYSTEM: hive salvo" } else { Registrar "SYSTEM: FALHOU (codigo $LASTEXITCODE)" }

# 4) logs de eventos (somente os ultimos N dias)
foreach ($par in @(@('Security', 'Security.evtx'), @('System', 'System.evtx'),
                   @('Microsoft-Windows-PowerShell/Operational', 'PowerShell-Operational.evtx'))) {
    $saida = Join-Path $Destino $par[1]
    & wevtutil.exe epl $par[0] $saida "/q:$xpath" /ow:true 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0 -and (Test-Path $saida)) {
        Registrar ("Log {0}: exportado ({1:N1} MB)" -f $par[0], ((Get-Item $saida).Length / 1MB))
    } else { Registrar "Log $($par[0]): FALHOU (codigo $LASTEXITCODE)" }
}

# 5) integridade: SHA-256 de tudo o que foi coletado
$hashes = Get-ChildItem $Destino -Recurse -File | Where-Object { $_.Name -ne 'coleta.log' -and $_.Name -ne 'SHA256.txt' } |
    Get-FileHash -Algorithm SHA256 | ForEach-Object { "{0}  {1}" -f $_.Hash, $_.Path.Substring($Destino.Length + 1) }
$hashes | Set-Content -Path (Join-Path $Destino 'SHA256.txt') -Encoding ASCII
Registrar "Concluido: $(@($hashes).Count) arquivos. Veja coleta.log e SHA256.txt."
Write-Host "`nPronto. Pasta: $Destino" -ForegroundColor Green
