<#
.SYNOPSIS
    Script de Configuração Automatizada SipCorp - Versão 4.13 (Produção)
.DESCRIPTION
    Instala e configura Tailscale e RustDesk, enviando notificação ao Telegram ou Discord.
    Versão otimizada para produção com RustDesk.
.NOTES
    Autor: SipCorp
    Versão: 4.13.0-PROD (2025-10-06)
    # Versão 4.13.0 - Substituição do TightVNC pelo RustDesk
#>

# Definir política de execução para permitir scripts
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Bypass -Force -ErrorAction SilentlyContinue

# Autoelevar se não for administrador
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    try {
        Start-Process powershell.exe -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -ErrorAction Stop
        exit
    } catch {
        Add-Type -AssemblyName System.Windows.Forms
        [System.Windows.Forms.MessageBox]::Show(
            "Este programa requer permissões administrativas. Por favor, confirme o prompt do UAC ou execute como administrador.",
            "Erro de Permissões",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
        exit 1
    }
}

# Configuração inicial
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Exibir mensagem inicial sem acentos
if (-not [Console]::IsOutputRedirected) {
    Write-Host "Iniciando script de configuracao SipCorp..." -ForegroundColor Green
}

# Arquivo de log para debug
$logFile = Join-Path $env:TEMP "sipcorp_install.log"
function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] $Message"
    Add-Content -Path $logFile -Value $logMessage -ErrorAction SilentlyContinue
    Write-Host $logMessage -ForegroundColor Cyan
}

# Caminhos e configurações
$rustdeskInstallerPath = Join-Path $env:TEMP "rustdesk_latest.exe"
$tailscaleInstallerPath = Join-Path $env:TEMP "tailscale_latest.exe"
$credFile = Join-Path $env:APPDATA "SipCorp\sipcorp_creds.encrypted"

# Função auxiliar para salvar arquivo em UTF-8 sem BOM
function Out-FileNoBom {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][string]$Content,
        [switch]$Append
    )
    try {
        $utf8NoBom = New-Object System.Text.UTF8Encoding $false
        if ($Append -and (Test-Path $Path)) {
            $existingContent = [System.IO.File]::ReadAllText($Path, [System.Text.Encoding]::UTF8)
            $newContent = $existingContent + $Content
            [System.IO.File]::WriteAllText($Path, $newContent, $utf8NoBom)
        } else {
            [System.IO.File]::WriteAllText($Path, $Content, $utf8NoBom)
        }
    } catch {
        throw
    }
}

# Verificar permissões administrativas
function Test-AdminPrivileges {
    try {
        $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if (-not $isAdmin) {
            Add-Type -AssemblyName System.Windows.Forms
            [System.Windows.Forms.MessageBox]::Show(
                "Este programa requer permissões administrativas. Por favor, confirme o prompt do UAC ou execute como administrador.",
                "Erro de Permissões",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
            throw "Permissões administrativas necessárias"
        }
    } catch {
        throw
    }
}

# Verificar conectividade
function Test-NetworkConnectivity {
    try {
        $ping = Test-Connection -ComputerName "www.google.com" -Count 1 -Quiet -ErrorAction Stop
        if (-not $ping) {
            throw "Sem conectividade de rede"
        }
    } catch {
        throw
    }
}

# Inicializar arquivo de credenciais
function Initialize-CredentialFile {
    param([Parameter(Mandatory=$true)][string]$CredPath)
    try {
        $tailscaleKeyPlain = "KEY Tailscale"
        $discordWebhookPlain = "Webhook Disord"
        $telegramBotTokenPlain = "token telegrama"
        $telegramChatIdPlain = "Id chat telegrama"

        $creds = @{
            TailscaleKey = $tailscaleKeyPlain
            DiscordWebhook = $discordWebhookPlain
            TelegramBotToken = $telegramBotTokenPlain
            TelegramChatId = $telegramChatIdPlain
        }

        New-Item -ItemType Directory -Path (Split-Path $CredPath -Parent) -Force -ErrorAction Stop | Out-Null
        $jsonContent = $creds | ConvertTo-Json -ErrorAction Stop
        $secureContent = $jsonContent | ConvertTo-SecureString -AsPlainText -Force -ErrorAction Stop
        $encryptedContent = ConvertFrom-SecureString $secureContent -ErrorAction Stop
        Out-FileNoBom -Path $CredPath -Content $encryptedContent -ErrorAction Stop
        return $true
    } catch {
        throw
    } finally {
        $tailscaleKeyPlain = $null
        $discordWebhookPlain = $null
        $telegramBotTokenPlain = $null
        $telegramChatIdPlain = $null
        [System.GC]::Collect()
    }
}

# Gerenciar credenciais
function Get-SecureCredentials {
    try {
        if (Test-Path $credFile) {
            Remove-Item -Path $credFile -Force -ErrorAction Stop
        }
        if (-not (Initialize-CredentialFile -CredPath $credFile)) {
            throw "Falha na inicialização do arquivo de credenciais"
        }
        $encryptedContent = Get-Content $credFile -Encoding UTF8 -ErrorAction Stop
        $secureString = ConvertTo-SecureString $encryptedContent -ErrorAction Stop
        $credJson = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureString))
        $creds = $credJson | ConvertFrom-Json -ErrorAction Stop
        return $creds
    } catch {
        throw
    } finally {
        $creds = $null
        $credJson = $null
        $secureString = $null
        $encryptedContent = $null
        [System.GC]::Collect()
    }
}

# Enviar notificação para Telegram
function Send-TelegramNotification {
    param(
        [Parameter(Mandatory=$true)][string]$Message,
        [Parameter(Mandatory=$true)][string]$BotToken,
        [Parameter(Mandatory=$true)][string]$ChatId
    )
    try {
        if (-not $BotToken -or -not $ChatId) {
            return $null
        }
        $uri = "https://api.telegram.org/bot$BotToken/sendMessage"
        $body = @{
            chat_id = $ChatId
            text = $Message
            parse_mode = "Markdown"
        } | ConvertTo-Json -ErrorAction Stop
        $response = Invoke-WebRequest -Uri $uri -Method Post -Body $body -ContentType "application/json; charset=utf-8" -ErrorAction Stop
        if ($response.StatusCode -eq 200) {
            return $response.StatusCode
        }
        return $response.StatusCode
    } catch {
        return $null
    }
}

# Enviar notificação para Discord
function Send-DiscordNotification {
    param(
        [Parameter(Mandatory=$true)][string]$Message,
        [Parameter(Mandatory=$true)][string]$WebhookUrl
    )
    try {
        if (-not $WebhookUrl) {
            return $null
        }
        $uri = $WebhookUrl
        $body = @{
            embeds = @(
                @{
                    description = $Message
                    color = 0x00FF00
                }
            )
        } | ConvertTo-Json -Depth 10 -ErrorAction Stop
        $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($body)
        $response = Invoke-WebRequest -Uri $uri -Method Post -Body $bodyBytes -ContentType "application/json; charset=utf-8" -ErrorAction Stop
        if ($response.StatusCode -eq 204) {
            return $response.StatusCode
        }
        return $response.StatusCode
    } catch {
        return $null
    }
}

# Obter versão mais recente do Tailscale
function Get-LatestTailscaleVersion {
    try {
        $maxRetries = 3
        $retryCount = 0
        $retryDelay = 5
        $defaultVersion = "1.88.3"
        while ($retryCount -lt $maxRetries) {
            try {
                $response = Invoke-WebRequest -Uri "https://pkgs.tailscale.com/stable/?mode=json" -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop
                $json = $response.Content | ConvertFrom-Json -ErrorAction Stop
                $version = $json.Tailscale.Version
                if (-not $version) {
                    throw "JSON inválido"
                }
                return $version
            } catch {
                $retryCount++
                if ($retryCount -lt $maxRetries) {
                    Start-Sleep -Seconds $retryDelay
                    $retryDelay *= 2
                } else {
                    return $defaultVersion
                }
            }
        }
    } catch {
        throw
    }
}

# Obter versão mais recente do RustDesk
function Get-LatestRustDeskVersion {
    try {
        Write-Log "Buscando versao mais recente do RustDesk..."
        $response = Invoke-RestMethod -Uri "https://api.github.com/repos/rustdesk/rustdesk/releases/latest" -ErrorAction Stop
        $version = $response.tag_name -replace 'v', ''
        Write-Log "Versao encontrada: $version"
        return $version
    } catch {
        Write-Log "ERRO ao buscar versao do RustDesk: $($_.Exception.Message)"
        Write-Log "Usando versao padrao: 1.4.2"
        return "1.4.2"
    }
}

# Instalar Tailscale
function Install-Tailscale {
    try {
        $version = Get-LatestTailscaleVersion
        $downloadUrl = "https://pkgs.tailscale.com/stable/tailscale-setup-$version.exe"
        (New-Object System.Net.WebClient).DownloadFile($downloadUrl, $tailscaleInstallerPath)
        $process = Start-Process -FilePath $tailscaleInstallerPath -ArgumentList "/S" -Wait -WindowStyle Hidden -PassThru -ErrorAction Stop
        if ($process.ExitCode -ne 0) {
            throw
        }
        return $true
    } catch {
        throw
    } finally {
        if (Test-Path $tailscaleInstallerPath) {
            Remove-Item $tailscaleInstallerPath -Force -ErrorAction SilentlyContinue
        }
    }
}

# Configuração do Tailscale
function Configure-Tailscale {
    param([Parameter(Mandatory=$true)][string]$TailscaleKey)
    try {
        if (-not $TailscaleKey) {
            throw
        }
        
        $tailscalePath = "C:\Program Files\Tailscale\tailscale.exe"
        if (-not (Test-Path $tailscalePath -ErrorAction Stop)) {
            if (-not (Install-Tailscale)) {
                throw
            }
        }
        $process = Start-Process -FilePath $tailscalePath -ArgumentList "up --authkey $TailscaleKey --accept-routes --reset" -PassThru -WindowStyle Hidden -Wait -ErrorAction Stop
        if ($process.ExitCode -ne 0) {
            throw
        }
        $ip = & $tailscalePath ip -4 | Select-Object -First 1 -ErrorAction SilentlyContinue
        if (-not $ip) {
            throw
        }
        return $ip
    } catch {
        throw
    }
}

# Gerar senha aleatória
function New-RandomPassword {
    param([int]$Length = 8)
    $validChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    return -join ($validChars.ToCharArray() | Get-Random -Count $Length)
}

# Instalação e configuração do RustDesk
function Install-RustDesk {
    try {
        Write-Log "Iniciando instalacao do RustDesk..."
        
        # Remover instalação anterior do RustDesk
        Write-Log "Verificando instalacoes anteriores do RustDesk..."
        Get-Process -Name "rustdesk" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        
        # Parar e remover serviço RustDesk
        $service = Get-Service -Name "RustDesk" -ErrorAction SilentlyContinue
        if ($service) {
            Write-Log "Removendo servico RustDesk existente..."
            Stop-Service -Name "RustDesk" -Force -ErrorAction SilentlyContinue
            Start-Process -FilePath "sc.exe" -ArgumentList "delete RustDesk" -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
        }
        
        # Remover via Windows Installer
        $installedRustDesk = Get-WmiObject -Class Win32_Product -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*RustDesk*" }
        if ($installedRustDesk) {
            Write-Log "Desinstalando RustDesk via MSI..."
            foreach ($app in $installedRustDesk) {
                $guid = $app.IdentifyingNumber
                Start-Process -FilePath "msiexec.exe" -ArgumentList "/x $guid /quiet /norestart" -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 3
            }
        }
        
        # Remover pastas de configuração e instalação
        Write-Log "Removendo pastas antigas do RustDesk..."
        $foldersToRemove = @(
            "$env:APPDATA\RustDesk",
            "$env:ProgramFiles\RustDesk",
            "$env:ProgramFiles(x86)\RustDesk"
        )
        foreach ($folder in $foldersToRemove) {
            if (Test-Path $folder) {
                Remove-Item -Path $folder -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
        
        # Remover chaves do registro
        Remove-Item -Path "HKLM:\SOFTWARE\RustDesk" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "HKCU:\SOFTWARE\RustDesk" -Recurse -Force -ErrorAction SilentlyContinue
        
        Start-Sleep -Seconds 3
        
        # Obter versão mais recente
        $version = Get-LatestRustDeskVersion
        Write-Log "Preparando download do RustDesk versao $version..."
        
        # Tentar múltiplas URLs de download
        $downloadUrls = @(
            "https://github.com/rustdesk/rustdesk/releases/download/$version/rustdesk-$version-x86_64.exe",
            "https://github.com/rustdesk/rustdesk/releases/download/$version/rustdesk-$version-windows_x64.exe",
            "https://github.com/rustdesk/rustdesk/releases/latest/download/rustdesk-$version-x86_64.exe"
        )
        
        $downloadSuccess = $false
        foreach ($url in $downloadUrls) {
            try {
                Write-Log "Tentando baixar de: $url"
                (New-Object System.Net.WebClient).DownloadFile($url, $rustdeskInstallerPath)
                if ((Test-Path $rustdeskInstallerPath) -and (Get-Item $rustdeskInstallerPath).Length -gt 1MB) {
                    Write-Log "Download concluido com sucesso!"
                    $downloadSuccess = $true
                    break
                }
            } catch {
                Write-Log "Falha no download desta URL: $($_.Exception.Message)"
            }
        }
        
        if (-not $downloadSuccess) {
            throw "Falha no download do RustDesk de todas as URLs"
        }
        
        # Gerar senha permanente
        $adminPassword = New-RandomPassword -Length 8
        Write-Log "Senha administrativa gerada"
        
        # CORREÇÃO PROD: Instalar sem -Wait pra evitar hang no instalador bugado
        Write-Log "Iniciando instalacao silenciosa do RustDesk..."
        $installArgs = @("--silent-install")
        
        # Inicia sem aguardar (evita travamento)
        Start-Process -FilePath $rustdeskInstallerPath -ArgumentList $installArgs -WindowStyle Hidden
        
        Write-Log "Instalador iniciado. Aguardando completacao..."
        Start-Sleep -Seconds 30  # Espera maior pra instalador terminar (doc recomenda ~20s)
        
        # Verifica se instalou (workaround pro bug de loop)
        $rustdeskExePath = "$env:ProgramFiles\RustDesk\rustdesk.exe"
        if (-not (Test-Path $rustdeskExePath)) {
            # Tenta caminho alternativo (x86)
            $rustdeskExePath = "${env:ProgramFiles(x86)}\RustDesk\rustdesk.exe"
            if (-not (Test-Path $rustdeskExePath)) {
                throw "Falha na instalacao: rustdesk.exe nao encontrado apos espera (possivel bug no instalador)"
            }
        }
        Write-Log "Instalacao confirmada: rustdesk.exe encontrado em $rustdeskExePath"
        
        # CORREÇÃO PROD: Definir senha APÓS instalação via rustdesk.exe (suportado pela doc)
        Write-Log "Definindo senha permanente via rustdesk.exe..."
        $setPassProcess = Start-Process -FilePath $rustdeskExePath -ArgumentList "--password", $adminPassword -WindowStyle Hidden -PassThru -Wait -ErrorAction SilentlyContinue
        Write-Log "Codigo de saida ao definir senha: $($setPassProcess.ExitCode)"
        
        # Configurar RustDesk via registro e arquivos de configuração
        Write-Log "Configurando RustDesk..."
        $rustdeskConfigPath = "$env:APPDATA\RustDesk\config\RustDesk2.toml"
        $rustdeskConfigDir = Split-Path $rustdeskConfigPath -Parent
        
        if (-not (Test-Path $rustdeskConfigDir)) {
            New-Item -ItemType Directory -Path $rustdeskConfigDir -Force | Out-Null
            Write-Log "Diretorio de configuracao criado"
        }
        
        # Criar configuração TOML
        $configContent = @"
[options]
allow-direct-ip = true
allow-remote-config-modification = true
auto-update = true
password = "$adminPassword"
permanent-password = "$adminPassword"
"@
        
        Set-Content -Path $rustdeskConfigPath -Value $configContent -Encoding UTF8 -Force
        Write-Log "Arquivo de configuracao criado"
        
        # Configurar via registro (CORREÇÃO PROD: Forçar save com Stop e log)
        $regPath = "HKLM:\SOFTWARE\RustDesk"
        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
        }
        
        Set-ItemProperty -Path $regPath -Name "password" -Value $adminPassword -Type String -Force -ErrorAction Stop
        Set-ItemProperty -Path $regPath -Name "allow_direct_ip" -Value 1 -Force -ErrorAction SilentlyContinue
        Write-Log "Configuracoes do registro aplicadas (senha salva confirmada)"
        
        # Reiniciar serviço RustDesk
        $service = Get-Service -Name "RustDesk" -ErrorAction SilentlyContinue
        if ($service) {
            Write-Log "Reiniciando servico RustDesk..."
            Restart-Service -Name "RustDesk" -Force -ErrorAction SilentlyContinue
        } else {
            Write-Log "AVISO: Servico RustDesk nao encontrado"
        }
        
        # MELHORIA PROD: Pegar ID do RustDesk após instalação
        $rustdeskId = & $rustdeskExePath --get-id 2>$null | Select-Object -First 1
        if (-not $rustdeskId) {
            Write-Log "AVISO: Nao foi possivel pegar ID do RustDesk"
            $rustdeskId = "ID nao disponivel"
        } else {
            Write-Log "ID RustDesk capturado: $rustdeskId"
        }
        
        Write-Log "Instalacao do RustDesk concluida com sucesso!"
        return @{ Password = $adminPassword; Id = $rustdeskId }
    } catch {
        Write-Log "ERRO na instalacao do RustDesk: $($_.Exception.Message)"
        Write-Log "Stack trace: $($_.ScriptStackTrace)"
        throw
    } finally {
        if (Test-Path $rustdeskInstallerPath) {
            Remove-Item $rustdeskInstallerPath -Force -ErrorAction SilentlyContinue
        }
    }
}

# Fluxo principal
try {
    Write-Log "=== INICIO DA EXECUCAO ==="
    Write-Log "Usuario: $env:USERNAME"
    Write-Log "Computador: $env:COMPUTERNAME"
    
    [void](Test-AdminPrivileges)
    Write-Log "Permissoes administrativas verificadas"
    
    [void](Test-NetworkConnectivity)
    Write-Log "Conectividade de rede verificada"
    
    $computerName = $env:COMPUTERNAME
    $creds = Get-SecureCredentials
    Write-Log "Credenciais carregadas"
    
    $tailscaleKey = $creds.TailscaleKey
    $discordWebhook = $creds.DiscordWebhook
    $telegramBotToken = $creds.TelegramBotToken
    $telegramChatId = $creds.TelegramChatId
    
    if (-not $tailscaleKey) {
        throw "Credenciais inválidas: TailscaleKey ausente"
    }
    if (-not $discordWebhook) {
        throw "Credenciais inválidas: DiscordWebhook ausente"
    }
    
    Write-Log "Iniciando configuracao do Tailscale..."
    $tailscaleIP = Configure-Tailscale -TailscaleKey $tailscaleKey
    if (-not $tailscaleIP) {
        throw "Falha na configuração do Tailscale"
    }
    Write-Log "Tailscale configurado com IP: $tailscaleIP"
    
    Write-Log "Iniciando instalacao do RustDesk..."
    $rustdeskResult = Install-RustDesk
    if (-not $rustdeskResult -or -not $rustdeskResult.Password) {
        throw "Falha na configuração do RustDesk"
    }
    Write-Log "RustDesk instalado com sucesso"
    
    $successMsg = @"
CONFIGURACAO CONCLUIDA COM SUCESSO
Computador: $computerName
IP Tailscale: $tailscaleIP
Data/Hora: $(Get-Date -Format 'yyyy-MM-dd HH:mm')
CREDENCIAIS RustDesk:
ID: $($rustdeskResult.Id)
Administrativa: $($rustdeskResult.Password)
MANTER ESSAS INFORMACOES EM SEGURANCA
"@
    
    $successMsg = $successMsg -replace "ç","c" -replace "ã","a" -replace "õ","o" -replace "í","i" -replace "á","a"
    
    Write-Log "Enviando notificacoes..."
    # Loop persistente para enviar notificação
    $maxAttempts = 10
    $attempt = 1
    $notificationSent = $false
    
    while (-not $notificationSent -and $attempt -le $maxAttempts) {
        if ($telegramBotToken -and $telegramChatId) {
            $telegramStatus = Send-TelegramNotification -Message $successMsg -BotToken $telegramBotToken -ChatId $telegramChatId
            if ($telegramStatus -eq 200) {
                $notificationSent = $true
                break
            }
        }
        
        $discordStatus = Send-DiscordNotification -Message $successMsg -WebhookUrl $discordWebhook
        if ($discordStatus -eq 204) {
            $notificationSent = $true
            break
        }
        
        Start-Sleep -Seconds 10
        $attempt++
    }
    
    if (-not $notificationSent) {
        throw "Falha ao enviar notificação"
    }
    
    Write-Log "Notificacao enviada com sucesso!"
    Write-Log "=== LOG COMPLETO SALVO EM: $logFile ==="
    
    if (-not [Console]::IsOutputRedirected) {
        Write-Host "Configuracao concluida com sucesso!" -ForegroundColor Green
        Write-Host "Log salvo em: $logFile" -ForegroundColor Yellow
    } else {
        Add-Type -AssemblyName System.Windows.Forms
        [System.Windows.Forms.MessageBox]::Show(
            "Configuração concluída com sucesso! Verifique as notificações no Telegram ou Discord.",
            "Sucesso",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        )
    }
    
    exit 0
}
catch {
    Write-Log "=== ERRO CRITICO ==="
    Write-Log "Mensagem: $($_.Exception.Message)"
    Write-Log "Stack: $($_.ScriptStackTrace)"
    Write-Log "=== LOG COMPLETO SALVO EM: $logFile ==="
    
    if (-not [Console]::IsOutputRedirected) {
        Write-Host "Erro na configuracao. Contate o suporte." -ForegroundColor Red
        Write-Host "Verifique o log em: $logFile" -ForegroundColor Yellow
    } else {
        Add-Type -AssemblyName System.Windows.Forms
        [System.Windows.Forms.MessageBox]::Show(
            "Erro na configuração: $($_.Exception.Message)\nContate o suporte.",
            "Erro",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
    }
    exit 1
}
finally {
    $tailscaleKey = $null
    $discordWebhook = $null
    $telegramBotToken = $null
    $telegramChatId = $null
    $rustdeskPassword = $null
    [System.GC]::Collect()
}