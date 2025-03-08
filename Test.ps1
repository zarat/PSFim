$servers = @(
    "vie-srv-dc01",
    "vie-srv-dc02",
    "vie-srv-fs03",
    "vie-srv-fs04",
    "vie-srv-ex01",
    "vie-srv-ex02"
    #"vie-srv-infra01",
    #"vie-srv-ca01"
)

foreach($server in $servers) {

    $result = Invoke-Command -ComputerName $server -ScriptBlock {

        
        # Check installed 3rd party software
        $3rdpartysoftware = """Name"";""Version""`n"
        Get-Package | where-object { $_.ProviderName -eq "Programs" -and $_.Version -ne $null } | foreach-object {
            $3rdpartysoftware += """$($_.Name)"";""$($_.Version)""`n"
        }
        #$3rdpartysoftware

        # Check services status
        $services = """Name"";""DisplayName"";""Status""`n"
        Get-Service | where-object {
            $services += """$($_.Name)"";""$($_.DisplayName)"";""$($_.Status)""`n"
        }
        #$services

        # Check network listening ports on 0.0.0.0
        $listeners = """Address"";""Port""`n"
        Get-NetTCPConnection -State Listen | where-object { $_.LocalAddress -eq "0.0.0.0"} | foreach-object {
            $listeners += """$($_.LocalAddress)"";""$($_.LocalPort)""`n"
        }
        #$listeners

        # Check ARP Table
        $arpOutput = arp -a
        $interfaces = @()
        $currentInterface = $null
        foreach ($line in $arpOutput) {
            if ($line -match "^(Schnittstelle|Interface):\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+---\s+(.+)$") {
                # Neues Interface-Objekt erstellen
                $currentInterface = [PSCustomObject]@{
                    InterfaceIP    = $matches[1]
                    InterfaceID    = $matches[2].Trim()
                    Addresses      = @()
                }
                $interfaces += $currentInterface
            }
            elseif ($line -match "^\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([\w\-\:]+)\s+(\w+)") {
                # ARP-Adressobjekt erstellen
                $address = [PSCustomObject]@{
                    IPAddress  = $matches[1]
                    MACAddress = $matches[2]
                    Type       = $matches[3]
                }
                if ($currentInterface) {
                    # Adresse zur aktuellen Schnittstelle hinzufügen
                    $currentInterface.Addresses += $address
                }
            }
        }
        $arplist = """InterfaceIP"";""arpip"";""arpmac""`n"
        foreach($if in $interfaces) {
            $arplist += "----`n"
            foreach($address in $if.Addresses) {
                $arplist += """$($if.InterfaceID)"";""$($address.IPAddress)"";""$($address.MACAddress)""`n"
            }
        }
        #$arplist

        # Get file hashes
        $fimfiles = @(
            "C:\Windows\System32\drivers\etc\hosts",
            "C:\Windows\System32\drivers\etc\networks",
            "C:\Windows\System.ini",
            "C:\Windows\Win.ini"
        )
        #$fim = """File"";""Hash""`n"
        $fim = @()
        foreach($fimfile in $fimfiles) {

            #$md5 = New-Object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
            #$utf8 = New-Object -TypeName System.Text.UTF8Encoding
            #$str = Get-Content -Path $fimfile
            #$hash = [System.BitConverter]::ToString($md5.ComputeHash($utf8.GetBytes($str)))
            $hash = (Get-FileHash (Get-Command $fimfile).Source -Algorithm MD5).Hash
            #$fim += """$($fimfile)"";""$($hash)""`n"
            $f = @{
                File = $fimfile
                Hash = $hash
            }
            $fim += [PSCustomObject]@{ 
                File = $fimfile 
                Hash = $hash
            }
        }

        $fimexecutables = @(
            "cmd.exe",
            "wmic.exe",
            "powershell.exe"
        )
        foreach($fimfile in $fimexecutables) {

            $hash = (Get-FileHash (Get-Command $fimfile).Source -Algorithm MD5).Hash
            #$fim += """$($fimfile)"";""$($hash)""`n"
            $f = @{
                File = $fimfile
                Hash = $hash
            }
            $fim += [PSCustomObject]@{ 
                File = $fimfile
                Hash = $hash 
            }
        }
        #$fim
        

        $out = @{
            "Software" = Get-Package | where-object { $_.ProviderName -eq "Programs" } | select Name, Version | ConvertTo-Json
            "Services" = Get-Service | select Name, Status | ConvertTo-Json
            "Listeners" = Get-NetTCPConnection -State Listen | select LocalAddress, LocalPort | where-object { $_.LocalAddress -eq "0.0.0.0"} | ConvertTo-Json
            "ArpList" = $interfaces | select InterfaceID, Addresses | ConvertTo-Json -Depth 5
            "Fim" = $fim | ConvertTo-Json
        }

        $out

    }

    $date = Get-Date -Format "yMd"

    mkdir ".\programs\$($date)"
    mkdir ".\programs\$($date)\$($server)"

    $result.Software | Add-Content -Path ".\programs\$($date)\$($server)\Software.txt"
    $result.Services | Add-Content -Path ".\programs\$($date)\$($server)\Services.txt"
    $result.Listeners | Add-Content -Path ".\programs\$($date)\$($server)\Listeners.txt"
    $result.ArpList | Add-Content -Path ".\programs\$($date)\$($server)\ArpList.txt"
    $result.Fim | Add-Content -Path ".\programs\$($date)\$($server)\Fim.txt"

}
