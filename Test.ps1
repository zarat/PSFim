# Setze den Pfad zur SQLite-Binary
$SQLitePath = "C:\chroot\\sqlite3.exe"

function Test-FullScan {

<#
$servers = @(
    "vie-srv-dc01",
    "vie-srv-dc02",
    #"vie-srv-fs03",
    #"vie-srv-fs04",
    #"vie-srv-ex01",
    #"vie-srv-ex02",
    #"vie-srv-infra01",
    #"vie-srv-ca01",
    "vie-t-srv-audit"
)
#>

Param(
    $servers
)

$date = Get-Date -Format "yyyyMMdd_HHmmss"
# mkdir ".\programs\$($date)"

foreach($server in $servers) {

    # Name der SQLite-Datenbank
    $Database = ".\$server.db"

    # Falls die Datei schon existiert, löschen wir sie für einen frischen Start
    if (-Not (Test-Path $Database)) {
        & $SQLitePath $Database "CREATE TABLE scans (id INTEGER PRIMARY KEY, name TEXT, timestamp INTEGER);"
    }

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
                    #MacAddress = (Get-NetIPConfiguration | Where-Object { $_.IPv4Address.IPAddress -eq $matches[1] } | Select-Object -ExpandProperty InterfaceAlias | Get-NetAdapter | Select-Object -ExpandProperty MacAddress)
                    MacAddress = (get-netadapter | where-object { $_.InterfaceIndex -eq (Get-NetIPConfiguration | Where-Object { $_.IPv4Address.IPAddress -eq $matches[2] }).InterfaceIndex }).MacAddress
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
            "Software" = Get-Package | where-object { $_.ProviderName -eq "Programs" } | select Name, Version #| ConvertTo-Json
            "Services" = Get-Service | select Name, Status #| ConvertTo-Json
            "Listeners" = Get-NetTCPConnection -State Listen | select LocalAddress, LocalPort | where-object { $_.LocalAddress -eq "0.0.0.0"} #| ConvertTo-Json
            "ArpList" = $interfaces #| ConvertTo-Json -Depth 5
            "Fim" = $fim #| ConvertTo-Json
        }

        $out

    }

    #mkdir ".\programs\$($date)\$($server)"
    <#
    $result.Software | Add-Content -Path ".\programs\$($date)\$($server)\Software.txt"
    $result.Services | Add-Content -Path ".\programs\$($date)\$($server)\Services.txt"
    $result.Listeners | Add-Content -Path ".\programs\$($date)\$($server)\Listeners.txt"
    $result.ArpList | Add-Content -Path ".\programs\$($date)\$($server)\ArpList.txt"
    $result.Fim | Add-Content -Path ".\programs\$($date)\$($server)\Fim.txt"
    #>

    $last = & $SQLitePath $Database "INSERT INTO scans (name, timestamp) VALUES ('Test', strftime('%s', 'now'));SELECT last_insert_rowid();"
    Write-Host "[info] Start indexing $($server)"

    & $SQLitePath $Database "CREATE TABLE IF NOT EXISTS software (id INTEGER PRIMARY KEY, scan_id INTEGER, name TEXT, version TEXT);"
    $c = 0
    $result.Software | foreach-object { 
        & $SQLitePath $Database "INSERT INTO software (scan_id, name, version) VALUES ('$($last)', '$($_.Name)', '$($_.Version)');"
        $c++
    }
    Write-Host "[info] $($c) software packages indexed"

    & $SQLitePath $Database "CREATE TABLE IF NOT EXISTS services (id INTEGER PRIMARY KEY, scan_id INTEGER, name TEXT, status TEXT);"
    $c = 0
    $result.Services | foreach-object { 
        & $SQLitePath $Database "INSERT INTO services (scan_id, name, status) VALUES ('$($last)', '$($_.Name)', '$($_.Status)');"
        $c++
    }
    Write-Host "[info] $($c) services indexed"

    & $SQLitePath $Database "CREATE TABLE IF NOT EXISTS listeners (id INTEGER PRIMARY KEY, scan_id INTEGER, port TEXT);"
    $c = 0
    $result.Listeners | foreach-object { 
        & $SQLitePath $Database "INSERT INTO listeners (scan_id, port) VALUES ('$($last)', '$($_.LocalPort)');"
        $c++
    }
    Write-Host "[info] $($c) listeners indexed"

    & $SQLitePath $Database "CREATE TABLE IF NOT EXISTS arplist (id INTEGER PRIMARY KEY, scan_id INTEGER, if TEXT, ip TEXT, mac TEXT);"
    $c = 0
    foreach($if in $result.ArpList) { 
        $addresses = $if.Addresses
        foreach($addr in $addresses) {
            & $SQLitePath $Database "INSERT INTO arplist (scan_id, if, ip, mac) VALUES ('$($last)', '$($if.InterfaceID)', '$($addr.IPAddress)', '$($addr.MACAddress)');"
            $c++
        }
    }
    Write-Host "[info] $($c) arp entries indexed"

    & $SQLitePath $Database "CREATE TABLE IF NOT EXISTS fim (id INTEGER PRIMARY KEY, scan_id INTEGER, name TEXT, hash TEXT);"
    $c = 0
    $result.Fim | foreach-object { 
        & $SQLitePath $Database "INSERT INTO fim (scan_id, name, hash) VALUES ('$($last)', '$($_.File)', '$($_.Hash)');"
        $c++
    }
    Write-Host "[info] $($c) fim entries indexed"

    <#
    & $SQLitePath $Database "SELECT * FROM software;"
    & $SQLitePath $Database "SELECT * FROM services;"
    & $SQLitePath $Database "SELECT * FROM listeners;"
    & $SQLitePath $Database "SELECT * FROM arplist;"
    & $SQLitePath $Database "SELECT * FROM fim;"
    & $SQLitePath $Database "SELECT * FROM scans;"
    #>

    <#
    $current = $last
    $last = $current - 1

    Write-Host "###### UNTERSCHIEDE #####"

    Write-Host "# SOFTWARE"
    & $SQLitePath $Database "
    SELECT * FROM software
    WHERE (name, version) NOT IN (
        SELECT name, version FROM software WHERE scan_id = $last
    ) AND scan_id = $current;
    "

    Write-Host "# SERVICES"
    & $SQLitePath $Database "
    SELECT * FROM services
    WHERE (name, status) NOT IN (
        SELECT name, status FROM services WHERE scan_id = $last
    ) AND scan_id = $current;
    "

    

    Write-Host "# NEW LISTENERS"
    & $SQLitePath $Database "
    SELECT * FROM listeners
    WHERE (port) NOT IN (
        SELECT port FROM listeners WHERE scan_id = $last
    ) AND scan_id = $current;
    "

    Write-Host "# DISAPPEARED LISTENERS"
    & $SQLitePath $Database "
    SELECT * FROM listeners
    WHERE (port) NOT IN (
        SELECT port FROM listeners WHERE scan_id = $current
    ) AND scan_id = $last;
    "

    Write-Host "# NEW ARP ENTRIES"
    & $SQLitePath $Database "
    SELECT * FROM arplist
    WHERE (if, ip, mac) NOT IN (
        SELECT if, ip, mac FROM arplist WHERE scan_id = $last
    ) AND scan_id = $current;
    "

    Write-Host "# DISAPPEARED ARP ENTRIES"
    & $SQLitePath $Database "
    SELECT * FROM arplist
    WHERE (if, ip, mac) NOT IN (
        SELECT if, ip, mac FROM arplist WHERE scan_id = $current
    ) AND scan_id = $last;
    "

    Write-Host "# FIM"
    & $SQLitePath $Database "
    SELECT * FROM fim
    WHERE (name, hash) NOT IN (
        SELECT name, hash FROM fim WHERE scan_id = $last
    ) AND scan_id = $current;
    "
    #>

}

}

function Test-Scan {

<#
Param(
    [string]$server  
)

$servers = @(
    $server
)
#>

Param(
    $servers
)


$date = Get-Date -Format "yyyyMMdd_HHmmss"
# mkdir ".\programs\$($date)"

foreach($srv in $servers) {

    # Name der SQLite-Datenbank
    $Database = ".\$srv.db"

    # Falls die Datei schon existiert, löschen wir sie für einen frischen Start
    if (-Not (Test-Path $Database)) {
        & $SQLitePath $Database "CREATE TABLE scans (id INTEGER PRIMARY KEY, name TEXT, timestamp INTEGER);"
    }

    $result = Invoke-Command -ComputerName $srv -ScriptBlock {

        
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
                    #MacAddress = (Get-NetIPConfiguration | Where-Object { $_.IPv4Address.IPAddress -eq $matches[1] } | Select-Object -ExpandProperty InterfaceAlias | Get-NetAdapter | Select-Object -ExpandProperty MacAddress)
                    MacAddress = (get-netadapter | where-object { $_.InterfaceIndex -eq (Get-NetIPConfiguration | Where-Object { $_.IPv4Address.IPAddress -eq $matches[2] }).InterfaceIndex }).MacAddress
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
            "Software" = Get-Package | where-object { $_.ProviderName -eq "Programs" } | select Name, Version #| ConvertTo-Json
            "Services" = Get-Service | select Name, Status #| ConvertTo-Json
            "Listeners" = Get-NetTCPConnection -State Listen | select LocalAddress, LocalPort | where-object { $_.LocalAddress -eq "0.0.0.0"} #| ConvertTo-Json
            "ArpList" = $interfaces #| ConvertTo-Json -Depth 5
            "Fim" = $fim #| ConvertTo-Json
        }

        $out

    }

    #mkdir ".\programs\$($date)\$($server)"
    <#
    $result.Software | Add-Content -Path ".\programs\$($date)\$($server)\Software.txt"
    $result.Services | Add-Content -Path ".\programs\$($date)\$($server)\Services.txt"
    $result.Listeners | Add-Content -Path ".\programs\$($date)\$($server)\Listeners.txt"
    $result.ArpList | Add-Content -Path ".\programs\$($date)\$($server)\ArpList.txt"
    $result.Fim | Add-Content -Path ".\programs\$($date)\$($server)\Fim.txt"
    #>

    $last = & $SQLitePath $Database "INSERT INTO scans (name, timestamp) VALUES ('Test', strftime('%s', 'now'));SELECT last_insert_rowid();"
    Write-Host "[info] Start indexing $($srv)"

    & $SQLitePath $Database "CREATE TABLE IF NOT EXISTS software (id INTEGER PRIMARY KEY, scan_id INTEGER, name TEXT, version TEXT);"
    $c = 0
    $result.Software | foreach-object { 
        & $SQLitePath $Database "INSERT INTO software (scan_id, name, version) VALUES ('$($last)', '$($_.Name)', '$($_.Version)');"
        $c++
    }
    Write-Host "[info] $($c) software packages indexed"

    & $SQLitePath $Database "CREATE TABLE IF NOT EXISTS services (id INTEGER PRIMARY KEY, scan_id INTEGER, name TEXT, status TEXT);"
    $c = 0
    $result.Services | foreach-object { 
        & $SQLitePath $Database "INSERT INTO services (scan_id, name, status) VALUES ('$($last)', '$($_.Name)', '$($_.Status)');"
        $c++
    }
    Write-Host "[info] $($c) services indexed"

    & $SQLitePath $Database "CREATE TABLE IF NOT EXISTS listeners (id INTEGER PRIMARY KEY, scan_id INTEGER, port TEXT);"
    $c = 0
    $result.Listeners | foreach-object { 
        & $SQLitePath $Database "INSERT INTO listeners (scan_id, port) VALUES ('$($last)', '$($_.LocalPort)');"
        $c++
    }
    Write-Host "[info] $($c) listeners indexed"

    & $SQLitePath $Database "CREATE TABLE IF NOT EXISTS arplist (id INTEGER PRIMARY KEY, scan_id INTEGER, if TEXT, ip TEXT, mac TEXT);"
    $c = 0
    foreach($if in $result.ArpList) { 
        $addresses = $if.Addresses
        foreach($addr in $addresses) {
            & $SQLitePath $Database "INSERT INTO arplist (scan_id, if, ip, mac) VALUES ('$($last)', '$($if.InterfaceID)', '$($addr.IPAddress)', '$($addr.MACAddress)');"
            $c++
        }
    }
    Write-Host "[info] $($c) arp entries indexed"

    & $SQLitePath $Database "CREATE TABLE IF NOT EXISTS fim (id INTEGER PRIMARY KEY, scan_id INTEGER, name TEXT, hash TEXT);"
    $c = 0
    $result.Fim | foreach-object { 
        & $SQLitePath $Database "INSERT INTO fim (scan_id, name, hash) VALUES ('$($last)', '$($_.File)', '$($_.Hash)');"
        $c++
    }
    Write-Host "[info] $($c) fim entries indexed"

    <#
    & $SQLitePath $Database "SELECT * FROM software;"
    & $SQLitePath $Database "SELECT * FROM services;"
    & $SQLitePath $Database "SELECT * FROM listeners;"
    & $SQLitePath $Database "SELECT * FROM arplist;"
    & $SQLitePath $Database "SELECT * FROM fim;"
    & $SQLitePath $Database "SELECT * FROM scans;"
    #>

    <#
    $current = $last
    $last = $current - 1

    Write-Host "###### UNTERSCHIEDE #####"

    Write-Host "# SOFTWARE"
    & $SQLitePath $Database "
    SELECT * FROM software
    WHERE (name, version) NOT IN (
        SELECT name, version FROM software WHERE scan_id = $last
    ) AND scan_id = $current;
    "

    Write-Host "# SERVICES"
    & $SQLitePath $Database "
    SELECT * FROM services
    WHERE (name, status) NOT IN (
        SELECT name, status FROM services WHERE scan_id = $last
    ) AND scan_id = $current;
    "

    

    Write-Host "# NEW LISTENERS"
    & $SQLitePath $Database "
    SELECT * FROM listeners
    WHERE (port) NOT IN (
        SELECT port FROM listeners WHERE scan_id = $last
    ) AND scan_id = $current;
    "

    Write-Host "# DISAPPEARED LISTENERS"
    & $SQLitePath $Database "
    SELECT * FROM listeners
    WHERE (port) NOT IN (
        SELECT port FROM listeners WHERE scan_id = $current
    ) AND scan_id = $last;
    "

    Write-Host "# NEW ARP ENTRIES"
    & $SQLitePath $Database "
    SELECT * FROM arplist
    WHERE (if, ip, mac) NOT IN (
        SELECT if, ip, mac FROM arplist WHERE scan_id = $last
    ) AND scan_id = $current;
    "

    Write-Host "# DISAPPEARED ARP ENTRIES"
    & $SQLitePath $Database "
    SELECT * FROM arplist
    WHERE (if, ip, mac) NOT IN (
        SELECT if, ip, mac FROM arplist WHERE scan_id = $current
    ) AND scan_id = $last;
    "

    Write-Host "# FIM"
    & $SQLitePath $Database "
    SELECT * FROM fim
    WHERE (name, hash) NOT IN (
        SELECT name, hash FROM fim WHERE scan_id = $last
    ) AND scan_id = $current;
    "
    #>

}

}

function Test-Changes {

Param(
    $servers
)
<#
$servers = @(
    "vie-srv-dc01",
    "vie-srv-dc02",
    #"vie-srv-fs03",
    #"vie-srv-fs04",
    #"vie-srv-ex01",
    #"vie-srv-ex02",
    #"vie-srv-infra01",
    #"vie-srv-ca01",
    "vie-t-srv-audit"
)
#>

foreach($server in $servers) {

    $Database = ".\$($server).db"

    $current = & $SQLitePath $Database "SELECT MAX(id) FROM scans;"
    $last = & $SQLitePath $Database "SELECT MAX(id - 1) FROM scans;"

    Write-Host "#####`n##### UNTERSCHIEDE auf $($server) #####`n#####"

    Write-Host "# SOFTWARE"
    & $SQLitePath $Database "
    SELECT * FROM software
    WHERE (name, version) NOT IN (
        SELECT name, version FROM software WHERE scan_id = $last
    ) AND scan_id = $current;
    "

    Write-Host "# SERVICES"
    & $SQLitePath $Database "
    SELECT * FROM services
    WHERE (name, status) NOT IN (
        SELECT name, status FROM services WHERE scan_id = $last
    ) AND scan_id = $current;
    "

    

    Write-Host "# NEW LISTENERS"
    & $SQLitePath $Database "
    SELECT * FROM listeners
    WHERE (port) NOT IN (
        SELECT port FROM listeners WHERE scan_id = $last
    ) AND scan_id = $current;
    "

    Write-Host "# DISAPPEARED LISTENERS"
    & $SQLitePath $Database "
    SELECT * FROM listeners
    WHERE (port) NOT IN (
        SELECT port FROM listeners WHERE scan_id = $current
    ) AND scan_id = $last;
    "

    Write-Host "# NEW ARP ENTRIES"
    & $SQLitePath $Database "
    SELECT * FROM arplist
    WHERE (if, ip, mac) NOT IN (
        SELECT if, ip, mac FROM arplist WHERE scan_id = $last
    ) AND scan_id = $current;
    "

    Write-Host "# DISAPPEARED ARP ENTRIES"
    & $SQLitePath $Database "
    SELECT * FROM arplist
    WHERE (if, ip, mac) NOT IN (
        SELECT if, ip, mac FROM arplist WHERE scan_id = $current
    ) AND scan_id = $last;
    "

    Write-Host "# FIM"
    & $SQLitePath $Database "
    SELECT * FROM fim
    WHERE (name, hash) NOT IN (
        SELECT name, hash FROM fim WHERE scan_id = $last
    ) AND scan_id = $current;
    "
    
}

}

function Test-Index {

    Param(
        [string]$server,
        [string]$table
    )

    $Database = ".\$($server).db"

    $current = & $SQLitePath $Database "SELECT MAX(id) FROM scans;"

    & $SQLitePath $Database "SELECT name FROM $($table) where scan_id = $current;"

}

#Test-Index -server vie-srv-ex01 -table software
#Invoke-Expression $args[0]
$servers = @(
    #"vie-srv-dc01",
    #"vie-srv-dc02",
    "vie-t-srv-audit"
)

#Test-FullScan -servers $servers
Test-Scan -servers $servers
Test-Changes -servers $servers
