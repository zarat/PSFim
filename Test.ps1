# Setze den Pfad zur SQLite-Binary
$SQLitePath = "C:\chroot\\sqlite3.exe"
$datadir = ".\data"

function Test-Scan {

Param(
    $servers
)

foreach($srv in $servers) {

    $Database = "$datadir\$($srv).db"

    if (-Not (Test-Path $Database)) {
        & $SQLitePath $Database "CREATE TABLE scans (id INTEGER PRIMARY KEY, name TEXT, timestamp INTEGER);"
    }

    $result = Invoke-Command -ComputerName $srv -ScriptBlock {

        
        $3rdpartysoftware = """Name"";""Version""`n"
        Get-Package | where-object { $_.ProviderName -eq "Programs" -and $_.Version -ne $null } | foreach-object {
            $3rdpartysoftware += """$($_.Name)"";""$($_.Version)""`n"
        }
        
        $services = """Name"";""DisplayName"";""Status""`n"
        Get-Service | where-object {
            $services += """$($_.Name)"";""$($_.DisplayName)"";""$($_.Status)""`n"
        }
        
        $listeners = """Address"";""Port""`n"
        Get-NetTCPConnection -State Listen | where-object { $_.LocalAddress -eq "0.0.0.0"} | foreach-object {
            $listeners += """$($_.LocalAddress)"";""$($_.LocalPort)""`n"
        }
        
        $arpOutput = arp -a
        $interfaces = @()
        $currentInterface = $null
        foreach ($line in $arpOutput) {
            if ($line -match "^(Schnittstelle|Interface):\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+---\s+(.+)$") {
                $currentInterface = [PSCustomObject]@{
                    InterfaceIP    = $matches[1]
                    InterfaceID    = $matches[2].Trim()
                    Addresses      = @()
                    MacAddress = (get-netadapter | where-object { $_.InterfaceIndex -eq (Get-NetIPConfiguration | Where-Object { $_.IPv4Address.IPAddress -eq $matches[2] }).InterfaceIndex }).MacAddress
                }
                $interfaces += $currentInterface
            }
            elseif ($line -match "^\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([\w\-\:]+)\s+(\w+)") {
                $address = [PSCustomObject]@{
                    IPAddress  = $matches[1]
                    MACAddress = $matches[2]
                    Type       = $matches[3]
                }
                if ($currentInterface) {
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


        $fimfiles = @(
            "C:\Windows\System32\drivers\etc\hosts",
            "C:\Windows\System32\drivers\etc\networks",
            "C:\Windows\System.ini",
            "C:\Windows\Win.ini"
        )
        $fim = @()
        foreach($fimfile in $fimfiles) {

            $hash = (Get-FileHash (Get-Command $fimfile).Source -Algorithm MD5).Hash
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
            $fim += [PSCustomObject]@{ 
                File = $fimfile
                Hash = $hash 
            }
        }

        # Login- und Logoff-Ereignisse auslesen
        #$logEvents = Get-WinEvent -LogName Security -FilterHashtable @{Id=4624,4634,4647,4648} -MaxEvents 100 | ForEach-Object {
        $logEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4634,4647,4648} -MaxEvents 1000 | ForEach-Object {
            $eventData = [xml]$_.ToXml()
            $eventProps = $eventData.Event.EventData.Data

            # Benutzername extrahieren
            $username = ($eventProps | Where-Object { $_.Name -eq "TargetUserName" }).'#text'
            if (-not $username) { $username = "Unknown" }

            # Ereignistyp
            $eventType = switch ($_.Id) {
                4624 { "Login" }
                4648 { "Login" }
                4634 { "Logoff" }
                4647 { "Logoff" }
                default { "Unknown" }
            }

            $i = 0
            $_.Properties | ForEach-Object {
                #Write-Output "Index $i : $($_.Value)"
                $i++
            }

            # Ausgabe für DB
            [PSCustomObject]@{
                Timestamp  = $_.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                Type       = $_.Id #$eventType
                User       = $username
                Message = $_.Message

                #Workstation = $_.Properties[8].Value
                #LogonType = $_.Properties[10].Value
                
            }
        } | Sort-Object Timestamp #-Descending

        #$patches = $(winget update --disable-interactivity)


        function Get-Winget-Upgradables1 {
            $apps  = @()
            $start = $false

            # Remove unnecessary first lines
            winget upgrade --accept-source-agreements --include-unknown | foreach-object {
                if ( $psitem -match '^([-]+)$' ) {
                    $start = $true
                }
                elseif ( $start -eq $true ) {
                    $apps += $psitem
                }
            }

            # Remove the last line
            $apps = $apps[ 0..( $apps.length - 2 ) ]

            # Loop the array and create a custom object for each app
            $index = 0
            $apps | ForEach-Object {
                $pattern = "^(.+\u2026?)\s+([\u2026\.\w\+]+)\s+([\.\d]+)\s+([\.\d]+)\s+([\w]+)$"
        
                # Create a PowerShell custom object for each app
                $appObject = [PSCustomObject]@{
                    Name      = ($_ -replace $pattern, '$1') -replace '\s+$', ''
                    Id        = ($_ -replace $pattern, '$2')
                    Version   = ($_ -replace $pattern, '$3')
                    Available = ($_ -replace $pattern, '$4')
                    Source    = ($_ -replace $pattern, '$5')
                }

                # Add the object to the array
                $apps[$index] = $appObject
                $index += 1
            }

            return $apps
        }

        # Only works on workstations
        #$patches = Get-Winget-Upgradables1

        $out = @{
            "Software" = Get-Package | where-object { $_.ProviderName -eq "Programs" } | select Name, Version #| ConvertTo-Json
            "Services" = Get-Service | select Name, Status #| ConvertTo-Json
            "Listeners" = Get-NetTCPConnection -State Listen | select LocalAddress, LocalPort | where-object { $_.LocalAddress -eq "0.0.0.0"} #| ConvertTo-Json
            "ArpList" = $interfaces #| ConvertTo-Json -Depth 5
            "Fim" = $fim #| ConvertTo-Json
            "Log" = $logEvents
            #"Patches" = $patches
        }

        $out

    }


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

    #foreach($e in $result.Log) {
    #    if($e.Timestamp -le "2025-03-08 22:30:05") { continue }
    #    Write-Output $e #"$($e.Timestamp) - $($e.Type) - $($e.User) - $($e.LogonID) - $($e.Workstation)"
    #}

    & $SQLitePath $Database "CREATE TABLE IF NOT EXISTS eventlog (id INTEGER PRIMARY KEY, timestamp TEXT, type INTEGER, user TEXT, message TEXT);"
    # Get last timestamp
    $last_timestamp = & $SQLitePath $Database "select timestamp from eventlog order by id desc LIMIT 1;"
    $c = 0
    $result.Log | foreach-object { 
        if($_.Timestamp -le $last_timestamp) { 
            Write-Host "skipping old log"
        }
        else {
            & $SQLitePath $Database "INSERT INTO eventlog (timestamp, type, user, message) VALUES ('$($_.Timestamp)', '$($_.Type)', '$($_.User)', '$($_.Message)');"
            $c++
        }
    }
    Write-Host "[info] $($c) eventlog entries indexed"

    #foreach($e in $result.Patches) {
        #Write-Output $e #"$($e.Timestamp) - $($e.Type) - $($e.User) - $($e.LogonID) - $($e.Workstation)"
    #}

    #$result.Patches | ConvertTo-Json -Depth 5

}

}

function Test-Changes {

Param(
    $servers
)


foreach($server in $servers) {

    $Database = "$datadir\$($server).db"

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
        $servers,
        [string]$query
    )

    foreach($server in $servers) {
    
        Write-Output "`n# Running query for $server`n"
        $Database = "$datadir\$($server).db"
        #$current = & $SQLitePath $Database "SELECT MAX(id) FROM scans;"
        #& $SQLitePath $Database "SELECT * FROM $($table) where scan_id = $current;"
        & $SQLitePath $Database $query

    }

}


<#
#Test-Index -server vie-srv-ex01 -table software
#Invoke-Expression $args[0]
$servers = @(
    "vie-srv-dc01",
    "vie-srv-dc02",
    "vie-t-srv-audit"
)


#Test-Scan -servers $servers
#Test-Changes -servers $servers
Test-Index -server vie-t-srv-audit -table services
#>
