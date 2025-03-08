function Check-3rdPartySoftware {

    Param(
        $software
    )

    foreach ($app in $Software) {
        
        $cveCheckUrl = "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=$($app.Name)"
        $cveData = Invoke-RestMethod -Uri $cveCheckUrl -Method Get
        
        if ($cveData.totalResults -gt 0) {
            
            Write-Output "### Schwachstellen für $($app.Name) ($($app.Version))`n"
            
            $all = @()

            $cveData.vulnerabilities | foreach-object {
                
                $id = $_.cve.id
                $status = $_.cve.vulnStatus
                $score = $_.cve.metrics.cvssMetricV31.cvssData.baseScore
                $severity = $_.cve.metrics.cvssMetricV31.cvssData.baseSeverity
                $attackVector = $_.cve.metrics.cvssMetricV31.cvssData.attackVector
                $attackComplexity =$_.cve.metrics.cvssMetricV31.cvssData.attackComplexity
                $description = ($_.cve.descriptions[0].value).Trim()
                $references = $_.cve.references.url -join ', '

				#$references = $references | Select-Object -ExpandProperty url | -join "; "
				
                $o = [PSCustomObject]@{
                    Id = $id
                    Status = $status
                    Score = $score 
                    Severity = $severity
                    Vector = $attackVector
                    Complexity = $attackComplexity
                    Description = $description
                    References = $references
                }

                Write-Host "$($o.Description)`n`nReferences:`n`n$($o.References)`n`n----------`n"
                #if($o.Severity -ne $null) { $all += $o }

            }

            #$all | select Id, severity, Score, Vector #| Out-GridView

        }

    }

}

#Invoke-Command -ComputerName vie-srv-fs03 -ScriptBlock {

    #Write-Output "### Hotfixes"
    # HotFixID, Description, InstalledOn, InstalledBy
    $hotfixes | foreach-object {
        #Write-Output "$($_.HotFixID) - $($_.InstalledOn) - $($_.Description)"
    }
    
    $thirdPartySoftware = Get-WmiObject -Class Win32_Product | Where-Object { $_.Vendor -notmatch "Microsoft" }

    #$thirdPartySoftware
    
    Check-3rdPartySoftware $thirdPartySoftware

    Write-Host "Done.."

    $inp = Read-Host

