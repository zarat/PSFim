$token = "test"
$packages = Get-WingetPackage | where-object { $_.Source -eq 'winget' -and -not ($_.Name -like "Microsoft*" -or $_.Id -like "Microsoft*") } | Select Name
$data = $((curl https://zarat.lima-city.de/repository.php?token=$token).Content) | ConvertFrom-Json
$data | where-object { $packages -contains $_.Name }
