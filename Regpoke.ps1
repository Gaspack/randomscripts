
$JSON = @'
    {
      "Name": "IZ_PolicyFileDownload_10",
      "File": "",
      "DisplayName": "Allow file downloads",
      "ExplainText": "This policy setting allows you to manage whether file downloads are permitted from the zone. This option is determined by the zone of the page with the link causing the download, not the zone from which the file is delivered.\n\nIf you enable this policy setting, files can be downloaded from the zone.\n\nIf you disable this policy setting, files are prevented from being downloaded from the zone.\n\n If you do not configure this policy setting, files can be downloaded from the zone.",
      "Class": "Both",
      "Key": "Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Lockdown_Zones\\0",
      "ValueName": null,
      "Category": "inetres_IZ_LocalMachineZoneLockdown",
      "SupportedOn": null,
      "Type": null,
      "Value": null 

    }
'@
$JSON | ConvertFrom-JSON
     
# Also write all top-level properties from the extension object, excluding certain fields
     
Try {
    $parentPath = Split-Path -Path $extensionregpath -Parent
    if (-not (Test-Path -Path $parentPath)) {
        New-Item -Path $parentPath -Force -ErrorAction SilentlyContinue | Out-Null
    }
    if (-not (Test-Path -Path $extensionregpath)) {
        New-Item -Path $extensionregpath -Force -ErrorAction SilentlyContinue | Out-Null
    }

    $skipFields = @('extension_name', 'browser', 'allow_group', 'extension_guid', '3rdparty', 'deny_group')
    foreach ($prop in $ext.PSObject.Properties) {
        $pname = $prop.Name
        if ($null -eq $pname) { Continue }
        if ($skipFields -contains $pname.ToLower()) { Continue }
        $pval = $prop.Value
        if ($null -eq $pval) { $pval = '' }
        elseif ($pval -is [System.Array] ) {
            $pval = $pval | ConvertTo-Json -Compress
        }
        else {
            $pval = [string]$pval
        }
        Try {
            if (-not (Test-Path -Path $extensionregpath)) { Continue }
            New-ItemProperty -Path $extensionregpath -Name $pname -Value $pval -PropertyType 'String' -Force | Out-Null
        }
        Catch {}
    }
    $blockedVal = '["*://*"]'
    Try { New-ItemProperty -Path $extensionregpath -Name 'runtime_blocked_hosts' -Value $blockedVal -PropertyType 'String' -Force | Out-Null } Catch {}
}
Catch {}
