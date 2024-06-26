param(
    [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    [String]$FullSenseFMTTxtFilePath
)

function Get-SenseHttpClientLastResult {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]$FullSenseFMTTxtFilePath
    )

    # Read all lines from the text file
    $lines = Get-Content -Path $FullSenseFMTTxtFilePath
    # Filter lines that contain the string "SenseHttpClient"
    $senseHttpClientLines = $lines | Where-Object { $_ -match "SenseHttpClient" }
    # Filter CnC request lines
    $cncLines = $senseHttpClientLines | Where-Object { $_ -match "HttpClient created" -and $_ -match "cnc" }
    if ($cncLines.Length -eq 0) {
        Write-Host "No CNC lines found in the log file." -ForegroundColor Yellow
        return
    }

    Write-Host "CNC request lines found in the log file." -ForegroundColor Yellow
    $lastCncRequest = $cncLines | Select-Object -Last 1
    $indexOfLastCncRequest = $senseHttpClientLines.IndexOf($lastCncRequest)

    # Get the 5 lines after the last CNC request and result
    $matchingLines = $senseHttpClientLines[$indexOfLastCncRequest..($indexOfLastCncRequest + 5)]

    # Output the matching lines
    Write-Host "Last SenseHttpClient Logging:"  -ForegroundColor Yellow
    foreach ($line in $matchingLines) {
        if ($line -match "failed") {
            Write-Host $line -ForegroundColor Red
        }
        else {
            Write-Host $line -ForegroundColor Green
        }
    }

    $proxyLine = $matchingLines | Where-Object { $_ -match "proxy parameters" }
    $proxySettingString = ($proxyLine -split "proxy parameters, ")[1]
    $proxySetting = ConvertTo-SenseHttpClientResultObject -SenseHttpClientResult $proxySettingString

    Write-Host "
"
    Write-Host "Effective Proxy Setting:" -ForegroundColor Yellow
    $proxySetting | Format-Table

    $lastResult = $matchingLines | Where-Object { ($_ -match "Request Completed") -or ($_ -match "Request failed") } | Select-Object -Last 1
    $resultString = ($lastResult -split "SenseHttpClient] ")[1]
    $result = ConvertTo-SenseHttpClientResultObject -SenseHttpClientResult $resultString

    Write-Host "
"
    Write-Host "Last SenseHttpClient Result:" -ForegroundColor Yellow
    $result | Format-Table

    # Scenario: SSL inspection or SSL cert issue
    $hasSSLCertError = $lastResult | Where-Object { $_ -match "WINHTTP_CALLBACK_STATUS_FLAG_INVALID_CERT" }
    if ($hasSSLCertError.Length -gt 0) {
        Write-Host "Error Insight:" -ForegroundColor Yellow
        Write-Host "+++++++++++++++++++++++++++++" -ForegroundColor Yellow
        Write-Host "SSL Certificate Error Found!" -ForegroundColor Yellow
        Write-Host $hasSSLCertError -ForegroundColor Red
        if ($proxySetting.HasProxyConfiguration -ne 0) {
            Write-Host "Please check if the proxy server has enabled SSL inspection and disable/bypass SSL inspection for MDE endpoints." -ForegroundColor Yellow
        }
        else {
            Write-Host "Please check if winatp cert is installed on the intermediated cert path. Or it could be an SSL cert issue." -ForegroundColor Yellow
        }
        Write-Host "+++++++++++++++++++++++++++++" -ForegroundColor Yellow
    }

    # Scenario: Timed out
    $hasTimedOutError = $lastResult | Where-Object { $_ -match "12029" }
    if ($hasTimedOutError.Length -gt 0) {
        Write-Host "Error Insight:" -ForegroundColor Yellow
        Write-Host "+++++++++++++++++++++++++++++" -ForegroundColor Yellow
        Write-Host "A connection with the server could not be established due to timed out!" -ForegroundColor Yellow
        Write-Host $hasTimedOutError -ForegroundColor Red
        if ($proxySetting.HasProxyConfiguration -ne 0) {
            Write-Host "Please check the connectivity to your proxy server." -ForegroundColor Yellow
        }
        else {
            Write-Host "Please check if MDE endpoints is reachable from this device." -ForegroundColor Yellow
        }
        Write-Host "+++++++++++++++++++++++++++++" -ForegroundColor Yellow
    }

}


function ConvertTo-SenseHttpClientResultObject {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]$SenseHttpClientResult
    )
    # Split the string into key-value pairs
    $keyValuePairs = $SenseHttpClientResult -split ', '

    # Initialize an empty hashtable
    $hashTable = @{}

    # Iterate over each key-value pair
    foreach ($pair in $keyValuePairs) {
        # Split the pair into key and value
        $key, $value = $pair -split '='

        # If the value is empty, set it to $null
        if ($value -eq '') {
            $value = $null
        }

        # Add the key-value pair to the hashtable
        $hashTable[$key] = $value
    }

    # Convert the hashtable to a custom object
    $customObject = [PSCustomObject]$hashTable

    # Output the custom object
    return $customObject
}

Get-SenseHttpClientLastResult -FullSenseFMTTxtFilePath $FullSenseFMTTxtFilePath
