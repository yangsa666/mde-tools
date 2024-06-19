param(
    [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    [String]$FullSenseFMTTxtFilePath
)

Get-SenseHttpClientLastResult -FullSenseFMTTxtFilePath $FullSenseFMTTxtFilePath

function Get-SenseHttpClientLastResult {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]$FullSenseFMTTxtFilePath
    )

# Read all lines from the text file
$lines = Get-Content -Path $FullSenseFMTTxtFilePath

# Filter lines that contain the string "SenseHttpClient"
$matchingLines = $lines | Where-Object { $_ -match "SenseHttpClient" } | Select-Object -Last 5

# Output the matching lines
Write-Host "Last SenseHttpClient Logging:"  -ForegroundColor Yellow
foreach ($line in $matchingLines) {
    if($line -match "failed") {
        Write-Host $line -ForegroundColor Red
    } else {
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

$lastLine = $matchingLines | Select-Object -Last 1
$resultString = ($lastLine -split "SenseHttpClient] ")[1]
$result = ConvertTo-SenseHttpClientResultObject -SenseHttpClientResult $resultString

Write-Host "
"
Write-Host "Last SenseHttpClient Result:" -ForegroundColor Yellow
$result | Format-Table

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
