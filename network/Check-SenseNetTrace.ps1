param (
    [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    [string]$NetTracePath,
    [Parameter(Mandatory = $false, Position = 1, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    [string]$ProxyAddress
)

function New-ResultObject {
    param (
        [string]$Status,
        [string]$Value,
        [string]$Logging
    )

    $resultObject = New-Object -TypeName PSObject
    $resultObject | Add-Member -MemberType NoteProperty -Name "Status" -Value $Status
    $resultObject | Add-Member -MemberType NoteProperty -Name "Value" -Value $Value
    $resultObject | Add-Member -MemberType NoteProperty -Name "Logging" -Value $Logging

    return $resultObject
}

function Check-DNS {
    param (
        [string]$Hostname
    )

    $dnsQueryResult = tshark -r $NetTracePath -Y "dns" | Where-Object { ($_ -match "$Hostname") -and ($_ -match "response") } | Select-Object -Last 1
    if ($null -eq $dnsQueryResult) {
        Write-Host "No DNS query found for $($Hostname):" -ForegroundColor Red
        $result = New-ResultObject -Status "Failed" -Value $null -Logging "No DNS query found for $($Hostname)"
        return $result
    }

    if ($dnsQueryResult -match "No such name") {
        Write-Host "DNS query result: No such name" -ForegroundColor Red
        $result = New-ResultObject -Status "Failed" -Value $null -Logging "DNS query result: No such name"
        return $result
    }

    $resolvedIpAddress = $dnsQueryResult -split "A " | Select-Object -Last 1

    Write-Host "IpAddress queryed for $($Hostname): $($resolvedIpAddress)" -ForegroundColor Yellow
    $result = New-ResultObject -Status "Success" -Value $resolvedIpAddress -Logging "IpAddress queryed for $($Hostname): $($resolvedIpAddress)"
    return $result


}

function Check-TCP {
    param (
        [string]$IpAddress
    )
    $tcpConnection = tshark -r $NetTracePath -Y "tcp and ip.addr == $($IpAddress)"
    # Scenario: Windows Firewall or 3rd party network security app may block the connection
    if ($null -eq $tcpConnection) {
        Write-Host "No TCP connection found for $($IpAddress):" -ForegroundColor Red
        $result = New-ResultObject -Status "Failed" -Value $null -Logging "No TCP connection found for $($IpAddress), maybe a firewall or 3rd party network app blocked the connection"
        return $result
    }

    # Scenario: TCP retransmission may indicate network congestion or packet loss, it could be blocked by a external firewall or NSG. Or itwas reset by the server
    $hasTCPTransnsmission = $tcpConnection | Where-Object { $_ -match 'TCP Retransmission' }
    if ($hasTCPTransnsmission.Length -gt 2) {
        Write-Host "TCP retransmission found for $($IpAddress), count: $($hasTCPTransnsmission.Length)" -ForegroundColor Red
        $result = New-ResultObject -Status "Failed" -Value $null -Logging "TCP retransmission found for $($IpAddress), count: $($hasTCPTransnsmission.Length). It could be blocked by a external firewall or NSG, or reset by the destination server."
        return $result
    }

    Write-Host "No TCP retransmission found for $($IpAddress)" -ForegroundColor Green
    $result = New-ResultObject -Status "Success" -Value $null -Logging "No TCP retransmission found for $($IpAddress)"
    return $result

}

function Is-IPv4Address {
    param (
        [string]$IpAddress
    )

    # Regular expression for matching IPv4 addresses
    $ipv4Pattern = '^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'

    return $IpAddress -match $ipv4Pattern
}

function Check-TLS {
    param (
        [string]$IpAddress
    )

    $tlsHandshake = tshark -r $NetTracePath -Y "tls and ip.addr == ${IpAddress}"
    if ($tlsHandshake.Length -gt 0) {
        Write-Host "TLS handshake found for $($IpAddress)" -ForegroundColor Green
    }
    else {
        Write-Host "TLS handshake not found for $($IpAddress)" -ForegroundColor Red
        $result = New-ResultObject -Status "Failed" -Value 'No TLS handshake' -Logging "No TLS handshake found for $($IpAddress)"
        return $result
    }

    $hasClientHello = $tlsHandshake | Where-Object { $_ -match 'Client Hello' }
    if ($hasClientHello.Length -gt 0) {
        $TlsVersion = ((($hasClientHello | Select-Object -last 1) -split "TLS")[1] -split " ")[0]
        $SNI = (($hasClientHello | Select-Object -last 1) -split "SNI=")[1] -replace ".{1}$"
        Write-Host "TLS handshake: Client Hello found for $($IpAddress)" -ForegroundColor Green
        if (($TlsVersion -eq "v1.2") -or ($TlsVersion -eq "v1.3")) {
            $TlsVersionForeGroundColor = "Green"
        }
        else {
            $TlsVersionForeGroundColor = "Red"
        }
        Write-Host "TLS version: $($TlsVersion), SNI: $($SNI)" -ForegroundColor $TlsVersionForeGroundColor
        $CipherSuites = tshark -r $NetTracePath -Y "tls.handshake.ciphersuites and ip.addr == $($IpAddress)" -Vx
        $clientCipherSuitesCountString = ($CipherSuites | Select-String -Pattern "Cipher Suite" | ForEach-Object { ($_.Line -replace "Cipher Suite: ", "").Trim() -replace "\s+", "" })[1]
        # Use a regular expression to extract the number
        $cipherSuitesNumber = [regex]::Match($clientCipherSuitesCountString, '\((\d+)suites\)').Groups[1].Value
        $clientCipherSuites = $CipherSuites | Select-String -Pattern "Cipher Suite:" | ForEach-Object { ($_.Line -replace "Cipher Suite: ", "").Trim() -replace "\s+", "" } | Select-Object -Last $cipherSuitesNumber
        $cleanedCipherSuites = $clientCipherSuites | ForEach-Object {
            $_ -replace "\(0x[0-9a-fA-F]+\)", ""
        }
        
        $supportedCipherSuites = @(
            # TLS 1.3 (suites in server-preferred order)
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
            "TLS_AES_128_GCM_SHA256",
            # TLS 1.2 (suites in server-preferred order)
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
        )
        $hasSupportedCipherSuites = $false
        $cleanedCipherSuites | ForEach-Object {
            if ($supportedCipherSuites -eq $_) {
                $hasSupportedCipherSuites = $true
                Write-Host "Supported Cipher Suite: $($_)" -ForegroundColor Green
            }
        }
        if ($hasSupportedCipherSuites -eq $false) {
            Write-Host "TLS handshake: Client Hello does not contain supported cipher suites for $($IpAddress)" -ForegroundColor Red
            Write-Host "Supported Cipher Suites:" -ForegroundColor Yellow
            Write-Host "++++++++++++++++++++++++++++" -ForegroundColor Blue
            $supportedCipherSuites | ForEach-Object {
                Write-Host $_ -ForegroundColor Blue
            }
            Write-Host "++++++++++++++++++++++++++++" -ForegroundColor Blue
            Write-Host "Client Cipher Suites:" -ForegroundColor Yellow
            Write-Host "++++++++++++++++++++++++++++" -ForegroundColor Red
            $cleanedCipherSuites | ForEach-Object {
                Write-Host $_ -ForegroundColor Red
            }
            Write-Host "++++++++++++++++++++++++++++" -ForegroundColor Red

            Write-Host "To add cipher suites, either deploy a group policy or use the TLS cmdlets:" -ForegroundColor Yellow
            Write-Host "To use group policy, configure SSL Cipher Suite Order under Computer Configuration > Administrative Templates > Network > SSL Configuration Settings with the priority list for all cipher suites you want enabled." -ForegroundColor Yellow
            Write-Host "To use PowerShell, see TLS cmdlets: https://learn.microsoft.com/en-us/powershell/module/tls/enable-tlsciphersuite?view=windowsserver2022-ps" -ForegroundColor Yellow

            $result = New-ResultObject -Status "Failed" -Value "Client CipherSuites not supported" -Logging "Client Hello does not contain supported cipher suites for $($IpAddress)"
            return $result
        }
    }
    else {
        Write-Host "TLS handshake: Client Hello not found for $($IpAddress)" -ForegroundColor Red
        $result = New-ResultObject -Status "Failed" -Value $null -Logging "No TLS handshake found for $($IpAddress)"
        return $result
    }

    $hasServerHelloDone = $tlsHandshake | Where-Object { $_ -match 'Server Hello Done' }
    $hasChangeCipherSpec = $tlsHandshake | Where-Object { $_ -match 'Change Cipher Spec' }
    $hasApplicationData = $tlsHandshake | Where-Object { $_ -match 'Application Data' }
    $hasAlert = $tlsHandshake | Where-Object { $_ -match 'Alert' }

    if ($hasApplicationData.Length -gt 0) {
        Write-Host "TLS connection is good: Application data found for $($IpAddress)" -ForegroundColor Green
        $result = New-ResultObject -Status "Success" -Value $null -Logging "TLS connection is good: Application data found for $($IpAddress)"
        return $result
    }

    if ($hasAlert.Length -gt 0) {
        $alertMessage = (($hasAlert | Select-Object -Last 1) -split "Alert ")[1]
        Write-Host "TLS connection has an issue: Alert found for $($IpAddress)" -ForegroundColor Red
        # Scenario: SSL inspection or SSL cert issue, Unknown CA error in the TLS alert
        if ($alertMessage -match "Unknown CA") {
            $alertMessage = "Unknown CA alert. Please check if the proxy server has enabled SSL inspection and disable/bypass SSL inspection for MDE endpoints." + $alertMessage
        }
        
        $result = New-ResultObject -Status "Failed" -Value ($hasAlert | Select-Object -Last 1)  -Logging $alertMessage
        return $result
    }

    if ($hasClientHello.Length -gt 0) {
        Write-Host "TLS handshake: Client Hello found for $($IpAddress)" -ForegroundColor Green
    }
    else {
        Write-Host "TLS handshake: Client Hello not found for $($IpAddress)" -ForegroundColor Red
        $result = New-ResultObject -Status "Failed" -Value $null -Logging "No Client Hello found for $($IpAddress)"
        return $result
    }

    if ($hasServerHelloDone.Length -gt 0) {
        Write-Host "TLS handshake: Server Hello Done found for $($IpAddress)" -ForegroundColor Green
    }
    else {
        Write-Host "TLS handshake: Server Hello Done not found for $($IpAddress)" -ForegroundColor Red
        $result = New-ResultObject -Status "Failed" -Value $null -Logging "No Server Hello Done found for $($IpAddress)"
        return
    }

    if ($hasChangeCipherSpec.Length -gt 0) {
        Write-Host "TLS handshake: Change Cipher Spec found for $($IpAddress)" -ForegroundColor Green
    }
    else {
        Write-Host "TLS handshake: Change Cipher Spec not found for $($IpAddress)" -ForegroundColor Red
        $result = New-ResultObject -Status "Failed" -Value $null -Logging "No Change Cipher Spec found for $($IpAddress)"
        return $result
    }
}



function Check-HTTP {
    param (
        [string]$IpAddress,
        [string]$HttpResponseUri
    )

    $httpRquest = tshark -r $NetTracePath -Y "ip.addr == $($IpAddress) and http.request.uri contains $($HttpResponseUri)"
    if ($null -eq $httpRquest) {
        Write-Host "No HTTP Request found for $($HttpResponseUri):" -ForegroundColor Red
        $result = New-ResultObject -Status "Failed" -Value "No request to the host" -Logging "No HTTP Request found for $($HttpResponseUri)"
        return $result
    }

    $httpConnection = tshark -r $NetTracePath -Y "ip.addr == $($IpAddress) and http.response_for.uri contains $($HttpResponseUri)"
    if ($null -eq $httpConnection) {
        Write-Host "No HTTP Response found for $($HttpResponseUri):" -ForegroundColor Red
        $result = New-ResultObject -Status "Failed" -Value $null -Logging "No HTTP Response found for $($HttpResponseUri)"
        return $result
    }

    # Scenario: HTTP 200 OK response returned by the proxy server. Good connection.
    $hasHTTP200 = $httpConnection | Where-Object { $_ -match '200 OK' }
    if ($hasHTTP200.Length -gt 0) {
        Write-Host "200 OK found for $($HttpResponseUri)" -ForegroundColor Red
        $result = New-ResultObject -Status "Success" -Value ($hasHTTP200 | Select-Object -Last 1) -Logging "200 OK found for $($HttpResponseUri)"
        return $result
    }
    
    # Scenario: Invalid HTTP response returned by the proxy server. Needs to check the proxy server
    $hasNonHTTP200 = $httpConnection | Where-Object { $_ -notmatch '200 OK' }
    Write-Host "No 200 OK found for $($HttpResponseUri)" -ForegroundColor Red
    $result = New-ResultObject -Status "Failed" -Value ($hasNonHTTP200 | Select-Object -Last 1) -Logging "No 200 OK found for $($HttpResponseUri)"
    return $result

}

function Check-Proxy {
    param (
        [string]$ProxyAddress,
        [string]$Hostname
    )

    $hasTls = tshark -r $NetTracePath -Y "ip.addr == $($ProxyAddress) and http.proxy_connect_host contains $($Hostname) and tls"
    if ($hasTls.Length -gt 0) {
        Write-Host "TLS handshake found for $($Hostname) in $($ProxyAddress)" -ForegroundColor Green
        $checkTlsResult = Check-TLS -IpAddress $ProxyAddress -Hostname $Hostname
        return $checkTlsResult
    }
    else {
        Write-Host "TLS handshake not found for Proxy $($ProxyAddress)" -ForegroundColor Red
        $checkHttpResult = Check-HTTP -IpAddress $ProxyAddress -HttpResponseUri $Hostname
        return $checkHttpResult
    }
}


## Direct connection
if ($null -eq $ProxyAddress -or $ProxyAddress -eq "") {
    # 1. Check DNS
    Write-Host "Checking DNS for CnC" -ForegroundColor Yellow
    $checkDnsResult = Check-DNS -Hostname "winatp"
    if ($checkDnsResult.Status -eq "Failed") {
        Write-Host $checkDnsResult.Logging -ForegroundColor Red
        return
    }

    # 2. Check TLS Succeeded handshake
    $checkTlsResult = Check-TLS -IpAddress $checkDnsResult.Value
    if ($checkTlsResult.Status -eq "Success") {
        Write-Host $checkTlsResult.Logging -ForegroundColor Green
        return
    }

    if ($checkTlsResult.Status -eq "Failed") {
        Write-Host $checkTlsResult.Logging -ForegroundColor Red

        # if No TLS handshake, check TCP connection
        if ($checkTlsResult.Value -eq "No TLS handshake") {
            # 3. Check TCP connection
            Write-Host "Checking TCP for CnC" -ForegroundColor Yellow
            $checkTcpResult = Check-TCP -IpAddress $checkDnsResult.Value

            if ($checkTcpResult.Status -eq "Failed") {
                Write-Host $checkTcpResult.Logging -ForegroundColor Red
                return
            }
        }
        return
    }
}

## Proxy connection
if ($null -ne $ProxyAddress -and $ProxyAddress -ne "") {
    $ProxyIpAddress = $ProxyAddress
    # 0. Check Proxy Address
    Write-Host "Checking Proxy Address: $($ProxyAddress)" -ForegroundColor Yellow
    if ((Is-IPv4Address -IpAddress $ProxyAddress) -eq $false) {
        Write-Host "Proxy Address is not an IP Address: $($ProxyAddress)" -ForegroundColor Yellow
        # 1. Check DNS
        $checkDnsResult = Check-DNS -Hostname $ProxyAddress
        if ($checkDnsResult.Status -eq "Failed") {
            Write-Host $checkDnsResult.Logging -ForegroundColor Red
            return
        }
        $ProxyIpAddress = $checkDnsResult.Value
    }

    # 2. Check Proxy with Check-TLS and Check-HTTP
    Write-Host "Checking Proxy" -ForegroundColor Yellow
    $checkProxyResult = Check-Proxy -ProxyAddress $ProxyIpAddress -Hostname "winatp"
    if ($checkProxyResult.Status -eq "Failed") {
        Write-Host $checkProxyResult.Logging -ForegroundColor Red
        if ($checkProxyResult.Value -eq "No request to the host") {
            # 3. Check TCP connection
            Write-Host "Checking TCP for Proxy $($ProxyIpAddress)" -ForegroundColor Yellow
            $checkTcpResult = Check-TCP -IpAddress $ProxyIpAddress

            if ($checkTcpResult.Status -eq "Failed") {
                Write-Host $checkTcpResult.Logging -ForegroundColor Red
                return
            }
        }
    }
}
