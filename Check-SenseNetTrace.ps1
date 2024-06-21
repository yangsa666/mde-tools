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

    $dnsQueryResult = tshark -r $NetTracePath -Y "dns" | Where-Object { $_ -match "$Hostname" } | Select-Object -Last 1
    if ($null -eq $dnsQueryResult) {
        Write-Host "No DNS query found for $($Hostname):" -ForegroundColor Red
        $result = New-ResultObject -Status "Failed" -Value $null -Logging "No DNS query found for $($Hostname)"
        return $result
    }

    if ($dnsQueryResult -match "No such name") {
        Write-Host "DNS query result: No such name" -ForegroundColor Red
        $result = New-ResultObject -Status "Failed" -Value $null -Logging "DNS query result: No such name"
    }

    $dnsIpAddress = $dnsQueryResult -split "A " | Select-Object -Last 1

    Write-Host "IpAddress queryed for $($Hostname):" -ForegroundColor Yellow
    $result = New-ResultObject -Status "Success" -Value $dnsIpAddress -Logging "IpAddress queryed for $($Hostname): $($dnsIpAddress)"


}

function Check-TCP {
    param (
        [string]$IpAddress
    )
    $tcpConnection = tshark -r $NetTracePath -Y "tcp and ip.addr == $($IpAddress)"
    if ($null -eq $tcpConnection) {
        Write-Host "No TCP connection found for $($IpAddress):" -ForegroundColor Red
        $result = New-ResultObject -Status "Failed" -Value $null -Logging "No TCP connection found for $($IpAddress)"
        return $result
    }

    $hasTCPTransnsmission = $tcpConnection | Where-Object { $_ -match 'TCP Retransmission' }
    if ($hasTCPTransnsmission.Length -gt 0) {
        Write-Host "TCP retransmission found for $($IpAddress), count: $($hasTCPTransnsmission.Length)" -ForegroundColor Red
        $result = New-ResultObject -Status "Failed" -Value $null -Logging "TCP retransmission found for $($IpAddress), count: $($hasTCPTransnsmission.Length)"
        return $result
    }

    Write-Host "No TCP retransmission found for $($IpAddress)" -ForegroundColor Green
    $result = New-ResultObject -Status "Success" -Value $null -Logging "No TCP retransmission found for $($IpAddress)"
    return $result

}

function Check-HTTP {
    param (
        [string]$IpAddress,
        [string]$HttpResponseUri
    )

    $httpConnection = tshark -r $NetTracePath -Y "ip.addr == $($IpAddress) and http.response_for.uri contains $($HttpResponseUri)"
    if ($null -eq $httpConnection) {
        Write-Host "No HTTP Response found for $($HttpResponseUri):" -ForegroundColor Red
        $result = New-ResultObject -Status "Failed" -Value $null -Logging "No HTTP Response found for $($HttpResponseUri)"
        return $result
    }

    $hasHTTP200 = $httpConnection | Where-Object { $_ -match '200 OK' }
    if ($hasHTTP200.Length -gt 0) {
        Write-Host "200 OK found for $($HttpResponseUri)" -ForegroundColor Red
        $result = New-ResultObject -Status "Success" -Value ($hasHTTP200 | Select-Object -Last 1) -Logging "200 OK found for $($HttpResponseUri)"
        return $result
    }

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
        $result = New-ResultObject -Status "Failed" -Value $null -Logging "No TLS handshake found for $($IpAddress)"
        return $result
    }

    $hasClientHello = $tlsHandshake | Where-Object { $_ -match 'Client Hello' }
    if ($hasClientHello.Length -gt 0) {
        $TlsVersion = (($hasClientHello | Select-Object -last 1) -split " ")[10]
        $SNI = (($hasClientHello | Select-Object -last 1) -split " ")[15]
        Write-Host "TLS handshake: Client Hello found for $($IpAddress)" -ForegroundColor Green
        Write-Host "TLS version: $($TlsVersion), SNI: $($SNI)" -ForegroundColor Yellow
        $CipherSuites = tshark -r $NetTracePath -Y "tls.handshake.ciphersuites and ip.addr == $($IpAddress)" -Vx
        $clientCipherSuites = $CipherSuites | Select-String -Pattern "Cipher Suite:" | ForEach-Object { ($_.Line -replace "Cipher Suite: ", "").Trim() -replace "\s+", "" }
        Write-Host "Client Cipher Suites:"
        $clientCipherSuites
        # TBD: Check if the cipher suites are supported
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
        Write-Host "TLS connection has an issue: Alert found for $($IpAddress)" -ForegroundColor Red
        $result = New-ResultObject -Status "Failed" -Value ($hasAlert | Select-Object -Last 1)  -Logging "TLS connection has an issue: Alert found for $($IpAddress)"
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

## Direct connection
if ($null -eq $ProxyAddress -or $ProxyAddress -eq "") {

    # 1. Check DNS
    Write-Host "Checking DNS for CnC" -ForegroundColor Yellow
    $checkDnsResult = Check-DNS -Hostname "winatp"
    if ($checkDnsResult.Status -eq "Failed") {
        Write-Host $checkDnsResult.Logging -ForegroundColor Red
        return
    }

    # 2. Check TCP connection
    Write-Host "Checking TCP for CnC" -ForegroundColor Yellow
    $checkTcpResult = Check-TCP -IpAddress $checkDnsResult.Value

    if ($checkTcpResult.Status -eq "Failed") {
        Write-Host $checkTcpResult.Logging -ForegroundColor Red
        return
    }

    # 3. Check TLS handshake
    Write-Host "Checking TLS for CnC" -ForegroundColor Yellow
    $checkTlsResult = Check-TLS -IpAddress $checkDnsResult.Value -Hostname "winatp"
    if ($checkTlsResult.Status -eq "Failed") {
        Write-Host $checkTlsResult.Logging -ForegroundColor Red
        return
    }

    if ($checkTlsResult.Status -eq "Success") {
        Write-Host $checkTlsResult.Logging -ForegroundColor Green
        return
    }

}

## Proxy connection
if ($null -ne $ProxyAddress -and $ProxyAddress -ne "") {
    $ProxyIpAddress = $ProxyAddress

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

    # 2. Check TCP connection
    Write-Host "Checking TCP for Proxy $($ProxyIpAddress)" -ForegroundColor Yellow
    $checkTcpResult = Check-TCP -IpAddress $ProxyIpAddress

    if ($checkTcpResult.Status -eq "Failed") {
        Write-Host $checkTcpResult.Logging -ForegroundColor Red
        return
    }

    # 3. Check HTTP connection
    Write-Host "Checking HTTP for Proxy" -ForegroundColor Yellow
    $checkHttpResult = Check-HTTP -IpAddress $ProxyIpAddress -HttpResponseUri "winatp"
    if ($checkHttpResult.Status -eq "Failed") {
        Write-Host $checkHttpResult.Logging -ForegroundColor Red
        return
    }
    if ($checkHttpResult.Status -eq "Success") {
        Write-Host $checkHttpResult.Logging -ForegroundColor Green
        return
    }
}
