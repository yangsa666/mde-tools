param (
    [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    [string]$NetTracePath,
    [Parameter(Mandatory = $false, Position = 1, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    [string]$proxyAddress
)


function Check-DNS {
    param (
        [string]$hostname
    )

    $dnsQueryResult = tshark -r $NetTracePath -Y "dns" | Where-Object { $_ -match "$hostname"} | Select-Object -Last 1
    if ($null -eq $dnsQueryResult) {
        Write-Host "No DNS query found for $($hostname):" -ForegroundColor Red
        return
    }

    if ($dnsQueryResult -match "No such name") {
        Write-Host "DNS query result: No such name" -ForegroundColor Red
        $dnsQueryResult
        return
    }

    $dnsIpAddress = $dnsQueryResult -split "A " | Select-Object -Last 1

    Write-Host "IpAddress queryed for $($hostname):" -ForegroundColor Yellow
    $dnsIpAddress

}

function Check-TCP {
    param (
        [string]$ipAddress
    )

    $tcpConnection = tshark -r $NetTracePath -Y "tcp and ip.addr == ${ipAddress}"
    if ($null -eq $tcpConnection) {
        Write-Host "No TCP connection found for $($ipAddress):" -ForegroundColor Red
        return
    }

    $hasTCPTransnsmission = $tcpConnection | Where-Object { $_ -match 'TCP Retransmission'}
    if ($hasTCPTransnsmission.Length -gt 0) {
        Write-Host "TCP retransmission found for $($ipAddress), count: $($hasTCPTransnsmission.Length)" -ForegroundColor Red
        return
    }

    Write-Host "No TCP retransmission found for $($ipAddress)" -ForegroundColor Green

}

function Check-HTTP {
    param (
        [string]$ipAddress,
        [string]$httpQuery
    )

    $httpConnection = tshark -r $NetTracePath -Y "http and ip.addr == $(${ipAddress}) and _ws.col.info contains $(${httpQuery})"
    if ($null -eq $httpConnection) {
        Write-Host "No HTTP connection found for $($ipAddress):" -ForegroundColor Red
        return
    }

    $hasHTTP200 = $httpConnection | Where-Object { $_ -match '200 OK'}
    if ($hasHTTP200.Length -gt 0) {
        Write-Host "No HTTP/1.1 200 OK found for $($ipAddress)" -ForegroundColor Red
        return
    }

}

function Is-IPv4Address {
    param (
        [string]$ipAddress
    )

    # Regular expression for matching IPv4 addresses
    $ipv4Pattern = '^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'

    return $ipAddress -match $ipv4Pattern
}

function Check-TLS {
    param (
        [string]$ipAddress
    )

    $tlsHandshake = tshark -r $NetTracePath -Y "tls and ip.addr == ${ipAddress}"
    if ($tlsHandshake.Length -gt 0) {
        Write-Host "TLS handshake found for $($ipAddress)" -ForegroundColor Green
    } else {
        Write-Host "TLS handshake not found for $($ipAddress)" -ForegroundColor Red
        return
    }

    $hasClientHello = $tlsHandshake | Where-Object { $_ -match 'Client Hello'}
    if ($hasClientHello.Length -gt 0) {
        $TlsVersion = (($hasClientHello | Select-Object -last 1) -split " ")[10]
        $SNI = (($hasClientHello | Select-Object -last 1) -split " ")[15]
        Write-Host "TLS handshake: Client Hello found for $($ipAddress)" -ForegroundColor Green
        Write-Host "TLS version: $($TlsVersion), SNI: $($SNI)" -ForegroundColor Yellow
        $CipherSuites = tshark -r $NetTracePath -Y "tls.handshake.ciphersuites and ip.addr == $($ipAddress)" -Vx
        $clientCipherSuites = $CipherSuites | Select-String -Pattern "Cipher Suite:" | ForEach-Object {($_.Line -replace "Cipher Suite: ", "").Trim() -replace "\s+", ""}
        Write-Host "Client Cipher Suites:"
        $clientCipherSuites
    } else {
        Write-Host "TLS handshake: Client Hello not found for $($ipAddress)" -ForegroundColor Red
    }

    $hasServerHelloDone = $tlsHandshake | Where-Object { $_ -match 'Server Hello Done'}
    $hasChangeCipherSpec = $tlsHandshake | Where-Object { $_ -match 'Change Cipher Spec'}
    $hasApplicationData = $tlsHandshake | Where-Object { $_ -match 'Application Data'}
    $hasAlert = $tlsHandshake | Where-Object { $_ -match 'Alert'}

    if ($hasApplicationData.Length -gt 0) {
        Write-Host "TLS connection is good: Application data found for $($ipAddress)" -ForegroundColor Green
        return
    }

    if ($hasAlert.Length -gt 0) {
        Write-Host "TLS connection has an issue: Alert found for $($ipAddress)" -ForegroundColor Red
        return
    }

    if ($hasClientHello.Length -gt 0) {
        Write-Host "TLS handshake: Client Hello found for $($ipAddress)" -ForegroundColor Green
    } else {
        Write-Host "TLS handshake: Client Hello not found for $($ipAddress)" -ForegroundColor Red
        return
    }

    if ($hasServerHelloDone.Length -gt 0) {
        Write-Host "TLS handshake: Server Hello Done found for $($ipAddress)" -ForegroundColor Green
    } else {
        Write-Host "TLS handshake: Server Hello Done not found for $($ipAddress)" -ForegroundColor Red
        return
    }

    if ($hasChangeCipherSpec.Length -gt 0) {
        Write-Host "TLS handshake: Change Cipher Spec found for $($ipAddress)" -ForegroundColor Green
    } else {
        Write-Host "TLS handshake: Change Cipher Spec not found for $($ipAddress)" -ForegroundColor Red
        return
    }
}

## Direct connection
# 1. Check DNS

# 2. Check TCP connection

# 3. Check TLS handshake
## TBD

## Proxy connection

# 1. Check DNS if the proxy is not set with IP address

# 2. Check TCP connection

# 3. Check HTTP