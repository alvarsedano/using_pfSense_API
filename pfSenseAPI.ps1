# Consumiendo pfSense rest-api
# https://github.com/jaredhendrickson13/pfsense-api

#TLS 1.2 para Invoke-RestMethod
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12


Function irmDesktop($method, $uri, $head, $body, $ct) {
    Invoke-RestMethod -Method $method -Uri $uri -Headers $head -Body $body -ContentType $ct
}

Function irmCore($method, $uri, $head, $body, $ct) {
    Invoke-RestMethod -Method $method -Uri $uri -Headers $head -Body $body -ContentType $ct -SkipCertificateCheck:$true
}

#Aceptar certificados autofirmados/expirados/inválidos
if ($PSEdition -ne 'Core') {
add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
[System.Net.ServicePointManager]::CertificatePolicy = [TrustAllCertsPolicy]::new()
New-Alias -name 'irm2' -Value 'irmDesktop' -Scope Local -Force -ErrorAction SilentlyContinue
}
else {
    #TODO Skip certificate check     
    New-Alias -name 'irm2' -Value 'irmCore' -Scope Local -Force -ErrorAction SilentlyContinue
}

# LA CHICHA
#
class pfsession : IDisposable {
    [string]$baseURI
    [string]$lastToken
    hidden [string]$contentType = 'application/json'
    hidden [HashTable]$headers = @{Accept        = 'application/json';
                                   Authorization = ''   }
    hidden [PSCredential]$cred
    hidden [hashTable]$funcionesGet = @{GetInterfaces    = 'interface';
                                        GetFwAliases     = 'firewall/alias';
                                        GetFwRules       = 'firewall/rule';
                                        GetFwVirtualIPs  = 'firewall/virtual_ip';
                                        GetFwNatOutbound = 'firewall/nat/outbound';
                                        GetNatPFwd       = 'firewall/nat/port_forward';
                                        GetGateways      = 'routing/gateway/';
                                        GetServices      = 'services';
                                        GetHostName      = 'system/hostname';
                                        GetCAs           = 'system/ca';
                                        GetCerts         = 'system/certificate';
                                        GetConfig        = 'system/config';
                                        GetArp           = 'system/arp';
                                        GetUsers         = 'user' }
    #TODO: manage token expiration

    # constrúúúctor
    #
    pfsession([string]$pfSenseBaseURI,[PSCredential]$credentials) {
        $this.cred = $credentials
        $this.baseURI = $pfSenseBaseURI
        if ($pfSenseBaseURI -match '\/$') {
            $this.baseURI += 'api/v1/'
        }
        else {
            $this.baseURI += '/api/v1/'
        }
        $this.GetToken()
    }

    # destrúúúctor
    #
    [void] Dispose() {
        if ($null -ne $this.cred -and $null -ne $this.cred.Password) {
            #Eliminar la password de las credenciales de acceso
            $this.cred.Password.Clear()
            $this.cred.Password.Dispose()
        }

        #Solo para hacer entender que ha sido destruido
        $this.lastToken = ''
        $this.baseURI = ''
    }

    [string] uri([string]$rel) {
        return "$($this.baseURI)$($rel)"
    }

    # Get pfSense token (JWT mode)
    # Saved in lastToken
    #
    [void] GetToken() {
        [string]$relUri = 'access_token'
        [hashTable]$cab = @{Accept = 'application/json'}

        $usr = $this.cred.UserName
        $pas = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($this.cred.Password))
        [string]$body = "{`"client-id`":`"$($usr)`",`"client-token`":`"$($pas)`"}"

        #$respuesta = Invoke-RestMethod -Method Post -Uri $this.uri($relUri) -Headers $cab -Body $body -ContentType $this.contentType
        $respuesta = irm2 -method Post -uri $this.uri($relUri) -head $cab -Body $body -ct $this.contentType
        if ($respuesta.code -eq 200) {
            # Token ok
            $this.lastToken = $respuesta.data.token
            $this.headers.Authorization = "Bearer $($this.lastToken)"
        }
        else {
            $this.lastToken = ''
            $this.headers.Authorization = ''
        }
    }

    # Get Functions
    # Returns a PSObject/PSObject array
    #
    [PSObject] GetFunction([string]$function) {
        $f = $this.funcionesGet.$function
        if ($f) {
            #$respuesta = Invoke-RestMethod -Method Get -Uri $this.uri($f) -Headers $this.headers -ContentType $this.contentType
            $respuesta = irm2 -method Get -uri $this.uri($f) -head $this.headers -ct $this.contentType
            if ($respuesta.code -eq 200) {
                return $respuesta.data
            }
            else {
                return $null
            }
        }
        else {
            return $null
        }
    }

    # Get pfSense Interfaces
    # Returns a PSObject
    #
    [PSObject] GetInterfaces() {
        return $this.GetFunction('GetInterfaces')
    }

    # Get Firewall Aliases
    # Returns a PSObject array
    #
    [PSObject] GetFwAliases() {
        return $this.GetFunction('GetFwAliases')
    }

    # Get Firewall Rules
    # Returns a PSObject array
    #
    [PSObject] GetFwRules() {
        return $this.GetFunction('GetFwRules')
    }

    # Get Firewall Virtual IPs
    # Returns a PSObject array
    #
    [PSObject] GetFwVirtualIPs() {
        return $this.GetFunction('GetFwVirtualIPs')
    }

    # Get Firewall NAT Outbound
    # Returns a PSObject array
    #
    [PSObject] GetFwNatOutbound() {
        return $this.GetFunction('GetFwNatOutbound')
    }

    # Get Firewall NAT Port Forwarding
    # Returns a PSObject array
    #
    [PSObject] GetFwNatPFwd() {
        return $this.GetFunction('GetFwNatPFwd')
    }

    # Get Gateways (routing)
    # Returns a PSObject
    #
    [PSObject] GetGateways() {
        return $this.GetFunction('GetGateways')
    }

    # Get Services
    # Returns a PSObject array
    #
    [PSObject] GetServices() {
        return $this.GetFunction('GetServices')
    }

    # Get HostName
    # Returns a PSObject array
    #
    [PSObject] GetHostName() {
        return $this.GetFunction('GetHostName')
    }

    # Get Users
    # Returns a PSObject array
    #
    [PSObject] GetUsers() {
        return $this.GetFunction('GetUsers')
    }

} #pfsession class end


#
# PoC de uso
#

try {
    $s = [pfsession]::New('https://10.0.2.10', (Get-Credential) )

    $interf    = $s.GetInterfaces()
    $fwAliases = $s.GetFwAliases()
    $fwNatOut  = $s.GetFwNatOutbound()
    $fwNatPFwd = $s.GetFwNatPFwd()
    $fwRules   = $s.GetFwRules()
    $fwVirtIP  = $s.GetFwVirtualIPs()
    $gw        = $s.GetGateways()
    $users     = $s.GetUsers()
    $svc       = $s.GetServices()
    $hostname  = $s.GetHostname()

}
finally {
    $s.Dispose()
    Remove-Variable s -ErrorAction SilentlyContinue
}

    "$hostname"

    "`nINTERFACES"
    $interf

    "`nGATEWAYS"
    $gw
<#
    $fwAliases  | Out-GridView
    $fwRules    | Out-GridView
    #$fwNatOut  | Out-GridView
    #$fwNatPFwd | Out-GridView
    $fwVirtIP   | Out-GridView
    $users      | Out-GridView
    $svc        | Out-GridView

#>
