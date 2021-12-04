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
if ($Global:PSEdition -ne 'Core') {
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
    [bool]$SkipCertificateCheck
    [bool]$isReadOnly
    [bool]$PSEditionCore
    [string]$lastToken
    hidden [string]$contentType = 'application/json'
    hidden [HashTable]$headers = @{Accept        = 'application/json';
                                   Authorization = ''   }
    hidden [PSCredential]$cred
    hidden [hashTable]$funcionesGet = @{GetInterfaces       = 'interface'
                                        GetInterfaceBridges = 'interface/bridge'
                                        GetFwAliases        = 'firewall/alias'
                                        GetFwRules          = 'firewall/rule'
                                        GetFwVirtualIPs     = 'firewall/virtual_ip'
                                        GetFwNatOutbound    = 'firewall/nat/outbound'
                                        GetFwNatOutboundMap = 'firewall/nat/outbound/mapping'
                                        GetFwNat1to1        = 'firewall/nat/one_to_one'
                                        GetNatPFwd          = 'firewall/nat/port_forward'
                                        GetGateways         = 'routing/gateway/'
                                        GetServices         = 'services'
                                        GetHostName         = 'system/hostname'
                                        GetCAs              = 'system/ca'
                                        GetCerts            = 'system/certificate'
                                        GetDns              = 'system/dns'
                                        GetConfig           = 'system/config'
                                        GetArp              = 'system/arp'
                                        GetVersion          = 'system/version'
                                        GetUsers            = 'user'}
                                        
    #TODO: manage token expiration

    # constrúúúctor helper
    #
    hidden Init([string]$pfSenseBaseURI,[PSCredential]$credentials, [bool]$SkipCertCheck,[bool]$isReadOnly) {
        $this.cred = $credentials
        $this.SkipCertificateCheck = $SkipCertCheck
        $this.isReadOnly = $isReadOnly
        $this.baseURI = $pfSenseBaseURI
        $this.PSEditionCore = $Global:PSEdition -eq 'Core'
        if ($pfSenseBaseURI -match '\/$') {
            $this.baseURI += 'api/v1/'
        }
        else {
            $this.baseURI += '/api/v1/'
        }
        $this.GetToken()
    }


    # constrúúúctor
    #
    pfsession([string]$pfSenseBaseURI,[PSCredential]$credentials, [bool]$SkipCertCheck,[bool]$isReadOnly) {
        $this.Init($pfSenseBaseURI,$credentials, $SkipCertCheck,$isReadOnly)
    }

    pfsession([string]$pfSenseBaseURI,[PSCredential]$credentials) {
        $this.Init($pfSenseBaseURI,$credentials, $true, $true)
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
    hidden [PSObject] GetFunction([string]$function) {
        $f = $this.funcionesGet.$function
        if ($f) {
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

    # Get pfSense Interface Bridges
    # Returns a PSObject array
    #
    [PSObject] GetInterfaceBridges() {
        return $this.GetFunction('GetInterfaceBridges')
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

    # Get Firewall NAT Outbound Setting Mode
    # Returns a PSObject array
    #
    [PSObject] GetFwNatOutbound() {
        return $this.GetFunction('GetFwNatOutbound')
    }

    # Get Firewall NAT Outbound Mappings (Rules)
    # Returns a PSObject array
    #
    [PSObject] GetFwNatOutboundMap() {
        return $this.GetFunction('GetFwNatOutboundMap')
    }

    # Get Firewall NAT Port Forwarding
    # Returns a PSObject array
    #
    [PSObject] GetFwNatPFwd() {
        return $this.GetFunction('GetFwNatPFwd')
    }

    # Get Firewall NAT 1 to 1 mappings
    # Returns a PSObject array
    #
    [PSObject] GetFwNat1to1() {
        return $this.GetFunction('GetFwNat1to1')
    }

    # Get Gateways (routing)
    # Returns a PSObject
    #
    [PSObject] GetGateways() {
        return $this.GetFunction('GetGateways')
    }

    # Get CAs
    # Returns a PSObject
    #
    [PSObject] GetCAs() {
        return $this.GetFunction('GetCAs')
    }

    #pem 2 x509 without private key
    hidden [Security.Cryptography.X509Certificates.X509Certificate2] pem2x509([string]$crt) {
        return [Security.Cryptography.X509Certificates.X509Certificate2]::new([Convert]::FromBase64String($crt))
    }

    #pem 2 x509 with private key (if running under core)
    hidden [Security.Cryptography.X509Certificates.X509Certificate2] pem2x509([string]$crt, [string]$prv) {
        if ($this.PSEditionCore) {
            [char[]]$crtS = [Text.Encoding]::ASCII.Getstring([Convert]::FromBase64String($crt)).ToCharArray()
            [char[]]$keyS = [Text.Encoding]::ASCII.Getstring([Convert]::FromBase64String($prv)).ToCharArray()
            return [Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPem($crtS, $keyS)
        }
        else {
            return $this.pem2x509($crt)
        }
    }

    # Get CAsX509 with or without Private Keys
    # Input params: $private: $true To return private Keys
    # Returns a X509Certificate2 array (with privateKeys if $private is $true and it's called from PWSH 7+ Core)
    #
    # NOTE: Mandatory PWSHCore to return Private Keys.
    #
    [System.Security.Cryptography.X509Certificates.X509Certificate2[]] GetCAsX509([bool]$private) {
        [PSObject]$obj = $this.GetFunction('GetCAs')

        [Security.Cryptography.X509Certificates.X509Certificate2[]]$r = @()
        [Security.Cryptography.X509Certificates.X509Certificate2]$ccc = $null
        foreach($c in $obj.ca) {
            if ($private) {
                $ccc = $this.pem2x509($c.crt, $c.prv)
            }
            else {
                $ccc = $this.pem2x509($c.crt)
            }
            $ccc.FriendlyName = $c.descr
            $r += $ccc
        }
        return $r
    }

    # Get Certs
    # Returns a PSObject array
    #
    [PSObject] GetCerts() {
        return $this.GetFunction('GetCerts')
    }

    # Get Config
    # Returns a PSObject array
    #
    [PSObject] GetConfig() {
        return $this.GetFunction('GetConfig')
    }

    # Get Dns
    # Returns a PSObject array
    #
    [PSObject] GetDns() {
        return $this.GetFunction('GetDns')
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

    # Get Version
    # Returns a PSObject
    #
    [PSObject] GetVersion() {
        return $this.GetFunction('GetVersion')
    }

    # Creates new vLan interface
    # Returns string with name of the new vlanIf
    #
    [string] newVLan([string]$parentIf, [uint16]$vlanId, [string]$descr) {
        $bodyJ = @{if   =$parentIf;
                   tag  =$vlanId;
                   descr=$descr}

        [string]$relUri = 'interface/vlan'
        $respuesta = irm2 -method Post -uri $this.uri($relUri) -head $this.headers -Body $($bodyJ|ConvertTo-Json -Depth 1 -Compress) -ct $this.contentType
        if ($respuesta.code -eq 200) {
            return $respuesta.data.vlanif
        }
        else {
            return $null
        }
        $respuesta
    }

    # assignIf
    # Returns a PSObject ¿???
    #
    [PSObject] assignIf([string]$ifName, [string]$descr, [bool]$enable, [string]$ipaddr, [byte]$subnetPref, [bool]$apply) {
        $bodyJ = @{if    =$ifName;
                   descr =$descr;
                   enable=$enable;
                   type  ='staticv4';
                   ipaddr=$ipaddr;
                   subnet=$subnetPref;
                   apply =$apply}

        [string]$relUri = 'interface'
        $respuesta = irm2 -method Post -uri $this.uri($relUri) -head $this.headers -Body $($bodyJ|ConvertTo-Json -Depth 1 -Compress) -ct $this.contentType
        if ($respuesta.code -eq 200) {
            return $respuesta.data
        }
        else {
            return $null
        }
        $respuesta
    }


} #pfsession class end


#
# PoC de uso
#

try {
    $s = [pfsession]::New('https://10.0.2.10', (Get-Credential) )

    $interf    = $s.GetInterfaces()
    $interfBrg = $s.GetInterfaceBridges()
    $fwAliases = $s.GetFwAliases()
    $fwNatOut  = $s.GetFwNatOutbound()
    $fwNatOutM = $s.GetFwNatOutboundMap()
    $fwNatPFwd = $s.GetFwNatPFwd()
    $fwRules   = $s.GetFwRules()
    $fwVirtIP  = $s.GetFwVirtualIPs()
    $gw        = $s.GetGateways()
    $users     = $s.GetUsers()
    $svc       = $s.GetServices()
    $hostname  = $s.GetHostname()
    $version   = $s.GetVersion()
    $cfg       = $s.GetConfig()
    $CAs       = $s.GetCAs()
    $Certs     = $s.GetCerts()
    $Dns       = $s.GetDns()

    $nuevaVLAN = $s.newVLan('em0', 145, 'vlan145')
    $s.assignIf($nuevaVLAN, 'vlan145', $true, '10.137.10.1', 24, $true)
}
finally {
    #$s.Dispose()
    #Remove-Variable s -ErrorAction SilentlyContinue
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
    