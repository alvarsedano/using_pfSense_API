# Consumiendo unofficial pfSense rest-api v2
# https://pfrest.org/api-docs/

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
    #[bool]$SkipCertificateCheck
    [bool]$isReadOnly
    [bool]$PSEditionCore
    [string]$lastToken
    hidden [string]$contentType = 'application/json'
    hidden [HashTable]$headers = @{Authorization = ''}
    hidden [PSCredential]$cred
    hidden [hashTable]$funcionesGet = @{GetInterfaces           = 'interfaces' #interface
                                        GetInterfaceBridges     = 'interface/bridges' #interface/bridge
                                        GetInterfaceVlans       = 'interface/vlans' # aniadido
                                        GetFwAliases            = 'firewall/aliases' #firewall/alias
                                        GetFwRules              = 'firewall/rules' #firewall/rule
                                        GetFwVirtualIPs         = 'firewall/virtual_ips' #firewall/virtual_ip
                                        GetFwNatOutbound        = 'firewall/nat/outbound/mode' #firewall/nat/outbound
                                        GetFwNatOutboundMaps    = 'firewall/nat/outbound/mappings' #firewall/nat/outbound/mapping
                                        GetFwNat1to1            = 'firewall/nat/one_to_one'
                                        GetFwNatPFwds           = 'firewall/nat/port_forwards' #firewall/nat/port_forward
                                        GetGateways             = 'routing/gateways'
                                        GetDefaultGateway       = 'routing/gateway/default'
                                        GetStaticRoutes         = 'routing/static_routes' #aniadido
                                        GetVPNOvpnServers       = 'vpn/openvpn/servers' # aniadido
                                        GetVPNWireGuardSettings = 'vpn/wireguard/settings' # aniadido
                                        GetVPNWireGuardPeers    = 'vpn/wireguard/peers' # aniadido
                                        GetVPNWireGuardTunnels  = 'vpn/wireguard/tunnels' # aniadido
                                        GetServices             = 'status/services' # ahora está en status
                                        GetSTCarp               = 'status/carp' #aniadido
                                        GetSTGateways           = 'status/gateways' #aniadido
                                        GetSTInterfaces         = 'status/interfaces' #aniadido
                                        GetSTSystem             = 'status/system' #aniadido
                                        GetSTOvpnServers        = 'status/openvpn/servers' #aniadido
                                        GetHostName             = 'system/hostname'
                                        GetCAs                  = 'system/certificate_authorities' #system/ca
                                        GetCRLs                 = 'system/crls' # aniadido
                                        GetCerts                = 'system/certificates' # system/certificate
                                        GetDns                  = 'system/dns'
                                        #GetConfig               = 'system/config' # no funciona --> Use better .GetSTSystem()
                                        GetArp                  = 'diagnostics/arp_table' # #diagnostics/arp
                                        GetVersion              = 'system/version' #ok
                                        GetUsers                = 'users' #user
                                        GetGroups               = 'user/groups'} #aniadido
                                        
    #TODO: manage token expiration

    # constrúúúctor helper
    #
    #TODO: manage skip/force pfSense certificate check on API calls (Invoke-RestMethod)
    #hidden Init([string]$pfSenseBaseURI,[PSCredential]$credentials, [bool]$SkipCertCheck,[bool]$isReadOnly) {
    hidden Init([string]$pfSenseBaseURI,[PSCredential]$credentials, [bool]$isReadOnly) {
        $this.cred = $credentials
        #$this.SkipCertificateCheck = $SkipCertCheck
        $this.isReadOnly = $isReadOnly
        $this.baseURI = $pfSenseBaseURI
        $this.PSEditionCore = $Global:PSEdition -eq 'Core'
        if ($pfSenseBaseURI -match '\/$') {
            $this.baseURI += 'api/v2/'
        }
        else {
            $this.baseURI += '/api/v2/'
        }
        $this.GetToken()
    }


    # Constructs Basic Authorization string to get JWT token
    # Return string 'Basic BASE64ENCODE("user:password")'
    hidden [string] usrpwdB64() {
        try {
            [string]$cadAuth = '{0}:{1}' -f $this.cred.UserName , [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($this.cred.Password))
            return ( 'Basic {0}' -f ([Convert]::ToBase64String([char[]]$cadAuth)) )
        } catch {
            return '';
        }
    }
    
    # constrúúúctor
    # No changes allowed on pfSense when $isReadOnly is true
    #
    #pfsession([string]$pfSenseBaseURI,[PSCredential]$credentials, [bool]$SkipCertCheck,[bool]$isReadOnly) {
    pfsession([string]$pfSenseBaseURI,[PSCredential]$credentials, [bool]$isReadOnly) {
        $this.Init($pfSenseBaseURI,$credentials, $isReadOnly)
    }

    # No changes allowed on pfSense when $isReadOnly is true
    # $isReadOnly = true is the default behavior
    #
    pfsession([string]$pfSenseBaseURI,[PSCredential]$credentials) {
        $this.Init($pfSenseBaseURI,$credentials, $true)
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
        #return "$($this.baseURI)$($rel)"
        return ( '{0}{1}' -f $this.baseURI, $rel )
    }

    # Get pfSense token (JWT mode)
    # Saved in lastToken
    #
    [void] GetToken() {
        [string]$relUri  = 'auth/jwt'
        <#
        [string]$cadAuth = '{0}:{1}' -f $this.cred.UserName , [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($this.cred.Password))
        [hashTable]$cab  = @{Accept        = $this.contentType
                             Authorization = 'Basic {0}' -f ([Convert]::ToBase64String([char[]]$cadAuth))}
        #>
        [hashTable]$cab  = @{Accept        = $this.contentType
                             Authorization = $this.usrpwdB64() }

        #$respuesta = irmCore2 -method Post -uri $this.uri($relUri) -head $cab -ct $this.contentType
        $respuesta = irm2 -method Post -uri $this.uri($relUri) -head $cab -ct $this.contentType
        if ($respuesta.code -eq 200) {
            # Token ok
            $this.lastToken = $respuesta.data.token
            $this.headers.Authorization = 'Bearer {0}' -f $this.lastToken
        }
        else {
            $this.lastToken = ''
            $this.headers.Authorization = ''
            Write-Host -BackgroundColor Red "error: $($respuesta.message)"
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

    # Get pfSense Interface Vlans
    # Returns a PSObject array
    #
    [PSObject] GetInterfaceVlans() {
        return $this.GetFunction('GetInterfaceVLans')
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
    # nombre cambiado GetFwNatOutboundMap --> GetFwNatOutboundMaps
    #
    [PSObject] GetFwNatOutboundMaps() {
        return $this.GetFunction('GetFwNatOutboundMaps')
    }

    # Get Firewall NAT Port Forwarding
    # Returns a PSObject array
    #
    # nombre cambiado GetFwNatPFwd --> GetFwNatPFwds
    [PSObject] GetFwNatPFwds() {
        return $this.GetFunction('GetFwNatPFwds')
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

    # Get Default Gateway (routing/gateway/default)
    # Returns a PSObject
    #
    [PSObject] GetDefaultGateway() {
        return $this.GetFunction('GetDefaultGateway')
    }

    # Get Static Routes (routing/static_routes)
    # Returns a PSObject array
    #
    [PSObject] GetStaticRoutes() {
        return $this.GetFunction('GetStaticRoutes')
    }

    # Get CRLs
    # Returns a PSObject
    #
    [PSObject] GetCRLs() {
        return $this.GetFunction('GetCRLs')
    }

    # Get CAs
    # Returns a PSObject
    #
    [PSObject] GetCAs() {
        return $this.GetFunction('GetCAs')
    }


    #pem 2 x509 without private key
    hidden [Security.Cryptography.X509Certificates.X509Certificate2] pem2x509([ref]$crt) {
        try {
            # Remove ^----*$ lines from X509 encoding cert
            $temp = [Security.Cryptography.X509Certificates.X509Certificate2]::new([Convert]::FromBase64String([string]((($crt.Value) -split "`n" ) -notmatch '^----') ))
        }
        catch {
            # Possible invalid cert content
            $temp = [Security.Cryptography.X509Certificates.X509Certificate2]::new()
        }
        return $temp
    }

    #pem 2 x509 with private key (if running under core)
    hidden [Security.Cryptography.X509Certificates.X509Certificate2] pem2x509([ref]$crt, [ref]$prv) {
        if ($this.PSEditionCore) {
            [char[]]$crtS = [Text.Encoding]::ASCII.Getstring([Convert]::FromBase64String($crt.Value)).ToCharArray()
            if ($null -ne $prv.Value) {
                [char[]]$keyS = [Text.Encoding]::ASCII.Getstring([Convert]::FromBase64String($prv.Value)).ToCharArray()
                return [Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPem($crtS, $keyS)
            }
            else {
                return $this.pem2x509($crt)
            }
        }
        else {
            return $this.pem2x509($crt)
        }
    }

    #certArray 2 X509 Array
    hidden [Security.Cryptography.X509Certificates.X509Certificate2[]] certArray2X509Array([ref]$array, [bool]$private) {
        [Security.Cryptography.X509Certificates.X509Certificate2[]]$result = @()
        [Security.Cryptography.X509Certificates.X509Certificate2]$ccc = $null
        foreach($c in $array.Value) {
            if ($private -and $this.PSEditionCore -and $null -ne $c.crt) {
                ##$c.creation
                try {
                    $ccc=[Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPem($c.crt, $c.prv)
                } catch {
                    $ccc = [Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPem($c.crt)
                }
            }
            else {
                $ccc = $this.pem2x509($c.crt)
                #$ccc = [Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPem($c.crt)
            }
            $ccc.FriendlyName = $c.descr
            $result += $ccc
        }
        return $result
    }

    # Get X509 CA certificates
    # Input params: $private: $true to return private Keys
    # Returns a X509Certificate2 array (with privateKeys if $private is $true and it's called from PWSH 7+ Core)
    #
    # NOTE: Mandatory PWSHCore to return Private Keys.
    #
    [System.Security.Cryptography.X509Certificates.X509Certificate2[]] GetCAsX509([bool]$private) {
        [PSObject]$obj = $this.GetFunction('GetCAs')
        return $this.certArray2X509Array([ref]($obj.ca), $private)
    }

    # Get Certs
    # Returns a PSObject array
    #
    [PSObject] GetCerts() {
        return $this.GetFunction('GetCerts')
    }

    # Get X509 Certificates
    # Input params: $private: $true to return private Keys
    # Returns a X509Certificate2 array (with privateKeys if $private is $true and it's called from PWSH 7+ Core)
    #
    # NOTE: It's mandatory to use PWSHCore to return Private Keys.
    #
    [System.Security.Cryptography.X509Certificates.X509Certificate2[]] GetCertsX509([bool]$private) {
        [PSObject]$obj = $this.GetFunction('GetCerts')
        return $this.certArray2X509Array([ref]($obj), $private)
    }

    <#
    # Get Config
    # Returns a PSObject array
    #
    [PSObject] GetConfig() {
        return $this.GetFunction('GetConfig')
    }
    #>

    # Get Arp tabñe (diagnostics/arp_table)
    # Returns a PSObject array
    #
    [PSObject] GetArp() {
        return $this.GetFunction('GetArp')
    }

    # Get Dns
    # Returns a PSObject array
    #
    [PSObject] GetDns() {
        return $this.GetFunction('GetDns')
    }

    # Get OpenVpn Servers (vpn/openvpn/servers)
    # Returns a PSObject array
    #
    [PSObject] GetVPNOvpnServers() {
        return $this.GetFunction('GetVPNOvpnServers')
    }

    # Get WireGuard Settings (vpn/wireguard/settings)
    # Returns a PSObject array
    #
    [PSObject] GetVPNWireGuardSettings() {
        return $this.GetFunction('GetVPNWireGuardSettings')
    }

    # Get WireGuard Peers (vpn/wireguard/peers)
    # Returns a PSObject array
    #
    [PSObject] GetVPNWireGuardPeers() {
        return $this.GetFunction('GetVPNWireGuardPeers')
    }

    # Get WireGuard Tunnels (vpn/openvpn/tunnels)
    # Returns a PSObject array
    #
    [PSObject] GetVPNWireGuardTunnels() {
        return $this.GetFunction('GetVPNWireGuardTunnels')
    }

    # Get Services Status (status/services)
    # Returns a PSObject array
    #
    [PSObject] GetServices() {
        return $this.GetFunction('GetServices')
    }

    # Get CARP Status (status/carp)
    # Returns a PSObject array
    #
    [PSObject] GetSTCarp() {
        return $this.GetFunction('GetSTCarp')
    }

    # Get Gateways Status (status/gateways)
    # Returns a PSObject array
    #
    [PSObject] GetSTGateways() {
        return $this.GetFunction('GetSTGateways')
    }

    # Get Interfaces Status (status/interfaces)
    # Returns a PSObject array
    #
    [PSObject] GetSTInterfaces() {
        return $this.GetFunction('GetSTInterfaces')
    }

    # Get System Status (status/system)
    # Returns a PSObject array
    #
    [PSObject] GetSTSystem() {
        return $this.GetFunction('GetSTSystem')
    }

    # Get OpenVPN Servers Status (status/openvpn/servers)
    # Returns a PSObject array
    #
    [PSObject] GetSTOvpnServers() {
        return $this.GetFunction('GetSTOvpnServers')
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

    # Get Groups
    # Returns a PSObject array
    #
    [PSObject] GetGroups() {
        return $this.GetFunction('GetGroups')
    }

    # Get Version
    # Returns a PSObject
    #
    [PSObject] GetVersion() {
        return $this.GetFunction('GetVersion')
    }

    hidden [void] throwNoPermission() {
        if ($this.isReadOnly) {
            Throw "Operation rejected: you do not have write permission."
            return # never executed
        }
      
    }

    # Creates new vLan interface
    # Returns string with name of the new vlanIf
    #
    [string] newVLan([string]$parentIf, [uint16]$vlanId, [string]$descr) {
        $this.throwNoPermission()

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
    }

    # assignIf
    # Returns a PSObject ¿???
    #
    [PSObject] assignIf([string]$ifName, [string]$descr, [bool]$enable, [string]$ipaddr, [byte]$subnetPref, [bool]$apply) {
        $this.throwNoPermission()

        $bodyJ = @{if     = $ifName
                   descr  = $descr
                   enable = $enable
                   type   = 'staticv4'
                   ipaddr = $ipaddr
                   subnet = $subnetPref
                   apply  = $apply}

        [string]$relUri = 'interface'
        $respuesta = irm2 -method Post -uri $this.uri($relUri) -head $this.headers -Body $($bodyJ|ConvertTo-Json -Depth 1 -Compress) -ct $this.contentType
        if ($respuesta.code -eq 200) {
            return $respuesta.data
        }
        else {
            return $null
        }
    }
<#
    [PSObject] newFwRule() {
        $this.throwNoPermission()

        $bodyJ = @{
            if           = $ifName
            ipprotocol   = 'inet|inet6|inet46'
            protocol     = $protocol
            icmptype     = $icmptype
            src          = $src
            dst          = $dst
            srcport      = $srcport
            dstport      = $dstport
            gateway      = $gateway
            sched        = $sched
            dnpipe       = $dnspipe
            pdnpipe      = $pdnpipe
            defaultqueue = $defaultqueue
            ackqueue     = $ackqueue
            disabled     = $disabled
            descr        = $descr
            apply        = $apply}

        return $null
    }
#>

} #pfsession class end


#
# PoC de uso
#

try {
    #$s = [pfsession]::New('https://10.0.2.10', (Get-Credential)) # <-- readonly mode
    $s = [pfsession]::New('https://10.0.2.10', (Get-Credential), $false) # <-- with write permissions
    
    
<#
    $interf    = $s.GetInterfaces()
    $interfBrg = $s.GetInterfaceBridges()
    $fwAliases = $s.GetFwAliases()
    $fwNatOut  = $s.GetFwNatOutbound()
    $fwNatOutM = $s.GetFwNatOutboundMaps()
    $fwNatPFwd = $s.GetFwNatPFwds()
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
    $x509CA    = $s.GetCAsX509($false)  # <-- false = without private key
    $x509Cert  = $s.GetCertsX509($true) # <-- true = with private key
#>

    # Test: vlan creation
    #$nuevaVLAN = $s.newVLan('em0', 146, 'vlan146')
    #$s.assignIf($nuevaVLAN, 'vlan146', $true, '10.137.10.1', 24, $true)
}
finally {
    # TODO: descomentar al terminar la depuración
    #$s.Dispose()
    #Remove-Variable s -ErrorAction SilentlyContinue
}

<#
    "$hostname"

    "`nINTERFACES"
    $interf

    "`nGATEWAYS"
    $gw
#>

<#
    $fwAliases  | Out-GridView
    $fwRules    | Out-GridView
    #$fwNatOut  | Out-GridView
    #$fwNatPFwd | Out-GridView
    $fwVirtIP   | Out-GridView
    $users      | Out-GridView
    $svc        | Out-GridView

#>

<#
# Exporting CA Certificates
foreach($c in $x509Cert) {
    If (-not $c.HasPrivateKey) {
        # Export certificates with privateKey as PFX. import password is 12345678.Abc
        [string]$pwdCert = '12345678.Abc'
        [byte[]]$ar = $c.Export([Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $pwdCert)
        [IO.File]::WriteAllBytes($c.FriendlyName +'.pfx', $ar)

    }
    else {
        # Export certificates without private key as CER.
        [byte[]]$ar = $c.Export([Security.Cryptography.X509Certificates.X509ContentType]::Cert)
        [IO.File]::WriteAllBytes($c.FriendlyName +'.cer', $ar)
    }
}



    "`nX509 Certificates Array"
    $x509Cert | Format-Table

#>

# $s contains the instance to interact with the API
#
