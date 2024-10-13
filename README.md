Alpha branch
PowerShell (v5.1 / v7.x core) Helper for the unofficial pfSense API v2 https://pfrest.org/

Not finished:
- Added the three auth methods. Test pending
- the variable "readonly" is not in use. TODO: remove it from Init methods and constructors
- Two versions of the Init helper method. TODO: remove one of them

# AUTH EXAMPLES

## Authentication using API_Key
- $credentials can be $null or whatveer (compatible type)
- $authtype must be [pfsessionAuthType]::authKey
- $s = [pfsession]::New('https://pfsenseIP', $null, 'tokenstring8f39d19b0c17', $false, [pfsessionAuthType]::authKey)

## Authentication using (user+password) Login 
- $credentials must be valid
- $apikey can be $null, '' or whatever string
- $authtype must be [pfsessionAuthType]::authLogin
- $s = [pfsession]::New('https://pfsenseIP', (Get-Credential), '', $false, [pfsessionAuthType]::authLogin)

## Token Authorization
- $credentials must be valid
- $apikey can be $null, '' or whatever string
- $authtype can be $null, unespecified or [pfsessionAuthType]::authJwt
- [pfsessionAuthType]::authJwt is the default auth mode
- $s = [pfsession]::New('https://pfsenseIP', (Get-Credential), '', $false, [pfsessionAuthType]::authJwt)
- or
- $s = [pfsession]::New('https://pfsenseIP', (Get-Credential), $false)
