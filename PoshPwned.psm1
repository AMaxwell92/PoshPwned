
#region Module Vars

    # env var name
    $tokenVarName = 'HIBP_API_TOKEN'

    # env var key
    $envVarPath   = 'HKCU:\Environment'

    # standard request headers
    $headers = @{
        'user-agent'   = 'PoshPwned'
        'hibp-api-key' = ''
    }

    # api base url
    $hibpUrl          = 'https://haveibeenpwned.com/api/v3/'
    $pwnedPasswordsUrl= 'https://api.pwnedpasswords.com/'

    # api endpoints
    $endpoints    = @{
        GetAllBreaches      = 'breachedaccount/{0}'
        GetAllBreachedSites = 'breaches'
        GetBreachedSite     = 'breach/{0}'
        GetAllDataClasses   = 'dataclasses'
        GetAllPastes        = 'pasteaccount/{0}'
        TestPwnedPassword   = 'range/{0}'
    }

#endregion

#region Utility Functions

    function Test-TokenExists {

        try {

            return [ bool ] ( get-itempropertyvalue -name $tokenVarName -path $envVarPath )

        } catch {


            write-error 'No HaveIBeenPwned API token was found! Run "Set-HaveIBeenPwned -Token [ YourToken ]" and try again!'
            return $false

        }
    }

    function Get-Token {

        if ( !( Test-TokenExists ) ) {

            write-error 'No HaveIBeenPwned API token was found! Run "Set-HIBP -Token [ YourToken ]" and try again!'

        }

        return ( get-itempropertyvalue -name $tokenVarName -path $envVarPath )

    }

    function Get-Headers {

        if ( !( Test-TokenExists ) ) {

            write-error 'No HaveIBeenPwned API token was found! Run "Set-HIBP -Token [ YourToken ]" and try again!'

        }

        return @{

            'user-agent'   = 'PoshPwned'
            'hibp-api-key' = ( Get-Token )
        }
    }

    function Set-HIBP {

        param(
            [ parameter( mandatory = $false ) ]
            [ string ] $Token
        )

        if ( $Token ) {

            set-itemproperty -path $envVarPath -name $tokenVarName -value $token

            if ( Test-TokenExists ) {

                write-host 'Token saved successfully!'

            }

            else {

                write-error 'Token save failed.. Please try again.'

            }
        }
    }

#endregion

#region API Wrapper

    function Get-AllAccountBreaches {

        <#

            .SYNOPSIS

                Retrieves all breaches for a specified account from the HaveIBeenPwned v3 API.

            .DESCRIPTION

                Wraps the HaveIBeenPwned REST API endpoint functionality outlined here: https://haveibeenpwned.com/API/v3#BreachesForAccount.

            .PARAMETER Account

                [ string ] : email address to retrieve breaches for.

            .PARAMETER NoTrunc

                [ switch ] : return the entire breach dataclass collection ( see here: https://haveibeenpwned.com/API/v3#BreachModel ).

            .PARAMETER Domain

                [ string ] : specific domain to query breach results for ( ex: adobe.com ).

            .PARAMETER IncludeUnverified

                [ string ] : return all breaches, including those that have not been verified.

            .OUTPUTS

                [ PSCustomObject[] ] : array of PSCustomObjects containing all breach dataclasses ( listed here: https://haveibeenpwned.com/API/v3#BreachModel ).

        #>

        param(
            [ parameter( mandatory = $true ) ]
            [ string ] $Account,
            [ parameter( mandatory = $false ) ]
            [ switch ] $NoTrunc,
            [ parameter( mandatory = $false ) ]
            [ string ] $Domain,
            [ parameter( mandatory = $false ) ]
            [ switch ] $IncludeUnverified
        )

        # check that we have an api key
        if ( !( Test-TokenExists ) ) { return }

        # format the uri
        $uri = "$hibpUrl$( $endpoints.GetAllBreaches )" -f $Account

        # handle params
        $params = ''

        # handle NoTrunc
        if ( $NoTrunc ) {

            $params += "$( if ( $params.length -gt 0 ) { '&' } else { '?' } )truncateResponse=false"

        }

        # handle domain
        if ( $Domain ) {

            $params += "$( if ( $params.length -gt 0 ) { '&' } else { '?' } )domain=$Domain"

        }

        # handle include unverified
        if ( $IncludeUnverified ) {

            $params += "$( if ( $params.length -gt 0 ) { '&' } else { '?' } )includeUnverified=false"

        }

        # format the request
        $req = @{
            uri     = "$uri$params"
            headers = ( get-headers )
        }

        # send it
        return ( invoke-restmethod @req )

    }

    function Get-AllBreachedSites {

        <#

            .SYNOPSIS

                Retrieves all breached sites from the HaveIBeenPwned v3 API.

            .DESCRIPTION

                Wraps the HaveIBeenPwned REST API endpoint functionality outlined here: https://haveibeenpwned.com/API/v3#AllBreaches.

            .PARAMETER Domain

                [ string ] : specific domain to query breach results for ( ex: adobe.com ).

            .OUTPUTS

                [ string[] ] : array of breached sites by domain.

        #>

        param(

            [ parameter( mandatory = $false ) ]
            [ string ] $Domain
        )

        # check that we have an api key
        if ( !( Test-TokenExists ) ) { return }

        # construct uri
        $uri = "$hibpUrl$( $endpoints.GetAllBreachedSites )"

        # construct params
        $params = ''

        # handle domain
        if ( $Domain ) {

            $params += "?domain=$Domain"

        }

        # construct request
        $req = @{

            uri     = "$uri$params"
            headers = ( get-headers )

        }

        # retrieve breached sites
        $breachedSites = invoke-restmethod @req

        # send it!
        return $breachedSites

    }

    function Get-BreachedSite {

        <#

            .SYNOPSIS

                Retrieves a single site's breach info from the HaveIBeenPwned v3 API.

            .DESCRIPTION

                Wraps the HaveIBeenPwned REST API endpoint functionality outlined here: https://haveibeenpwned.com/API/v3#SingleBreach.

            .PARAMETER Site

                [ string ] : specific site to query breach results for ( ex: adobe.com ).

            .OUTPUTS

                [ PSCustomObject[] ] : array of PSCustomObjects containing all breach dataclasses, per site ( listed here: https://haveibeenpwned.com/API/v3#BreachModel ).

        #>

        param(

            [ parameter( mandatory = $true ) ]
            [ string ] $Site
        )

        # check for an API token
        if ( !( Test-TokenExists ) ) { return }

        # format the uri
        $uri = "$hibpUrl$( $endpoints.GetBreachedSite )" -f $site

        # format the request
        $req = @{
            uri     = $uri
            headers = ( get-headers )
        }

        # retrieve the results
        $breachedSite = invoke-restmethod @req

        # send it!
        return $breachedSite

    }

    function Get-AllPastes {

        <#

            .SYNOPSIS

                Retrieves all pastes for a specified account from the HaveIBeenPwned v3 API.

            .DESCRIPTION

                Wraps the HaveIBeenPwned REST API endpoint functionality outlined here: https://haveibeenpwned.com/API/v3#PastesForAccount.

            .PARAMETER Account

                [ string ] : email address to retrieve breaches for.

            .OUTPUTS

                [ PSCustomObject[] ] : array of PSCustomObjects containing all breach dataclasses, per site ( listed here: https://haveibeenpwned.com/API/v3#BreachModel ).

        #>

        param(
            [ parameter( mandatory = $true ) ]
            [ string ] $Account
        )

        if ( !( Test-TokenExists ) ) { return }

        # format the uri
        $uri = "$hibpUrl$( $endpoints.GetAllPastes )" -f $Account

        # format the request
        $req = @{
            uri     = $uri
            headers = ( get-headers )
        }

        # retrieve results
        $res = invoke-restmethod @req

        # send it!
        return $res

    }

    function Test-PasswordPwned {

        <#

            .SYNOPSIS

                Checks if the specified password is listed in the HIBP pwned passwords database.

            .DESCRIPTION

                Wraps the HaveIBeenPwned REST API endpoint functionality outlined here: https://haveibeenpwned.com/API/v3#SearchingPwnedPasswordsByRange.

                The lifecycle of the password for this function is as follows:
                    - Password is provided via argument as a SecureString
                    - The SecureString password is reversed to plaintext
                    - The plaintext password is SHA1 hashed
                    - At this point, both the securestring and plaintext passwords are removed from memory by the function.

            .PARAMETER Password

                [ securestring ] : password to evaluate for pwnage.

            .OUTPUTS

                [ bool ] : whether the password is pwned or not

            .EXAMPLE

                PS> Test-PasswordPwned -Password ( 'Password!123' | ConvertTo-SecureString -AsPlainText -Force )
                True

        #>

        param(
            [ parameter( mandatory = $true ) ]
            [ system.security.securestring ] $Password
        )

        # check for an api token
        if ( !( Test-TokenExists ) ) { return }

        # convert securestring to pscredential object
        $passwordPlaintext = [ pscredential ]::new( 0, $password ).getnetworkcredential().password

        # encode the password
        $passwordBytes = [ system.text.encoding ]::utf8.getbytes( $passwordPlaintext )

        # build memory stream for password hash
        $stream = [ system.io.memorystream ]::new( $passwordBytes )

        # remove password vars from memory
        remove-variable -name passwordPlaintext
        remove-variable -name password

        # sha1 hash password
        $passwordHash = get-filehash -algorithm sha1 -inputstream $stream

        # first 5-characters of hash
        $passwordHashStart = $passwordHash.hash.substring( 0, 5 )

        # format the uri
        $uri = "$pwnedPasswordsUrl$( $endpoints.TestPwnedPassword )" -f $passwordHashStart

        # format the request
        $req = @{
            uri     = $uri
            headers = ( get-headers )
        }

        # retrieve the results
        $pwnedPasswords = invoke-restmethod @req

        # check if the password is pwned
        foreach ( $pwnedPassword in $pwnedPasswords.split( "`n" ) ) {

            # reform full hash
            $hash = "$passwordHashStart$( $pwnedPassword.split( ':' )[ 0 ] )"

            if ( $hash -eq $passwordHash.hash ) {

                return $true

            }
        }

        return $false

    }

#endregion

#region Member Exports

    Export-ModuleMember -Function Get-AllAccountBreaches
    Export-ModuleMember -Function Get-AllBreachedSites
    Export-ModuleMember -Function Get-BreachedSite
    Export-ModuleMember -Function Get-AllPastes
    Export-ModuleMember -Function Test-PasswordPwned
    Export-ModuleMember -Function Set-HIBP

#endregion
