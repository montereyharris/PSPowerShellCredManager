Function New-AESkey{
    [Cmdletbinding()]
    param(
        # Parameter help description
        [Parameter(Mandatory = $false)]
        [ValidateSet(32,64)]
        [int32]
        $Keylength = 32,

        [Parameter(Mandatory = $false)]
        [string]
        $KeyFilepath
    )

    $AESKey = New-Object Byte[] $Keylength
    [Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($AESKey)

    $AESKey

    If($KeyFilepath){Set-Content -Path $KeyFilepath -Value $AESKey}

}


Function Export-PsCredential {

    [Cmdletbinding()]
    param(
        # Parameter help description
        [Parameter(Mandatory = $false)]
        [ValidateSet(32,64)]
        [int32]
        $Keylength = 32,

        [Parameter(Mandatory = $false)]
        [string]
        $KeyFilepath,

        # Parameter help description
        [Parameter(Mandatory = $true)]
        [pscredential]
        $Credential
    )


    Begin{
        $plaintext = $credential.getnetworkcredential()

        if($KeyFilepath){$key = Get-Content -Path $KeyFilepath}
        else{$key = New-AESkey -Keylength 32 }

    }

    Process{
        $encryptedpassword = $plaintext.password| ConvertTo-SecureString -Key $Key

    }

    End{
            $object = @{

                username = $plaintext.UserName
                Password = $encryptedpassword
                Key = $key
            }

            $CredObject = New-Object -TypeName PsObject -Property $object
            $CredObject
    }
}

Function Import-PsCredential {
    [Cmdletbinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $KeyFilepath,

        [Parameter(Manadatory = $true, ParameterSetName = 'File')]
        [string]
        $PasswordFilepath,

        [Parameter(Manadatory = $true, ParameterSetName = 'File')]
        [string]
        $Username,

        [Parameter(Manadatory = $true, ParameterSetName = 'Object')]
        [System.Object[]]
        $UserObject

    )

    Begin{
        $key = Get-Content $KeyfilePath

        if($PScmdlet.parametersetname -eq 'File' ){
        $pwd = Get-Content $PasswordFilepath
        $securePassword = $pwd | ConvertTo-SecureString -Key $Key
        $credObject = New-Object System.Management.Automation.PSCredential -ArgumentList $username,$securePassword

        }
    }

    Process{
        if($PScmdlet.parametersetname -eq 'Object' ){

            $credObject = @()

            Foreach($cred in $UserObject){

                $propertytest = $cred.psobject.Properties|where{$_.name -eq 'Username' -or $_.name -eq 'Password'}

                If($propertytest){

                    $pwd = $cred.password
                    $Username = $cred.username
                    $securePassword = $pwd | ConvertTo-SecureString -Key $Key
                    $credObject += New-Object System.Management.Automation.PSCredential -ArgumentList $username,$securePassword


                }

            }
        }
    }


    End{
        $credObject
    }



}