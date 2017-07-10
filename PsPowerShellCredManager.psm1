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
        [Parameter(ParameterSetName = 'GenerateKeyFile')]
        [Parameter(ParameterSetName = 'ProvidedKeyFile')]
        [ValidateSet(32,64)]
        [int]
        $Keylength = 32,

        [Parameter(Mandatory = $false)]
        [Parameter(ParameterSetName = 'ProvidedKeyFile')]
        [string]
        $KeyFilepath,

        [Parameter(Mandatory = $false)]
        [Parameter(ParameterSetName = 'GenerateKeyFile')]
        [Parameter(ParameterSetName = 'ProvidedKeyFile')]
        [string]
        $ExportCredFilePath,

        [Parameter(Mandatory = $false)]
        [Parameter(ParameterSetName = 'GenerateKeyFile')]
        [string]
        $ExportKeyFilePath,


        [Parameter(Mandatory = $false)]
        [Parameter(ParameterSetName = 'GenerateKeyFile')]
        [Parameter(ParameterSetName = 'ProvidedKeyFile')]
        [switch]
        $ExportCredstoCSV,


        # Parameter help description
        [Parameter(Mandatory = $true, ValuefromPipeline = $true)]
        [Parameter(ParameterSetName = 'GenerateKeyFile')]
        [Parameter(ParameterSetName = 'ProvidedKeyFile')]
        [pscredential[]]
        $Credential
    )


    Begin{

        if($KeyFilepath){$key = Get-Content -Path $KeyFilepath}
        else{$key = New-AESkey -Keylength 32 }
        $credObject

    }

    Process{
        Foreach($cred in $credential){


            $encryptedpassword = $cred.Password | Convertfrom-SecureString  -Key $Key
            $object = @{

                username = $credential.UserName
                Password = $encryptedpassword
                key = $key
                Keylocation = if($KeyfilePath){$KeyFilepath}Else{ "$ExportKeyFilePath\credkeyfile"}
                CredentialsLocation = "$ExportCredFilePath\Credfile"


            }

            $CredObject += New-Object -TypeName PsObject -Property $object
        }
    }

    End{

            $CredObject
            If($ExportCredFilePath -and $ExportCredstoCSV){$credobject | select Username,Password|Export-CSV  -path "$ExportCredFilePath\CredObject.csv"  }
            elseif($ExportCredFilePath){$credobject.password|%{$_|add-Content $ExportCredFilePath\Credfile} }
            If($ExportKeyFilePath){$key|Set-Content -path $ExportKeyFilePath\Credkeyfile }
    }
}


Function Import-PsCredential {

    [Cmdletbinding()]
    param(
        [Parameter(Mandatory = $true)]
        [Parameter(ParameterSetName = 'CredFile')]
        [Parameter( ParameterSetName = 'CredObject')]
        [string]
        $KeyFilepath,

        [Parameter(Mandatory = $true, ParameterSetName = 'CredFile')]
        [string]
        $PasswordFilepath,

        [Parameter(Mandatory = $true, ParameterSetName = 'CredFile')]
        [string]
        $Username,

        [Parameter(Mandatory = $true, ParameterSetName = 'CredObject')]
        [System.Object[]]
        $UserObject

    )

    Begin{

        $key = Get-Content $KeyfilePath

        if($PScmdlet.parametersetname -eq 'CredFile' ){
        $pswd = Get-Content $PasswordFilepath
        $securePassword = $pswd | ConvertTo-SecureString -Key $Key -ErrorAction SilentlyContinue
        If($securePassword.count -gt 1){
            Write-Error -Message "Credential file contains mulitple passwords" -Exception "MultiplePasswords"
            }
        else{$credObject = New-Object System.Management.Automation.PSCredential -ArgumentList $username,$securePassword}

        }
    }

    Process{
        if($PScmdlet.parametersetname -eq 'CredObject' ){

            $credObject = @()

            Foreach($cred in $UserObject){

                $propertytest = $cred.psobject.Properties|where{$_.name -eq 'Username' -or $_.name -eq 'Password'}

                If($propertytest){

                    $pswd = $cred.password
                    $Username = $cred.username
                    $securePassword = $pswd | ConvertTo-SecureString -Key $Key -ErrorAction SilentlyContinue
                    If($securePassword.count -gt 1){Write-Error -Message "Credential file contains mulitple passwords" -Exception "MultiplePasswords"}
                    Else{$credObject += New-Object System.Management.Automation.PSCredential -ArgumentList $username,$securePassword}


                }

            }
        }
    }


    End{
        $credObject
    }



}