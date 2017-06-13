Function New-AESkey{
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