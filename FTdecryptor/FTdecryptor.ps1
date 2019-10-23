function Invoke-FTdecryptor{
    <#
    .SYNOPSIS
        Once the FTcode password (ek) is intercepted in the http post request it is possible to decrypt the files through this simple function.

        Authors: Gabriele Pippi (@gabriele_pippi)
        License: AGPL-3.0 
        General Requirements: encryption password is required
        Required pwsh Dependencies: None
        Optional pwsh Dependencies: None
    	Tested on Version 1018.1

    .PARAMETER Force
        [Warning] In case there is any error during the decryption process all files will become unrecoverable.
        Tries to decrypt without backing up files
        This parameter is mutually exclusive with BackupPath.

    .PARAMETER BackupPath
        Specifies the directory where the encrypted files will be backed up. Default = (get-location).Path + '\ftdecryptor_' + (get-date).tostring("MM-dd-yyyy")
        This parameter is mutually exclusive with Force.
    
    .PARAMETER Log
        Enables tool logging, it requires the Verbose switch option.

    .PARAMETER LogPath
        Specifies the full path to the log file, it requires the Log switch option. Default = (get-location).Path + '\ftdecryptor_'+ (get-date).tostring("MM-dd-yyyy") + '.log'
        
    .PARAMETER Extension
        Specifies the mandatory extension used by FTcode to rename files. It is currently used to identify possible infected files.
        In the observed samples the extension is passed in the "ext" parameter contained in the body of the plain text post concerned.    
    
    .PARAMETER Pass
        Specifies the mandatory password used by FTcode to encrypt files.
        In the observed samples the extension is passed in the "ek" parameter contained in the body of the plain text post concerned.
        At Certego we intercept the requests in question on the networks monitored through a suricata signature.

    .PARAMETER Path
        Specifies the optional path to restrict the scope of encrypted files to be recovered. The path is analyzed recursively.
        If the path parameter is not specified, all the disks will be recursively checked.

    .PARAMETER MinFreeDiskSpace
        Changes the parameter to skip all the disks with less free bytes of the inserted integer.
        Default = 50000 free bytes.
        This parameter is checked only if the path parameter has not been specified.

    .PARAMETER MaxByteSize2Decrypt
        [WARNING] Incorrectly changing this parameter may make the files unrecoverable.
        Specifies the optional parameter that allows you to change the maximum number of bytes to be decrypted.
        This parameter was only added for possible code changes by malware authors.

    .EXAMPLE
        powershell -Executionpolicy Bypass -Command "Import-Module -Name .\FTdecryptor.ps1; Invoke-FTdecryptor -Verbose -Pass <ek > -Extension <ext>" -Log

    .EXAMPLE
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/certego/ransomware_decryptors/master/FTdecryptor/FTdecryptor.ps1')); Invoke-FTdecryptor -Verbose -Pass <ek > -Extension <ext> -Log

    .LINK
        http://certego.net/<FTdecryptor>
    #>

    [CmdletBinding(DefaultParameterSetName='GoSafe')]

    Param(
        [Parameter(Mandatory=$false,ParameterSetName = 'GoSafe')][string]$BackupPath= (get-location).Path + '\ftdecryptor_' + (get-date).tostring("MM-dd-yyyy"),
        [Parameter(Mandatory=$false,ParameterSetName = 'GoBrutal')][switch]$Force=$false,
        [Parameter(Mandatory=$true)][string]$Extension,
        [Parameter(Mandatory=$true)][string]$Pass,
        [Parameter(Mandatory=$false)][string]$Path,
        [Parameter(Mandatory=$false)][switch]$Log,
        [Parameter(Mandatory=$false)][string]$LogPath= (get-location).Path + '\ftdecryptor_'+ (get-date).tostring("MM-dd-yyyy") + '.log',
        [Parameter(Mandatory=$false)][int]$MaxByteSize2Decrypt=[int]40960, ### be careful to change this parameter
        [Parameter(Mandatory=$false)][int]$MinFreeDiskSpace=[int]50000,
	    [Parameter(Mandatory=$false)][string]$Version="1018.1",
        [Parameter(Mandatory=$false)][switch]$Help=$false
    )
    function FtDecrypt($bytefilein, $passin){

        $salt="BXCODE hack your system"
        $init="BXCODE INIT"
        $RijndaelObj = New-Object System.Security.Cryptography.RijndaelManaged  
        $bytepass = [Text.Encoding]::UTF8.GetBytes($passin)
        $salt = [Text.Encoding]::UTF8.GetBytes($salt)
        $RijndaelObj.Key = (New-Object Security.Cryptography.PasswordDeriveBytes $bytepass, $salt, "SHA1", 5).GetBytes(32)
        $RijndaelObj.IV = (New-Object Security.Cryptography.SHA1Managed).ComputeHash( [Text.Encoding]::UTF8.GetBytes($init) )[0..15]
        $RijndaelObj.Padding="Zeros"
        $RijndaelObj.Mode="CBC"
        $decryptor = $RijndaelObj.CreateDecryptor()
        $memorystream = New-Object IO.MemoryStream
        $cryptostream = New-Object Security.Cryptography.CryptoStream $memorystream,$decryptor,"Write"
        $cryptostream.Write($bytefilein, 0,$bytefilein.Length)
        $cryptostream.Close()
        $memorystream.Close()
        $RijndaelObj.Clear()
        return $memorystream.ToArray()
    }

    function FileRestoration($filein,$passin,$extensionin){

        Try

            {

                if (-Not ($Force))
                    {
                        Copy-Item -Path $filein.FullName -Destination $BackupPath -Force
                        Write-Verbose "[*] $($filein.FullName) backuped successfully`r"
                    }

                $fin=[io.file]::Open($filein.FullName, 'Open', 'ReadWrite')
            }

        Catch

            {
                Write-Verbose - "[!] Error, skipping file: $($filein.FullName) - i suggest you use handle.exe to see if something is blocking the file https://docs.microsoft.com/en-us/sysinternals/downloads/handle`r"
                return
            }

        if ($fin.Length -lt $MaxByteSize2Decrypt)
            {
                $len=$fin.Length
            }
            
        else
            {
                $len=$MaxByteSize2Decrypt
            }

        [byte[]]$ByteObj = New-Object byte[] $len
        $ByteFile = $fin.Read($ByteObj, 0, $ByteObj.Length)
        $fin.Position='0'
        
        try 
            {
                $decryptedbytes = FtDecrypt $ByteObj $passin
            }
        catch
            {
                Write-Verbose "[!] Error, failed to decrypt following file $($filein.FullName)`r"
                return
            } 

        write-Verbose "[*] Decrypting $($filein.FullName) with the following length: $($decryptedbytes.Length)`r"

        if (-Not ( ($decryptedbytes.Length -eq 0) -or ($decryptedbytes -eq $null) ) )
            {
                $fin.Write($decryptedbytes, 0, $decryptedbytes.Length)
            }
        
            $fin.Close()

        $newname=$filein.FullName -replace "\.$($extensionin)$",""

        if (Test-Path -Path $newname)
            {
                Write-Verbose "[!] Error , Failted to rename $newname, this file already exists. Skipping`r"
                return
            }

        Try

            {
        
                Rename-Item -Path $filein.FullName -NewName $newname -Force
            }
        Catch

            {
                Write-Verbose "[!] Error, skipping file: $($filein.FullName) - i suggest you use handle.exe to see if something is blocking the file https://docs.microsoft.com/en-us/sysinternals/downloads/handle`r"
                return
            }
                
    }

    if ($Help)
        {
            Get-Help $MyInvocation.MyCommand -Full
            return
        }
    
    if ($Log)

        {
            ### Stop any previous loggers
            $ErrorActionPreference="SilentlyContinue"
            Stop-Transcript | Out-Null
            $ErrorActionPreference = "Continue"

            ### Start Logger
            Start-Transcript -Path $LogPath -Append
        }

    if (-Not ($Force) )

        {
            if (Test-Path $BackupPath)
                {
                    if ( -Not ( Test-Path $BackupPath -PathType Container ) )
                        {
                            Write-Verbose "[!] Error: the backup path must be a directory`r"
                            return
                        }
                }
            else
                {
                    New-item -Path $BackupPath -ItemType Directory -Force
                }
        }

    if ($Extension -notmatch '^[a-z0-9]+$')
        {
            Write-Error "[!] Error: non-alphanumeric extension - $Extension`r"
            return
        }

    if ($Path)
        
        {
            try
                {
                    $encryptedfiles=Get-ChildItem -Path $Path -ErrorAction SilentlyContinue -Recurse -Force | Where-Object {$_.FullName -Match "\.$($Extension)$"} | ?{ -Not $_.PSIsContainer }
                }
            
            catch
                
                {
                    Write-Verbose "[!] Error, skipping this path: $Path"
                    return
                }
            if ( $encryptedfiles -eq $null ) {write-verbose "[!] No encrypted files were found in this path: $Path`r"; return}

            $encryptedfiles | % { FileRestoration $_ $Pass $Extension}
        }
        
    else

        {
            $excludedfolders = "windows|temp|Recycle|intel|OEM|Program Files|ProgramData"
            $LogicalDisks = Get-PSDrive|Where-Object {$_.Free -gt $MinFreeDiskSpace} | Sort-Object -Descending

            foreach ($ldisk in $LogicalDisks)
                {
                    $Path=$ldisk.Root

                    try
                        {
                            $encryptedfiles=Get-ChildItem -Path $Path -ErrorAction SilentlyContinue -Recurse -Force | Where-Object {$_.FullName -Match "\.$($Extension)$"} | ?{ -Not $_.PSIsContainer }
                        }
                    
                    catch
                        
                        {
                            Write-Verbose "[!] Error, skipping this path: $Path`r"
                            Continue
                        }

                    if ( $encryptedfiles -eq $null ) {write-verbose "[!] No encrypted files were found in this path: $Path`r"; Continue}

                    $encryptedfiles | % {

                        if ( $_.FullName -notmatch $excludedfolders )
                            {
                                FileRestoration $_ $Pass $Extension
                            }
                        }
                }
        }

        if ($Log)

            {
                # Stop Logger
                $ErrorActionPreference="SilentlyContinue"
                Stop-Transcript | Out-Null
                $ErrorActionPreference = "Continue"
            }
    }
