<#
.Synopsis
   
   Carbon Black (Live) Response Script

   Author: Caabv

.DESCRIPTION
   Script for Carbon Black Response Live Response - Putting KAPE on target sensor, executing and exfiltrating data
.EXAMPLE
   N/A - Will be executed with CbR_Kape.py
#>

$KapePath = 'C:\Windows\CarbonBlack\Tools\kape\Kape.exe'
$ZipPath = 'C:\Windows\CarbonBlack\Tools\'
$KapeArg = '--tsource C: --tdest C:\temp\kape\collect --tflush --target !BasicCollection --vss --zip KFF --msource C:\temp\kape\collect --mdest C:\temp\kape\process --mflush --zm true --module !EZParser --mef csv --zpw forensics'

function Invoke-Kape
{
    Start-Process -FilePath $KapePath $KapeArg -NoNewWindow -Wait
}

function Invoke-Uncompression
{
    Expand-Archive -LiteralPath $ZipPath'Kape.zip' -DestinationPath $ZipPath | Out-Null
}

function Invoke-Compression
{
    Compress-Archive -Path 'C:\temp\kape' -DestinationPath 'C:\temp\KFF.zip' | Out-Null
}

function Invoke-CleanUp 
{
    Remove-Item 'C:\temp\kape' -Recurse -Confirm:$false -Force
}

function Get-Forensics 
{
    Invoke-Uncompression
    Invoke-Kape
    Invoke-Compression
    Invoke-CleanUp    
}

Get-Forensics
