# Generate all icons under src-tauri/icons/ (PNG sizes + PNG-in-ICO container).
# Usage: powershell -ExecutionPolicy Bypass -File scripts/gen-icons.ps1
# NOTE: ASCII-only on purpose. Windows PowerShell 5.1 reads BOM-less files as
# ANSI/GBK, and CJK comment bytes can swallow the trailing newline and comment
# out the next line. Keep this script ASCII-only.

Add-Type -AssemblyName System.Drawing

$dir = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\src-tauri\icons"))
New-Item -ItemType Directory -Force -Path $dir | Out-Null

function New-Icon {
    param([int]$Size, [string]$OutFile)
    $bmp = New-Object System.Drawing.Bitmap $Size, $Size
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit

    # Deep indigo base (plain rectangle: simple and reliable)
    $bg = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(255, 30, 58, 138))
    $g.FillRectangle($bg, 0, 0, $Size, $Size)

    # Slightly lighter band on top for depth
    $band = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(255, 42, 76, 168))
    $bandH = [int][math]::Floor($Size * 0.42)
    $g.FillRectangle($band, 0, 0, $Size, $bandH)

    # "SHU" centered
    $font = New-Object System.Drawing.Font ("Segoe UI", ($Size * 0.30), [System.Drawing.FontStyle]::Bold, [System.Drawing.GraphicsUnit]::Pixel)
    $fg = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::White)
    $fmt = New-Object System.Drawing.StringFormat
    $fmt.Alignment = [System.Drawing.StringAlignment]::Center
    $fmt.LineAlignment = [System.Drawing.StringAlignment]::Center
    $box = New-Object System.Drawing.RectangleF 0, 0, $Size, $Size
    $g.DrawString("SHU", $font, $fg, $box, $fmt)

    # Green status dot, bottom-right
    $dot = [int][math]::Floor($Size * 0.16)
    if ($dot -lt 2) { $dot = 2 }
    $green = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(255, 52, 199, 123))
    $gx = $Size - $dot - [int][math]::Floor($Size * 0.10)
    $g.FillEllipse($green, $gx, $gx, $dot, $dot)

    $g.Dispose()
    $bmp.Save($OutFile, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    Write-Host "OK  $OutFile ($Size x $Size)"
}

New-Icon -Size 32  -OutFile (Join-Path $dir "32x32.png")
New-Icon -Size 128 -OutFile (Join-Path $dir "128x128.png")
New-Icon -Size 256 -OutFile (Join-Path $dir "128x128@2x.png")
New-Icon -Size 512 -OutFile (Join-Path $dir "icon.png")

# icon.ico: wrap the 256x256 PNG into an ICO container (PNG-in-ICO is standard)
$src = Join-Path $dir "128x128@2x.png"
if (-not (Test-Path -LiteralPath $src)) { throw "missing source image: $src" }
$png = [System.IO.File]::ReadAllBytes($src)
if ($png.Length -le 0) { throw "empty source image: $src" }
$icoPath = Join-Path $dir "icon.ico"
$fs = [System.IO.File]::Create($icoPath)
$bw = New-Object System.IO.BinaryWriter ($fs)
$bw.Write([uint16]0)              # reserved
$bw.Write([uint16]1)              # type = icon
$bw.Write([uint16]1)              # count
$bw.Write([byte]0)                # width 256 -> 0
$bw.Write([byte]0)                # height 256 -> 0
$bw.Write([byte]0)                # palette
$bw.Write([byte]0)                # reserved
$bw.Write([uint16]1)              # planes
$bw.Write([uint16]32)             # bpp
$bw.Write([uint32]$png.Length)
$bw.Write([uint32]22)             # offset = 6 + 16
$bw.Write([byte[]]$png)
$bw.Dispose()
Write-Host "OK  $icoPath (256 png-in-ico, $($png.Length) bytes)"
Write-Host "icons generated -> $dir"
