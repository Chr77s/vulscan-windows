# generate-icons.ps1
# Genere des icones PNG placeholder pour l'extension Chrome
# Lancer depuis le dossier extension/ :
#   powershell -ExecutionPolicy Bypass -File generate-icons.ps1

$sizes = @(16, 32, 48, 128)
$iconDir = Join-Path $PSScriptRoot "icons"

if (-not (Test-Path $iconDir)) {
    New-Item -ItemType Directory -Path $iconDir | Out-Null
}

Add-Type -AssemblyName System.Drawing

foreach ($size in $sizes) {
    $bmp    = New-Object System.Drawing.Bitmap($size, $size)
    $g      = [System.Drawing.Graphics]::FromImage($bmp)
    $brush  = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(255, 79, 70, 229))
    $g.FillEllipse($brush, 0, 0, $size, $size)

    # Texte "V" au centre pour les grandes tailles
    if ($size -ge 32) {
        $font     = New-Object System.Drawing.Font("Arial", [int]($size * 0.45), [System.Drawing.FontStyle]::Bold)
        $strBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::White)
        $sf       = New-Object System.Drawing.StringFormat
        $sf.Alignment       = [System.Drawing.StringAlignment]::Center
        $sf.LineAlignment   = [System.Drawing.StringAlignment]::Center
        $rect = New-Object System.Drawing.RectangleF(0, 0, $size, $size)
        $g.DrawString("V", $font, $strBrush, $rect, $sf)
    }

    $outPath = Join-Path $iconDir "icon${size}.png"
    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    Write-Host "Cree : $outPath"
    $g.Dispose()
    $bmp.Dispose()
}

Write-Host ""
Write-Host "Icones generees dans le dossier icons/"
