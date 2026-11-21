# Builds the app's launcher icon from the artwork in art/icon.png.
#
# art/icon.png is the full icon: a blue rounded square with the disc on it.
# Android draws app icons in its own shape (circle, squircle, ...), so the
# app uses an adaptive icon: the blue as a plain background colour
# (res/values/colors.xml) and the artwork, scaled down so the disc fits the
# shape's safe zone, as the foreground. This writes that foreground:
#   app/src/main/res/drawable-nodpi/ic_launcher_foreground.png
#
# Run it after changing art/icon.png, then build the app as usual:
#   .\scripts\make-icon.ps1
# If the background blue changes, also change icon_background in
# app/src/main/res/values/colors.xml.

$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Drawing

$root = Split-Path -Parent $PSScriptRoot
$source = Join-Path $root "art\icon.png"
$target = Join-Path $root "app\src\main\res\drawable-nodpi\ic_launcher_foreground.png"

# The icon canvas is 108 dp; drawn at 4x (432 px). The artwork takes the
# middle 84 dp, so its disc stays inside the 66 dp every launcher shows.
$canvas = 432
$art = 336

$src = [System.Drawing.Image]::FromFile($source)
try {
    $bmp = New-Object System.Drawing.Bitmap $canvas, $canvas
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
    $g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    $height = [int]($art * $src.Height / $src.Width)
    $g.DrawImage($src, [int](($canvas - $art) / 2), [int](($canvas - $height) / 2), $art, $height)
    $g.Dispose()
    New-Item -ItemType Directory -Force (Split-Path -Parent $target) | Out-Null
    $bmp.Save($target, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
} finally {
    $src.Dispose()
}
Write-Output "Wrote $target from $source"
