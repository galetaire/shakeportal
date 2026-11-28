# Builds the app's launcher icon from the artwork in art/icon.png, and the
# logo shown at the top of the app's screen from art/icon2.png.
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
    # Only the opaque square counts: transparent margins in the file (the
    # artwork may be a few pixels taller than wide) would shift it off-centre.
    # Found along the middle row and column, which the square crosses.
    $midX = [int]($src.Width / 2); $midY = [int]($src.Height / 2)
    $top = 0; while ($top -lt $src.Height - 1 -and $src.GetPixel($midX, $top).A -eq 0) { $top++ }
    $bottom = $src.Height - 1; while ($bottom -gt $top -and $src.GetPixel($midX, $bottom).A -eq 0) { $bottom-- }
    $left = 0; while ($left -lt $src.Width - 1 -and $src.GetPixel($left, $midY).A -eq 0) { $left++ }
    $right = $src.Width - 1; while ($right -gt $left -and $src.GetPixel($right, $midY).A -eq 0) { $right-- }
    $crop = New-Object System.Drawing.Rectangle $left, $top, ($right - $left + 1), ($bottom - $top + 1)
    $height = [int]($art * $crop.Height / $crop.Width)
    $dest = New-Object System.Drawing.Rectangle ([int](($canvas - $art) / 2)), ([int](($canvas - $height) / 2)), $art, $height
    $g.DrawImage($src, $dest, $crop, [System.Drawing.GraphicsUnit]::Pixel)
    $g.Dispose()
    New-Item -ItemType Directory -Force (Split-Path -Parent $target) | Out-Null
    $bmp.Save($target, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
} finally {
    $src.Dispose()
}
Write-Output "Wrote $target from $source"

# The logo at the top of the app's screen (44 dp, so at most 176 px) comes
# from art/icon2.png, the round artwork, scaled down to 192 px
$logoSource = Join-Path $root "art\icon2.png"
$logoTarget = Join-Path $root "app\src\main\res\drawable-nodpi\logo.png"
$size = 192
$src = [System.Drawing.Image]::FromFile($logoSource)
try {
    $bmp = New-Object System.Drawing.Bitmap $size, $size
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
    $g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    $g.DrawImage($src, 0, 0, $size, $size)
    $g.Dispose()
    $bmp.Save($logoTarget, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
} finally {
    $src.Dispose()
}
Write-Output "Wrote $logoTarget from $logoSource"
