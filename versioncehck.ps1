# Google Chrome
$content = curl.exe -k -L -s "https://chromereleases.googleblog.com/search/label/Desktop%20Update"

$chromeVersion = ([regex]::Match(
    $content,
    '(\d+\.\d+\.\d+\.\d+)/(\d+)\s+for Windows'
)).Value

# Notepad++
$content = curl.exe -k -L -s "https://notepad-plus-plus.org/news/"

$nppVersion = ([regex]::Match(
    $content,
    'Current Version\s+([0-9\.]+)'
)).Groups[1].Value

# Adobe Acrobat Reader DC
$content = curl.exe -k -L -s "https://www.adobe.com/devnet-docs/acrobatetk/tools/ReleaseNotesDC/index.html"

$adobeVersion = ([regex]::Match(
    $content,
    '\b\d{2}\.\d{3}\.\d{5}\b'
)).Value

$adobeDate = ([regex]::Match(
    $content,
    '\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{1,2},\s+\d{4}\b'
)).Value

@(
    [PSCustomObject]@{
        Application = 'Google Chrome'
        Version     = $chromeVersion
        ReleaseDate = ''
    }

    [PSCustomObject]@{
        Application = 'Notepad++'
        Version     = $nppVersion
        ReleaseDate = ''
    }

    [PSCustomObject]@{
        Application = 'Adobe Acrobat Reader DC'
        Version     = $adobeVersion
        ReleaseDate = $adobeDate
    }
)
