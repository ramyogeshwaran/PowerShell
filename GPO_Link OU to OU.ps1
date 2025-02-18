# This Script is link the GPO's from source OU GPO to Destination OU GPO with the same link order.


# Define source and destination OUs
$sourceOU = "OU=Logistik-Client,DC=test,DC=biz"
$destinationOU = "OU=Test_TaskbarAlignment_Left,DC=test,DC=biz"

# Get the linked GPOs from the source OU
$sourceGpoLinks = Get-GPInheritance -Target $sourceOU | Select-Object -ExpandProperty GpoLinks

# Get existing GPO links in the destination OU
$existingGpoLinks = Get-GPInheritance -Target $destinationOU | Select-Object -ExpandProperty GpoLinks
$existingGpoNames = $existingGpoLinks.DisplayName  # Extract existing GPO names to avoid duplicates

# Apply GPO links to the destination OU in the same order, only if not already linked
foreach ($gpo in $sourceGpoLinks) {
    if ($gpo.DisplayName -notin $existingGpoNames) {
        New-GPLink -Name $gpo.DisplayName -Target $destinationOU -Order $gpo.Order
    }
}

Write-Host "GPOs from $sourceOU have been linked to $destinationOU in the same order. Existing links remain unchanged."
