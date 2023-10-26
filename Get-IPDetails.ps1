[cmdletbinding()]
param (
 [parameter(ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
    [string[]]$ComputerName = $env:computername
)            
begin {}
process {
 foreach ($Computer in $ComputerName) {
  if(Test-Connection -ComputerName $Computer -Count 1 -ea 0) {
   $Networks = Get-WmiObject Win32_NetworkAdapterConfiguration -ComputerName $Computer | ? {$_.IPEnabled}
   foreach ($Network in $Networks) {
    $IPAddress  = $Network.IpAddress[0]
    $SubnetMask  = $Network.IPSubnet[0]
    $DefaultGateway = $Network.DefaultIPGateway
    $DNSServers  = $Network.DNSServerSearchOrder
    $MACAddress  = $Network.MACAddress
	$DHCPServer  = $Network.DHCPServer
    $DNSDomain  = $Network.DNSDomainSuffixSearchOrder
    
	$OutputObj  = New-Object -Type PSObject
    $OutputObj | Add-Member -MemberType NoteProperty -Name IPAddress -Value $IPAddress
    $OutputObj | Add-Member -MemberType NoteProperty -Name SubnetMask -Value $SubnetMask
    $OutputObj | Add-Member -MemberType NoteProperty -Name Gateway -Value $DefaultGateway
    $OutputObj | Add-Member -MemberType NoteProperty -Name DNSServers -Value $DNSServers
    $OutputObj | Add-Member -MemberType NoteProperty -Name MACAddress -Value $MACAddress
    $OutputObj | Add-Member -MemberType NoteProperty -Name DHCPServer -Value $DHCPServer
	$OutputObj | Add-Member -MemberType NoteProperty -Name DNSDomain -Value $DNSDomainSuffixSearchOrder
	$OutputObj |
	
   }
  }
 }
}            
end {}