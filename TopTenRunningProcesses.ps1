$properties=@(

   @{Name="Process Name"; Expression = {$_.name}},

   @{Name="CPU (%)"; Expression = {$_.PercentProcessorTime}},    

   @{Name="Memory (MB)"; Expression = {[Math]::Round(($_.workingSetPrivate / 1mb),2)}}

)

Get-WmiObject -class Win32_PerfFormattedData_PerfProc_Process |

   Select-Object $properties |

   Sort-Object "CPU (%)" -Descending |

   select -First 10 |

   Format-Table -AutoSize