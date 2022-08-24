$text = @"
 _    _ _            ______          _  ______           _ 
| |  | (_)           | ___ \        | | |  ___|         | |
| |  | |_ _ __ ______| |_/ /__  _ __| |_| |___      ____| |
| |/\| | | '_ \______|  __/ _ \| '__| __|  _\ \ /\ / / _` |
\  /\  / | | | |     | | | (_) | |  | |_| |  \ V  V / (_| |
 \/  \/|_|_| |_|     \_|  \___/|_|   \__\_|   \_/\_/ \__,_|
                                                          
Author : DeepZec

Modified by Sajibu																							
"@
write-host -fore green $text
If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))

{   
$arguments = "& '" + $myinvocation.mycommand.definition + "'"
Start-Process powershell -Verb runAs -ArgumentList $arguments
Break
}
do {
    do {
		write-host ""
        write-host "A - Setup a port forwarding"
        write-host "B - Show current fowarding list"
        write-host "C - Remove a specifc forwarding"
        write-host "D - Remove all forwarding"
        write-host ""
        write-host "X - Exit"
        write-host ""
        write-host -nonewline "Type your choice and press Enter: "
        
        $choice = read-host
        
        write-host ""
        
        $ok = $choice -match '^[abcdx]+$'
        
        if ( -not $ok) { write-host "Invalid selection" }
    } until ( $ok )
    
    switch -Regex ( $choice ) {
        "A"
        {
			do {
			$Lhost = Read-Host -Prompt 'Enter the Local IP Addres that the traffic will come from'
			$ok = $Lhost -match "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
			if ( -not $ok) { write-host "Invalid host address" }
				} until ( $ok )
				
			do {
            $Lport = Read-Host -Prompt 'Enter the Local Port Number that the traffic will come from'
			$ok = [int]$Lport -le 65535
			if ( -not $ok) { write-host "Invalid Port Number" }
				} until ( $ok )
			
			do {
			$Rhost = Read-Host -Prompt 'Enter the Remote IP Addres that traffic needs to go to'
			$ok = $Lhost -match "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
			if ( -not $ok) { write-host "Invalid host address" }
				} until ( $ok )
			
			do {
			$Rport = Read-Host -Prompt 'Enter the Remote Port Number that traffic needs to go to'
			$ok = [int]$Lport -le 65535 
			if ( -not $ok) { write-host "Invalid Port Number" }
				} until ( $ok )
				
			if ( -not $ok) { write-host "Invalid user input" }
			
			else {
			netsh interface portproxy add v4tov4 listenaddress=$Lhost listenport=$Lport connectaddress=$Rhost connectport=$Rport
            netsh advfirewall firewall add rule name="forward_port_rule_in" protocol=TCP dir=in localip=$Lhost localport=$Lport action=allow
            Write-Host 'Incoming firewall rule from address ' + $Lhost ' with port ' + '$Lport' + ' added as well!'
            netsh interface portproxy show all

				}
        }
        
        "B"
        {
            netsh interface portproxy show all
        }

        "C"
        {
            $Lport = Read-Host -Prompt 'Enter the Listen Port'
            $Lhost = Read-Host -Prompt 'Enter the Listen IP Address'
            netsh interface portproxy delete v4tov4 listenport=$Lport listenaddress=$Lhost
            netsh advfirewall firewall delete rule name="forward_port_rule_in" protocol=TCP dir=in localip=$Lhost localport=$Lport
            Write-Host 'Forwarding from address'$Lhost with port $Lport 'has been removed'
            Write-Host 'Incoming firewall rule from IP address'$Lhost 'with port' $Lport 'removed as well!'
            netsh interface portproxy show all
        }

        "D"
        {
            netsh interface portproxy reset
            netsh advfirewall firewall delete rule name="forward_port_rule_in" protocol=TCP dir=in localip=$Lhost localport=$Lport
            Write-Host 'All Port Forwarding has been removed!'
            netsh interface portproxy show all
        }


    }
} until ( $choice -match "X" )

