# MSFStager-DInvoke-MM
Metasploit C# Two-Stage dropper using Dynamic Win32 API calls and manual mapping of kernel32.dll

As of <u>30-07-2023</u> this results on an undetected Meterpreter session \[at least\] against the following products with default installation settings:
- Windows Defender
- Avira Internet Security
- AVG Antivirus Free
- ESET Smart Security

## How it works

-Generate a metasploit stager shellcode using the windows/x64/meterpreter/reverse_tcp_rc4 payload and x64/xor encoder

-Python server serves the first stage shellcode

-C# dropper retrieves the first stage shellcode and invokes it using dynamic Win32 API calls (manual mapping of kernel32.dll)

-First stage shellcode connects to multi/handler and retrieves second stage

-Meterpreter session is established


https://blindsecurity.gr/site/2023/07/30/av-evasion-using-dinvoke-two-stage-payload-and-rc4-in-meterpreter/

## 
![alt text](https://github.com/k4z01/MSFStager-DInvoke-MM/blob/main/test.gif?raw=true)
