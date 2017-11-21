# CVE-2017-11882 Exploit

CVE-2017-11882 Exploit accepts 109 bytes long command in maximum.

This exploit will call WinExec with SW_HIDE and call ExitProcess after WinExec returns.

I cannot find a reference for the object structure...so I cannot change the file length for arbitrary length code execution..:(

Please issue me if you know how to enlarge the payload , thanks.

## Usage
```
usage: CVE-2017-11882.py [-h] -c CMD -o OUTPUT

PoC for CVE-2017-11882

optional arguments:
  -h, --help            show this help message and exit
  -c CMD, --cmd CMD     Command run in target system
  -o OUTPUT, --output OUTPUT
                        Output exploit rtf
```

Example:

```
CVE-2017-11882.py -c cmd.exe -o test.rtf
```
## Debug

 1. Set debugger value to your debugger path in HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\EQNEDT32.EXE

 2. Build a exploit and run it.
 
 3. Set break point at 0x41165f
 
 4. This break point will be hit twice, at second time the payload will be executed after this function returned.
