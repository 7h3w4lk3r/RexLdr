# RexLdr  
### Rex is a simple shellcode loader i developed for AV/EDR evasion tests. following techniques are implemented in this loader:  
    
* RC4 encrypted payload  
* Dynamic API calls  
* String obfuscation  
* MapView shellcode injection ( by default on explorer.exe )  
* Sleep timer ( 5 secs, tick count )
* Sandbox check ( number of running processes and CPU cores )  

## Usage

#### 1. Generate the shellcode using your C2 framework (tested with Havoc, Metasploit & CobaltStrike):
* `msfvenom -p windows/x64/exec cmd=calc.exe exitfunc=thread -f raw -o calc.bin`

#### :warning: Exit function should be set to thread, otherwise the host process will crash and your shellcode won't get executed :warning:  

#### 2. Use the `rc4.py` script to generate a rc4 encrypted shellcode from a binary file (calc.bin for example) with a random key:
* `python3 rc4.py calc.bin`  

#### 3. replace the generated shellcode and key in the project source  
#### 4. build in release mode  
#### 5. Drop it and pop a shell :)  

## Tips
#### Sleep timer is set to 5 seconds, sandbox check for number of running processes is set to 20 and CPU core check is set to more than 2 cores. change these to suit your needs.  
#### Target process for MapView injection is explorer.exe ( tested ), you can change that if you want.  
