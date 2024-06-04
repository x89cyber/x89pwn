# x89pwn
Collection of pwning helper functions
## Functions
#### is_port_connected(port)
Determine if the port is in "ESTABLISHED" state using netstat.

#### bytes_to_escaped_str(bytestring)
Convert a bytestring to an escaped string with the byte code representation for printable and non-printable chars.  Ex. "\x0a\x10\x00\xff"

#### xformatbytes(raw_bytes)
Similar to bytes_to_escaped_str() - formats a bytestring into \xxx format. Prints a message for the length of the bytes output.

#### msf_patern_create(length)
Create a non-repeatable pattern with metaploit msf-pattern_create and return as a byte string.
    
    Requirements:
    metasploit must be installed and in the path.
    
    Attributes:
    length: length of the pattern to create.
    
#### msf_generate_shellcode(payload, lhost, lport, b=None, e="x86/shikata_ga_nai", x="process", force=True)
Generate shellcode using msfvenom with dynamic arguments.

    Requirements:
    metasploit must be installed and in the path.

    Attributes:
    payload: The payload to use (e.g., 'windows/meterpreter/reverse_tcp').
    lhost: The LHOST value (attacker IP).
    lport: The LPORT value (listening port).
    b: bytestring of badchars; syntax is b'\\x00\\x0a\\x0d'. Default is None (no encoding).
    e: The '-e' argument, encoding used for the shellcode.  Default is 'x86/shikata_ga_nai'. 
    x: exit function: process, thread, seh, none
    force: force the shellcode generation - if False read from the cache if it exists
    return: The generated shellcode as a bytestring, or throw an exception.
    
#### all_chars(bad_chars, start=0x01)
Return a bytestring of all characters excluding those in the bad_chars list.
    
    Attributes:
    bad_chars: bytes to exclude in hex format, ex. b'\x00\x0a'
    start: byte to start at - defaults to 0x01
    
#### egghunter_x86_seh(egg=b"w00t")
Return an x86 egghunter shellcode that implements it's own exception handler.
  
    Attributes:
    egg: the 4 byte string to search for twice.  Default is "w00t" and search for "w00tw00t".
  
#### egghunter_x86_syscall(syscall, egg=b"w00t")
Return the x86 NtAccessCheckAndAuditAlarm system call egghunter shellcode based on original Matt Miller exploit.  
  
    Note: The system call number is pased to the syscall variable. This varies by version of windows after windows 7. Lookup 
        the syscall number in WinDbg with this call:  u ntdll!NtAccessCheckAndAuditAlarm, and look for the value moved to eax.

    Attributes:
    syscall: Windows x86 system call number for NtAccessCheckAndAuditAlarm.  Pass this is a hex value, ex. 0x1c8.
    egg: the 4 byte egg to search for twice.  Default is "w00t" and search is for "w00tw00t".

#### rop_stub_VirtualAlloc()
Return the VirtualAlloc API stub for DEP bypass using ROP.

#### rop_stub_VirtualAllocEx()
Return the VirtualAllocEx API stub for DEP bypass using ROP.

#### rop_stub_VirtualProtect(vp_addr=0x60606060, lpAddress=0x61616161, dwSize=0xffffffff, flNewProtect=0xffffffc0, lpflOldProtect=0x65656565)
Return the VirtualProtect API stub for DEP bypass using ROP.  

    Attributes:
    vp_addr: VirtualProtect address
    lpAddress: ShellCode address
    dwSize: default to -0x01
    flNewProtect: default to -0x40
    lpflOldProtect: DWORD pointer to writable memory

#### rop_stub_WriteProcessMemory(wpm_addr, code_cave_addr, dword_addr)
Return the WriteProcessMemory API stub for DEP bypass using ROP.

    Attributes:
    wpm_addr: address of WriteProcessMemory function
    code_cave_addr: address of the code cave to write shellcode to
    dword_addr: address of a location the number of bytes written can be written to
  
