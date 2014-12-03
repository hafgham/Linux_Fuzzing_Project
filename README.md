Linux_Fuzzing_Project
=====================

Linux Kernel System Calls Fuzzing 

Changelog
=========


0.1 Proof Of Concept(POC)
---------
Basic draft. 

Here we are calling `sys_chdir()` syscall 20 times in a loop 
with not just a random binary data as input, but kind of highly poisoned
variable length, variable tree depth path string with some nonASCII \
symbols (which in log substituted with '_' char to not break text output).
We can see here no hangs no crashes. Instead syscall returns '-1'
as designed by smart Linux devs for any incorrect path input.
