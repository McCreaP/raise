# Raise

> The default action of certain signals is to cause a process to terminate and produce a core dump file, a disk file containing an image of the process's memory at the time of termination. - man 5 core

Programm `raise` recreates a terminated process from a core dump file. 

It's not advised to `raise` a process that died because of a "natural" `SIGSEV`. Recreated process will reexecute a problematic instruction and terminate instantly.

## Limitations

The program works with 32-bits processes on x86 processors. Moreover:
* core dump doesn’t contain information about open files - program `raise` assumes there were no open files except stdin, stdout, and stderr,
* it can't be ensured that the new process will have exactly the same PID as the original one,
* it's assumed a terminated process didn’t use threads,
* some state of the process, e.g. related to the memory layout (see: `man 2 prctl`), can’t be recreated based on a core file.

Additionally, we assume the standard memory layout of a terminated process - we assume memory below the standard loading address `0x8048000` was unused.

## Build

`make all` builds a program `raise` which can be invoked with a command `./raise <core_dump>`.
