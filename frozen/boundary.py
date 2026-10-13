"""R18A Linux boundary: reviewed R10 Landlock design with thread-only clone.

Install before importing numerical libraries. New threads inherit restrictions;
clone3 returns ENOSYS so libc uses auditable clone flags. No process/network
creation. No fallback. This is additive, not a change to the frozen R10 boundary.
"""
import ctypes
import errno
import os
from pathlib import Path
import platform
import sys


def restrict(read, write):
    if sys.platform != 'linux' or platform.machine() != 'x86_64':
        raise RuntimeError('QUALIFIED_LINUX_X86_64_REQUIRED')
    libc=ctypes.CDLL(None,use_errno=True);libc.syscall.restype=ctypes.c_long
    if libc.syscall(444,0,0,1)<3:raise RuntimeError('LANDLOCK_ABI_3_REQUIRED')
    class Rules(ctypes.Structure):_fields_=[('fs',ctypes.c_uint64)]
    class Beneath(ctypes.Structure):
        _pack_=1
        _fields_=[('access',ctypes.c_uint64),('fd',ctypes.c_int32)]
    attr=Rules((1<<15)-1);fd=libc.syscall(444,ctypes.byref(attr),ctypes.sizeof(attr),0)
    if fd<0:raise OSError(ctypes.get_errno(),'LANDLOCK_CREATE')
    try:
        for item,writable in [(p,False) for p in read]+[(p,True) for p in write]:
            p=Path(item).resolve(strict=True);access=1|4|(8 if p.is_dir() else 0)
            if writable:
                access|=2|(1<<14)
                if p.is_dir():access|=(1<<4)|(1<<5)|(1<<7)|(1<<8)|(1<<12)
            pfd=os.open(p,os.O_PATH|os.O_CLOEXEC)
            try:
                rule=Beneath(access,pfd)
                if libc.syscall(445,fd,1,ctypes.byref(rule),0):raise OSError(ctypes.get_errno(),'LANDLOCK_RULE')
            finally:os.close(pfd)
        if libc.prctl(38,1,0,0,0) or libc.syscall(446,fd,0):raise OSError(ctypes.get_errno(),'LANDLOCK_INSTALL')
    finally:os.close(fd)
    class Filter(ctypes.Structure):_fields_=[('code',ctypes.c_ushort),('jt',ctypes.c_ubyte),('jf',ctypes.c_ubyte),('k',ctypes.c_uint)]
    class Program(ctypes.Structure):_fields_=[('length',ctypes.c_ushort),('filters',ctypes.POINTER(Filter))]
    deny=0x00050000|errno.EPERM;allow=0x7fff0000
    rows=[(0x20,0,0,4),(0x15,1,0,0xc000003e),(0x06,0,0,0x80000000),
          (0x20,0,0,0),(0x45,0,1,0x40000000),(0x06,0,0,0x80000000)]
    for nr in (41,53,57,58,62,101,200,234,250,298,304,310,311,321,323):
        rows += [(0x15,0,1,nr),(0x06,0,0,deny)]
    rows += [(0x15,0,1,435),(0x06,0,0,0x00050000|errno.ENOSYS)]
    # clone must include CLONE_VM | CLONE_SIGHAND | CLONE_THREAD.
    rows += [(0x15,0,4,56),(0x20,0,0,16),(0x54,0,0,0x10900),
             (0x15,1,0,0x10900),(0x06,0,0,deny),(0x06,0,0,allow)]
    filters=(Filter*len(rows))(*(Filter(*r) for r in rows));program=Program(len(rows),filters)
    if libc.prctl(22,2,ctypes.byref(program),0,0):raise OSError(ctypes.get_errno(),'SECCOMP_INSTALL')
