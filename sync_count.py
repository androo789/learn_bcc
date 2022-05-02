#!/usr/bin/python
#
# sync_timing.py    Trace time between syncs.
#                   For Linux, uses BCC, eBPF. Embedded C.
#
# Written as a basic example of tracing time between events.
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

from __future__ import print_function
from bcc import BPF
from bcc.utils import printb

# load BPF program
b = BPF(text="""
#include <uapi/linux/ptrace.h>

BPF_HASH(last);

int do_trace(struct pt_regs *ctx) {
    u64  key = 0; 
    u64  *cnt ;
    u64 cur_cnt;

    cnt = last.lookup(&key);
    if (cnt == NULL){
        bpf_trace_printk("%d\\n", 11);
    }
    
    if (cnt == NULL ) {
        cur_cnt = 1;
    }else{
        cur_cnt=*cnt+1;
        //last.delete(&key);
    }
    bpf_trace_printk("%d\\n", cur_cnt);
    last.update(&key, &cur_cnt);
    return 0;
}
""")


"""
1
不用delete也可以
2
cnt明明是指针，为什么不能和null比较？？
噢噢，反了，可以和null比较，但是要判断==，而不是判断！=



"""
b.attach_kprobe(event=b.get_syscall_fnname("sync"), fn_name="do_trace")
print("Tracing for quick sync's... Ctrl-C to end")

# format output
start = 0
while 1:
    try:
        (task, pid, cpu, flags, ts, ms) = b.trace_fields()
        if start == 0:
            start = ts
        ts = ts - start
        printb(b"At time %.2f s: multiple syncs detected, last %s cnt ago" % (ts, ms))
    except KeyboardInterrupt:
        exit()
