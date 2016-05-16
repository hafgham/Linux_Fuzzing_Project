#include "syscall_def.h"

const scall_desc*  get_scall_desc(int scid)
{
    int scidx;

    if (scid < 0)
      return NULL;

    for (scidx=0; scidx<SYSCALL_NUM; scidx++)
    {
        if (fuzzer_call_spec_list[scidx].scid == scid)
            return &fuzzer_call_spec_list[scidx];
    }

    return NULL;
}
