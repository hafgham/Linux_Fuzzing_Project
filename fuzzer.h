#ifndef FUZZER_H_INCLUDED
#define FUZZER_H_INCLUDED

#define SELF_VERSION        "0.5"

//uncomment to debug fork stuff
//#define DEBUG_FORK         // used to see detailed process table updates

//multiprocess defines
#define WORKER_NUM          4
#define PPD_SIZE            WORKER_NUM+2

#define PROC_TYPE_DEF       -1   // default,  used as argument to autodetect, etc
#define PROC_TYPE_MAIN      0
#define PROC_TYPE_WD        1
#define PROC_TYPE_WORKER    2
#define PROC_TYPE_SHELL     3   // process is command line shell to display status, etc

int log_(int pid, const char *src, int ptype);

#endif // FUZZER_H_INCLUDED
