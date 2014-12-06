#ifndef SANDBOX_H_INCLUDED
#define SANDBOX_H_INCLUDED

#include "syscall_def.h"

#define SANDBOX_DIR  "./sandbox"    // related to current (returned by pwd)

#define SANDBOX_REGION_NUM    3                   // max number of arguments for fuzzing per call
#define SANDBOX_REGION_SIZE   MAX_ULONG_BUFSIZE   // to be sure we can safely place biggest arg (like file path, buffer) + some safety space

#define MAX_LEN_STR		        4000
#define MAX_LEN_PATH		      1024
#define MAX_LEN_FNAME         128
#define PROB_STR_NONASCII	    5  // percents

// each process will obtain it's own copy of sandbox, so don't need to care about access safety
char sandbox[SANDBOX_REGION_NUM][SANDBOX_REGION_SIZE];

#define FD_STATE_CLOSED    128

#define FD_POOL_NUM_ROPEN   50  // number of open for reading fd's at fuzzer start
#define FD_POOL_NUM_WOPEN   50  // number of open writing fd's at fuzzer start
#define FD_POOL_NUM_CLOSED  10  // number of closed fd's at fuzzer start

// item of fd pool
typedef struct
{
  int       fd;
  mode_t    mode;        // one of the O_RDONLY, O_WRONLY, and O_RDWR
  int       last_scid;       // which syscall id was applied to this fd last time

} fd_pool_item;

// fill fd_pool with open and closed fd's
int fd_pool_populate();
long int  sandbox_syscall_run(int scid, FILE* log_stream);

#endif // SANDBOX_H_INCLUDED
