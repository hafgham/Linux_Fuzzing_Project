#define _XOPEN_SOURCE 500
#define _GNU_SOURCE

#include <ftw.h>

#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include <fcntl.h>
#include <ftw.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

#include <linux/limits.h>
#include <time.h>
#include <utime.h>

#include "sandbox.h"

static char callback_path_tmp[PATH_MAX];
static int  callback_fuz_arg;

// prepopulated pool of file descriptors
static fd_pool_item   fd_pool[FD_POOL_NUM_ROPEN + FD_POOL_NUM_WOPEN + FD_POOL_NUM_CLOSED];
static int            fd_pool_cnt = 0;
static fd_pool_item*  last_fd_used;

// helper rand generator - return rand within given range
int rrand(int min, int max)
{
  assert(min <= max);
  return min + rand() % (max - min + 1);
}

// find fd in pool which fits access mode specified with fuz_arg
fd_pool_item*  find_fd_in_pool( int fuz_arg )
{
  int i;
  mode_t  mode;

  // simple mapping
  if (fuz_arg == FUZ_ARG_UINT_FD_ROPEN)
    mode = O_RDONLY;
  else
  if (fuz_arg == FUZ_ARG_UINT_FD_WOPEN)
    mode = O_WRONLY;
  else
    mode = FD_STATE_CLOSED;

  // find item which meet mode
  for (i=0; i<sizeof(fd_pool); i++)
  {
    if (fd_pool[i].mode == mode)
      return &fd_pool[i];
  }

  return &fd_pool[sizeof(fd_pool)-1];
}

//****************************************************
void helper_gen_fuz_str(char* ptr, int cnt)
{
    int i;

    for (i=0; i<cnt; i++)
    {
        *(ptr+i) =  (rand()%100 < PROB_STR_NONASCII)? rand() % 256 : rrand(97, 122);
    }
}

// used inside nftw() call to process dir tree hierarchies
static int callback_get_path(const char *fpath, const struct stat *sb, int tflag, struct FTW *ftwbuf)
{
   if (rand() % 50 < 2)
   {
     // we need dir and current item is also dir
     if (callback_fuz_arg == FUZ_ARG_PATH_DIR_EXIST)
     {
       if (tflag == FTW_D)
          {
            strcpy(callback_path_tmp, fpath);
            return 1;  // stop traversal
          }
      else
         return 0;  // continue traversal
     }

     // we need a file and current item is also a file
     if (callback_fuz_arg == FUZ_ARG_PATH_FILE_EXIST)
     {
       if (tflag == FTW_F)
          {
            strcpy(callback_path_tmp, fpath);
            return 1; // stop traversal
          }
      else
         return 0; // continue traversal
     }

     return 1; // stop traversal
   }

   return 0;  // continue traversal
}

// generate path string according to argument:
// FUZ_ARG_PATH_FILE_EXIST - path to existing file
// FUZ_ARG_PATH_FILE_NONEXIST - valid path to nonexisting file/dir
// FUZ_ARG_PATH_DIR_EXIST - valid path to existing dir
// path will be always inside dir specified with SANDBOX_DIR
int gen_path( int fuz_arg, char* dst )
{
  // generate nonexisting file path
  if (fuz_arg == FUZ_ARG_PATH_FILE_NONEXIST)
  {
    int len =  rand() % MAX_LEN_PATH;
    int chunk_len;
    int cnt = 1;

    dst[0] = '/';

    while (cnt < len)
    {
      chunk_len = rand() % MAX_LEN_FNAME;
      helper_gen_fuz_str(dst+cnt, chunk_len);
      cnt += (chunk_len-1);
      dst[cnt] = '/'; cnt++;
    }

    dst[cnt] = 0;
    return 0;
  }

  //let's choose random directory in ./sandbox subtree
  callback_fuz_arg = fuz_arg;
  nftw(SANDBOX_DIR, callback_get_path, 1, /*FTW_DEPTH*/0 );

  strcpy(dst, callback_path_tmp);

  return 0;
}

// used inside nftw() call to process dir tree hierarchies
static int callback_fd_pool_populate(const char *fpath, const struct stat *sb, int tflag, struct FTW *ftwbuf)
{
   int res1, res2;

   // is our pool already full?
   if (fd_pool_cnt >= (FD_POOL_NUM_ROPEN + FD_POOL_NUM_WOPEN + FD_POOL_NUM_CLOSED))
     return 1; // stop traversal

   if (tflag == FTW_F )
   {
     if (fd_pool_cnt > FD_POOL_NUM_WOPEN)
        {
          // closed fd's
          res1 = open(fpath, O_RDONLY );
          res2 = close(res1);

          if (res1 != -1 && res2 == 0)
          {
            fd_pool[fd_pool_cnt].fd = res1;
            fd_pool[fd_pool_cnt].mode = FD_STATE_CLOSED;
            fd_pool[fd_pool_cnt].last_scid = -1;
            fd_pool_cnt++;
          }
        }
        else
        if (fd_pool_cnt > FD_POOL_NUM_ROPEN)
        {
          // write opened  fd's
          res1 = open(fpath, O_WRONLY );

          if (res1 != -1)
          {
            fd_pool[fd_pool_cnt].fd = res1;
            fd_pool[fd_pool_cnt].mode = O_WRONLY;
            fd_pool[fd_pool_cnt].last_scid = -1;
            fd_pool_cnt++;
          }
        }
        else
        { // read opened fd's
          res1 = open(fpath, O_RDONLY );

          if (res1 != -1)
          {
            fd_pool[fd_pool_cnt].fd = res1;
            fd_pool[fd_pool_cnt].mode = O_RDONLY;
            fd_pool[fd_pool_cnt].last_scid = -1;
            fd_pool_cnt++;
          }
        }
   }

   return 0;  // continue traversal
}

// fill fd_pool with open and closed fd's
int fd_pool_populate()
{
  fd_pool_cnt = 0;
  nftw(SANDBOX_DIR, callback_fd_pool_populate, 10, 0 );

  return 0;
}

// generate fuzz data in sandbox region `argno`. Type of fuzzing specified with `fuz_type`
int sandbox_syscall_fuzarg(int argno, int fuz_type, FILE* log_stream)
{
  last_fd_used = NULL;   // used to track changes in read-write mode of pool fd's
  int i,j, res;
  unsigned long int uli;
  unsigned int ui;
  long int li, li2;
  struct timespec *t;
  struct utimbuf *ut;

  if (fuz_type == FUZ_ARG_END)
    return 0;

    // actual fuzzing data generation happens below
    switch (fuz_type)
    {
      case FUZ_ARG_END:
          return 0;

      case FUZ_ARG_NULL:
          ((void**)sandbox[argno])[0] = NULL;
          fprintf(log_stream, "arg #%d = NULL\n", argno);
          return 0;

      case FUZ_ARG_BUF_GENERIC:
          ((char**)sandbox[argno])[0] = sandbox[argno];   // in first bytes we will store pointer to ourself
          fprintf(log_stream, "arg #%d = %p (fuz type #%d)\n", argno, sandbox[argno], fuz_type);
          return 0;

      case FUZ_ARG_PTR_RAND:
          ((void**)sandbox[argno])[0] = (void *)(intptr_t)rand();
          fprintf(log_stream, "arg #%d = %p, (fuz type #%d)\n", argno, ((void**)sandbox[argno])[0], fuz_type);
          return 0;

      case FUZ_ARG_BUF_RANDFILL:
          ((char**)sandbox[argno])[0] = sandbox[argno];
          for (i=0; i<SANDBOX_REGION_SIZE; i++ )
            sandbox[argno][i] = (char)(rand() % 256);
          fprintf(log_stream, "arg #%d = %0x, %0x, %0x, %0x... random binary buffer\n", argno, ((int*)sandbox[argno])[0], ((int*)sandbox[argno])[1], ((int*)sandbox[argno])[2], ((int*)sandbox[argno])[3] );
          return 0;

      case FUZ_ARG_ULONG_BUFSIZE:
          ((unsigned long*)sandbox[argno])[0] = rrand(MIN_ULONG_BUFSIZE, MAX_ULONG_BUFSIZE);
          fprintf(log_stream, "arg #%d = %ld (fuz type #%d)\n", argno, ((unsigned long*)sandbox[argno])[0], fuz_type);
          return 0;

      case FUZ_ARG_UINT_FD_ROPEN:
          ((int*)sandbox[argno])[0] = fd_pool[rrand(0, FD_POOL_NUM_ROPEN)].fd;
      case FUZ_ARG_UINT_FD_WOPEN:
          ((int*)sandbox[argno])[0] = fd_pool[rrand(FD_POOL_NUM_ROPEN, FD_POOL_NUM_WOPEN+FD_POOL_NUM_ROPEN)].fd;
      case FUZ_ARG_UINT_FD_CLOSED:
          ((int*)sandbox[argno])[0] = fd_pool[rrand(FD_POOL_NUM_WOPEN+FD_POOL_NUM_ROPEN, FD_POOL_NUM_WOPEN+FD_POOL_NUM_ROPEN+FD_POOL_NUM_CLOSED)].fd;
          fprintf(log_stream, "arg #%d = %d (fuzzing type #%d)\n", argno, *((int*)sandbox[argno]), fuz_type);
          return 0;

      case FUZ_ARG_PATH_FILE_EXIST:
      case FUZ_ARG_PATH_FILE_NONEXIST:
      case FUZ_ARG_PATH_DIR_EXIST:
        res = gen_path(fuz_type, sandbox[argno]);
        fprintf(log_stream, "arg #%d = `%s` (fuzzing type #%d)\n" ,argno, sandbox[argno], fuz_type);
        return res;

      case FUZ_ARG_OPEN_FLAGS:
        // one of these flags is required
        if (rand()%2)
          i = O_RDONLY;
        else if (rand()%2)
          i = O_WRONLY;
        else
          i = O_RDWR;
        // any other are optional
        i |= rand();
        ((int*)sandbox[argno])[0] = i;
        fprintf(log_stream, "arg #%d = %x (fuz type #%d)\n" ,argno, i, fuz_type);
        return 0;

      case FUZ_ARG_OPEN_MODE:
        ((int*)sandbox[argno])[0] = i = rand();
        fprintf(log_stream, "arg #%d = %x (fuz type #%d)\n" ,argno, i, fuz_type);
        return 0;

      case FUZ_ARG_FILE_PERM_MODE:
        ((int*)sandbox[argno])[0] = i = rand();
        fprintf(log_stream, "arg #%d = %o (octal permissions)\n" ,argno, i);
        return 0;

      case FUZ_ARG_DEV_TYPE:
        i = rand();
        j = rand();
        ((unsigned long int*)sandbox[argno])[0] = uli = makedev(i, j);
        fprintf(log_stream, "arg #%d = %lx = (maj %x, min %x)\n", argno, uli, i, j);
        return 0;

      case FUZ_ARG_UID:
      case FUZ_ARG_GID:
        ((unsigned int*)sandbox[argno])[0] = ui = ((rand() << 1) + rand());
        fprintf(log_stream, "arg #%d = %x (fuz type #%d)\n", argno, ui, fuz_type);
        return 0;

      case FUZ_ARG_LONGINT_OFFSET:
        ((long int*)sandbox[argno])[0] = li = (long int)(rand() << 16) + rand();
        fprintf(log_stream, "arg #%d = %lx (fuz type #%d)\n", argno, li, fuz_type);
        return 0;

      case FUZ_ARG_LSEEK_MODE:
        if (rand()%2)
          i = SEEK_SET;
        else if (rand()%2)
          i = SEEK_CUR;
        else if (rand()%2)
          i = SEEK_END;
        else
          i = rand();
        ((int*)sandbox[argno])[0] = i;
        fprintf(log_stream, "arg #%d = %d\n", argno, i);
        return 0;

      case FUZ_ARG_TIMESPEC:
        t = (struct timespec*)(intptr_t)sandbox[argno][0];
        t->tv_sec = rand()%3;
        t->tv_nsec = ((long)rand() << 16) + rand();
        fprintf(log_stream, "arg #%d = (%ld sec, %ld nanosec)\n", argno, t->tv_sec, t->tv_nsec);
        return 0;

      case FUZ_ARG_UTIMBUF:
        ut = (struct utimbuf*)(intptr_t)sandbox[argno][0];
        ut->actime = li = (long int)(rand() << 16) + rand();
        ut->modtime = li2 = (long int)(rand() << 16) + rand();
        fprintf(log_stream, "arg #%d = (access time: %ld, mod.time: %ld)\n", argno, li, li2);
        return 0;

      //case FUZ_ARG_EXECVE_ENVP:
      case FUZ_ARG_EXECVE_ARGV:
        {
          char *args[4];
          int i;

          args[0] = &sandbox[0][0];  //  execve required first arg must be same as filename
          args[1] = &sandbox[argno][10000];
          args[2] = &sandbox[argno][20000];
          args[3] = NULL;
          memcpy(&(sandbox[argno][0]), args, sizeof(char*)*4);

          //copy strings also
          helper_gen_fuz_str(&(sandbox[argno][10000]), 512);
          sandbox[argno][10000+512] = '\0';
          helper_gen_fuz_str(&(sandbox[argno][20000]), 512);
          sandbox[argno][20000+512] = '\0';

          fprintf(log_stream, "arg #%d = (fuzzing type #%d)\n", argno, fuz_type);
          for (i=0;i<4;i++)
          {
            if ( args[i] == NULL )
              break;

            fprintf(log_stream, "   arg #%d[%i] = `%s`\n", argno, i, args[i] );
          }

          return 0;
        }

      default:
        fprintf(log_stream, "<not implemented> (fuzzing type #%d)\n", fuz_type);
        return -1;
    }
}

// generate all fuzz arguments required by specified syscall
int sandbox_syscall_fuzargs(int scid, FILE* log_stream)
{
    int argidx;
    int fuz_arg_type_num;
    int fuz_arg_type[3];
    const scall_desc*  scdesc;

    scdesc = get_scall_desc(scid);

    // if this syscall is not supported by fuzzer
    if (!scdesc)
      return -1;

    // iterate on all arguments and randomly choose fuzz type for each from available within desc
    for (argidx=0; argidx<scdesc->argnum; argidx++)
    {
        // calculate number of fuzz types for argidx's arg
        fuz_arg_type_num = 0;
        while (scdesc->arg_type[argidx][fuz_arg_type_num] != FUZ_ARG_END)
          fuz_arg_type_num++;

        // randomly select on of available fuz types for this arg
        fuz_arg_type[argidx] = scdesc->arg_type[argidx][ rand() % fuz_arg_type_num ];

        sandbox_syscall_fuzarg(argidx, fuz_arg_type[argidx], log_stream);
    }

  return 0;
}

// generate fuz args in sandbox region and call scid syscall, placing log record to debug_msg
long int sandbox_syscall_run(int scid, FILE* log_stream)
{
    const scall_desc*  scdesc = get_scall_desc(scid);
    long int res = -1;
    //int i;

    // if this syscall is not supported by fuzzer
    if (!scdesc)
      return -1;

    fprintf(log_stream, "************************************************************************\n");
    fprintf(log_stream, "[%d] system call #%d = `%s`, %d argument(-s):\n\n" , getpid(), scid, scdesc->name, scdesc->argnum);

    sandbox_syscall_fuzargs(scid, log_stream);   // prepare fuzzed arg data in sandbox

    fprintf(log_stream, "\ncalling.... ");
    // ensure last buffered log data was stored to file before critical syscall

    // do all possible things to flush cached data to hard driveb before probable crash during syscall
    fflush(log_stream);
    fsync( fileno(log_stream) );

    //depending on number of syscall args pass pointers to prepopulated sandbox regions
    switch (scdesc->argnum)
    {
        case 1:
            res = syscall(scid, sandbox[0]); break;
        case 2:
            res = syscall(scid, sandbox[0], sandbox[1]); break;

        case 3:
            res = syscall(scid, sandbox[0], sandbox[1], sandbox[2]); break;

        default:
           fprintf(log_stream, "<no syscalls with more than 3 args>\n");
           break;
    }

    fprintf(log_stream, "syscall result: %ld\n", res);

    // update fd pool if need
    if (res >= 0 && last_fd_used)
    {
        // looks like syscall was successful... let's update fd pool
        switch (scid)
        {
          case SYS_open:
              last_fd_used->last_scid = scid;
              last_fd_used->mode =  (mode_t)sandbox[2][0];
          break;
          case SYS_creat:
              last_fd_used->last_scid = scid;
              last_fd_used->mode = (mode_t)sandbox[1][0];
          break;

          case SYS_close:
              last_fd_used->last_scid = scid;
              last_fd_used->mode = FD_STATE_CLOSED;
          break;

          default:
          break;
        }

        last_fd_used = NULL;
    }

    return res;
}
