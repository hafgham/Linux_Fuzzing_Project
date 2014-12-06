#ifndef SYSCALL_DEF_H_INCLUDED
#define SYSCALL_DEF_H_INCLUDED

#include <sys/syscall.h>
#include <sys/times.h>
#include <sys/types.h>
#include <unistd.h>

#define SYSCALL_NUM 15

// define possible syscall argument natures
#define  FUZ_ARG_END                 -1    // used as list terminator
#define  FUZ_ARG_NULL                 0    // no arg or not implemented

#define  FUZ_ARG_PTR_RAND             2      // totally random ptr

#define  FUZ_ARG_UINT_FD_ROPEN        3    // already open file descriptor for reading
#define  FUZ_ARG_UINT_FD_WOPEN        4    // already open file descriptor for writing
#define  FUZ_ARG_UINT_FD_CLOSED       5    // already open file descriptor for writing

#define  FUZ_ARG_BUF_GENERIC          6
#define  FUZ_ARG_BUF_RANDFILL         7

#define  FUZ_ARG_ULONG_BUFSIZE        8    // size_t

#define  FUZ_ARG_LONGINT_OFFSET       9     // off_t, file position offset, signed

#define  FUZ_ARG_PATH_FILE_EXIST      10
#define  FUZ_ARG_PATH_FILE_NONEXIST   11
#define  FUZ_ARG_PATH_DIR_EXIST       12

#define  FUZ_ARG_OPEN_FLAGS           14      // int
#define  FUZ_ARG_OPEN_MODE            15      // int

#define  FUZ_ARG_DEV_TYPE             16      // dev_t
#define  FUZ_ARG_FILE_PERM_MODE       17      // mode_t, file attribute bitmasks

#define  FUZ_ARG_UID                  18      // uid_t
#define  FUZ_ARG_GID                  19      // gid_t

#define  FUZ_ARG_TIMESPEC             20      // timespec
#define  FUZ_ARG_UTIMBUF              21      // utimbuf
#define  FUZ_ARG_LSEEK_MODE           22      // uint
#define  FUZ_ARG_EXECVE_ARGV          23      // execve arg
#define  FUZ_ARG_EXECVE_ENVP          24      // execve arg


#define  MIN_ULONG_BUFSIZE   0
#define  MAX_ULONG_BUFSIZE   40960

// structure defines each syscall specifics to unify calls in batches
typedef struct
{
    int   scid;             // system int number of syscall
    char  name[20];         // name (read, open)
    int   argnum;           // number of arguments
    int   arg_type[4][20];  // for each arg specifies list of possible types of parameters available

} scall_desc;

// main syscall fuzzing description array
static const scall_desc fuzzer_call_spec_list[] =
{
  {
    SYS_read, "SYS_read", 3,
    {
      { FUZ_ARG_UINT_FD_ROPEN, FUZ_ARG_UINT_FD_WOPEN, FUZ_ARG_UINT_FD_CLOSED, FUZ_ARG_END },
      { FUZ_ARG_BUF_GENERIC, FUZ_ARG_NULL, FUZ_ARG_END },
      { FUZ_ARG_ULONG_BUFSIZE, FUZ_ARG_END }
    }
  },
  {
    SYS_write, "SYS_write", 3,
    {
      { FUZ_ARG_UINT_FD_ROPEN, FUZ_ARG_UINT_FD_WOPEN, FUZ_ARG_UINT_FD_CLOSED, FUZ_ARG_END },
      { FUZ_ARG_BUF_GENERIC, FUZ_ARG_NULL, FUZ_ARG_BUF_RANDFILL, FUZ_ARG_END },
      { FUZ_ARG_ULONG_BUFSIZE, FUZ_ARG_END }
    }
  },
  {
   SYS_open, "SYS_open", 3,
    {
      { FUZ_ARG_PATH_FILE_EXIST, FUZ_ARG_PATH_FILE_NONEXIST, FUZ_ARG_PATH_DIR_EXIST, FUZ_ARG_END },
      { FUZ_ARG_OPEN_FLAGS, FUZ_ARG_END },
      { FUZ_ARG_OPEN_MODE, FUZ_ARG_END }
    }
  },
  {
    SYS_close, "SYS_close", 1,
    {
      { FUZ_ARG_UINT_FD_ROPEN, FUZ_ARG_UINT_FD_WOPEN, FUZ_ARG_UINT_FD_CLOSED, FUZ_ARG_END },
      { FUZ_ARG_END },
      { FUZ_ARG_END }
    }
  },
  {
    SYS_creat, "SYS_creat", 2,
    {
      { FUZ_ARG_PATH_FILE_EXIST, FUZ_ARG_PATH_FILE_NONEXIST, FUZ_ARG_PATH_DIR_EXIST, FUZ_ARG_END },
      { FUZ_ARG_OPEN_MODE, FUZ_ARG_END },
      { FUZ_ARG_END }
    }
  },
  {
    SYS_link, "SYS_link", 2,
    {
      { FUZ_ARG_PATH_FILE_EXIST, FUZ_ARG_PATH_FILE_NONEXIST, FUZ_ARG_PATH_DIR_EXIST, FUZ_ARG_END },
      { FUZ_ARG_PATH_FILE_EXIST, FUZ_ARG_PATH_FILE_NONEXIST, FUZ_ARG_PATH_DIR_EXIST, FUZ_ARG_END },
      { FUZ_ARG_END }
    }
  },
  {
    SYS_execve, "SYS_execve", 3,
    {
      { FUZ_ARG_PATH_FILE_EXIST, FUZ_ARG_PATH_FILE_NONEXIST, FUZ_ARG_PATH_DIR_EXIST, FUZ_ARG_NULL, FUZ_ARG_END },
      { FUZ_ARG_EXECVE_ARGV, FUZ_ARG_NULL, FUZ_ARG_END },
      { FUZ_ARG_NULL, FUZ_ARG_END }
    }
  },
  {
    SYS_chdir, "SYS_chdir", 1,
    {
      { FUZ_ARG_PATH_FILE_EXIST, FUZ_ARG_PATH_FILE_NONEXIST, FUZ_ARG_PATH_DIR_EXIST, FUZ_ARG_END },
      { FUZ_ARG_END },
      { FUZ_ARG_END }
    }
  },
  {
    SYS_time, "SYS_time", 1,
    {
      { FUZ_ARG_BUF_GENERIC, FUZ_ARG_NULL, FUZ_ARG_END },
      { FUZ_ARG_END },
      { FUZ_ARG_END }
    }
  },
  {
    SYS_mknod, "SYS_mknod", 3,
    {
      { FUZ_ARG_PATH_FILE_EXIST, FUZ_ARG_PATH_FILE_NONEXIST, FUZ_ARG_PATH_DIR_EXIST, FUZ_ARG_END },
      { FUZ_ARG_FILE_PERM_MODE, FUZ_ARG_END },
      { FUZ_ARG_DEV_TYPE, FUZ_ARG_END }
    }
  },
  {
    SYS_chmod, "SYS_chmod", 2,
    {
      { FUZ_ARG_PATH_FILE_EXIST, FUZ_ARG_PATH_FILE_NONEXIST, FUZ_ARG_PATH_DIR_EXIST, FUZ_ARG_END },
      { FUZ_ARG_FILE_PERM_MODE, FUZ_ARG_END },
      { FUZ_ARG_END }
    }
  },
  {
    SYS_lchown, "SYS_lchown", 3,
    {
      { FUZ_ARG_PATH_FILE_EXIST, FUZ_ARG_PATH_FILE_NONEXIST, FUZ_ARG_PATH_DIR_EXIST, FUZ_ARG_END },
      { FUZ_ARG_UID, FUZ_ARG_GID, FUZ_ARG_END },
      { FUZ_ARG_UID, FUZ_ARG_GID, FUZ_ARG_END }
    }

  },
  {
    SYS_lseek, "SYS_lseek", 3,
    {
      { FUZ_ARG_UINT_FD_ROPEN, FUZ_ARG_UINT_FD_WOPEN, FUZ_ARG_UINT_FD_CLOSED, FUZ_ARG_END },
      { FUZ_ARG_LONGINT_OFFSET, FUZ_ARG_END },
      { FUZ_ARG_LSEEK_MODE, FUZ_ARG_END }
    }
  },
  {
    SYS_nanosleep, "SYS_nanosleep", 2,
    {
      { FUZ_ARG_TIMESPEC, FUZ_ARG_END },
      { FUZ_ARG_TIMESPEC, FUZ_ARG_NULL, FUZ_ARG_END },
      { FUZ_ARG_END }
    }
  },
  {
    SYS_utime, "SYS_utime", 2,
    {
      { FUZ_ARG_PATH_FILE_EXIST, FUZ_ARG_PATH_FILE_NONEXIST, FUZ_ARG_PATH_DIR_EXIST, FUZ_ARG_END },
      { FUZ_ARG_UTIMBUF, FUZ_ARG_END },
      { FUZ_ARG_END }
    }
  },
  // terminator
  {
   -1, "", 0,
    {
      { FUZ_ARG_END },
      { FUZ_ARG_END },
      { FUZ_ARG_END }
    }
  }
};

const scall_desc*  get_scall_desc(int scid);
void* sc_prepare_fuzzed_arg(int argno, int argtype);
void  sanitize_args_for_call(int scid);

#endif // SYSCALL_DEF_H_INCLUDED
