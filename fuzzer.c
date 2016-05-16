#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <dirent.h>
#include <signal.h>
#include <string.h>
#include <time.h>

#include <sys/wait.h>
#include <sys/resource.h>

#include "fuzzer.h"
#include "sandbox.h"

// global shared multiprocess data
typedef struct {
  int  id;       // id of worker
  FILE *flog;
  int pid;
  int ptype;     // one of the def, main, wd, worker
  int died;

} proc_desc;

static proc_desc  ppd[PPD_SIZE];
static int proc_desc_cnt = 0;

char log_strbuf[2048*10];
char strbuf [64*1024];
char outbuf [64*1024];

// for debug only
// dumps  ppd array to stdout - process statuses
void dump_ppd()
{
#ifdef DEBUG_FORK
  int i;
  printf("\n   PPD dump (we are pid=%d):\n", getpid());

  for (i=0;i<PPD_SIZE;i++)
  {
      printf("       idx=%d, ptype=%d, id=%d, pid=%d, died=%d [proc_desc_cnt=%d]\n", i, ppd[i].ptype, ppd[i].id, ppd[i].pid, ppd[i].died, proc_desc_cnt);
  }
#endif
}

// to use as advance seed for rand() to make random generator much better
// returns the number of cycles used by the processor since the start.
// It can be obtained on x86 processors (Intel, AMD), with the assembly command rdtsc
unsigned int rdtsc()
{
#ifdef __i386
  unsigned long long x;
  __asm__ volatile ("rdtsc" : "=A" (x));
  return (unsigned int)x;

#elif __amd64
  unsigned long long a, d;
  __asm__ volatile ("rdtsc" : "=a" (a), "=d" (d));
  return (unsigned int)((d<<32) | a);

#endif
}

//return our worker process description structure by pid
proc_desc* get_proc_desc(int pid)
{
  int i;
  for (i=0;i<PPD_SIZE;i++)
  {
      if (ppd[i].pid == pid)
        return &ppd[i];
  }

  return NULL;
}

// register new process - main, worker or watchdog
proc_desc* register_new_process(int pid, int ptype, int id, int replace_died_pid)
{
  char str[64], str2[64];
  FILE *fpid;
  proc_desc *pd = NULL;

  if (replace_died_pid)
  {
      pd = get_proc_desc(replace_died_pid);
  }
  else
  {
      if (get_proc_desc(pid)) // check if proc_desc record already exists for this pid
        return NULL;

      //allocate next available record
      pd = &(ppd[proc_desc_cnt]);
      proc_desc_cnt++;
  }

  pd->pid = pid;
  pd->ptype = ptype;
  pd->id = id;
  pd->died = 0;

  switch (ptype)
  {
    case PROC_TYPE_MAIN:  strcpy(str2, "main_"); break;
    case PROC_TYPE_WD:    strcpy(str2, "wd_"); break;
    case PROC_TYPE_WORKER: strcpy(str2,"worker_"); break;
    default: strcpy(str2, ""); break;
  }

  //create pid file
  sprintf(str, "pid/%s%d.pid", str2, pid);
  fpid = fopen(str, "w");
  fclose(fpid);

  //create log file
  sprintf(str, "log/%s%d.log", str2, pid);
  pd->flog = fopen(str, "w");

  return pd;
}

//remove pid file, etc
int unregister_process(int pid, int ptype)
{
   char str[64], str2[64];
   proc_desc *pd = get_proc_desc(pid);

   if (!pd) return -1;

   pd->pid = 0;

   switch (ptype)
  {
    case PROC_TYPE_MAIN:  strcpy(str2, "main_"); break;
    case PROC_TYPE_WD:    strcpy(str2, "wd_"); break;
    case PROC_TYPE_WORKER: strcpy(str2,"worker_"); break;
    default: strcpy(str2, ""); break;
  }
   sprintf(str, "pid/%s%d.pid", str2, pid);
   return remove(str);
}

// write log
int log_(int pid, const char *src, int ptype)
{
  proc_desc *pd = get_proc_desc(pid);

  if (!pd && ptype == PROC_TYPE_DEF) return -1;  //can't write log

  if (!pd)
    return -1;

  fprintf(pd->flog, "[%d] %s\n", pid, src);

  // flush last log entries to disk to protect from possible process crash
  fflush(pd->flog);
  fsync( fileno(pd->flog) );

  return 0;
}

// close log
static int close_log(int pid)
{
   proc_desc *pd = get_proc_desc(pid);

   if (!pd) return -1;

   log_(pid, "Normal process shutdown due to `close_log()` call...", PROC_TYPE_DEF);
   log_(pid, "\n\n", PROC_TYPE_DEF);

   fclose(pd->flog);

   return 0;
}

// get log stream descriptor
static FILE* get_log_stream(int pid)
{
   proc_desc *pd = get_proc_desc(pid);
   return (pd)? pd->flog : NULL;
}

//****************************************************
void  helper_log_fix_str(char* src, char* dst)
{
  int i = 0;

  while( src[i] && i < MAX_LEN_STR)
  {
    dst[i]  = isgraph(src[i])? src[i] : '_';
    i++;
  }
  dst[i] = 0;
}

// child termination support
void SIGCHLD_handler(sig)
{
  while (1) {
    int status;
    proc_desc* pd;

    pid_t pid = waitpid(-1, &status, WNOHANG);

    if (pid <= 0) {
        break;
    }

    dump_ppd();

    pd = get_proc_desc(pid);

    if (!pd)
      return;

    // flag to recreate worker ASAP
    pd->died = 1;

    printf("Worker #%d crashed. Pid=%d\n", pd->id, pid);

    sprintf( log_strbuf, "Worker #%d crashed. Pid=%d", pd->id, pid);
    log_(getpid(), log_strbuf, PROC_TYPE_DEF );

    dump_ppd();
  }
}


void signal_handler(sig)
{
	switch(sig) {

	case SIGHUP:
	    log_(getpid(), "hangup signal catched", PROC_TYPE_DEF );
        close_log(getpid());
        unregister_process(getpid(), PROC_TYPE_DEF);
		break;
	case SIGTERM:
	    log_(getpid(), "terminate signal catched", PROC_TYPE_DEF );
        close_log(getpid());
        unregister_process(getpid(), PROC_TYPE_DEF);
		exit(0);
		break;
	}
}

// fuzz single syscall specified number of times
long sc_batch_single(int scid, int times)
{
   int i;
   long ret;

   if (scid < 0)
     return -1;

   for (i=0; i<times; i++)
   {
     ret = sandbox_syscall_run( scid, get_log_stream(getpid()) );
     sleep(1);
   }
   return ret;
}

// call all defined syscalls one by one - one cycle, regardless of the result of calls
// 'times' is same syscall sequence size
void sc_batch_roundrobbin(int times)
{
   int i;

   for (i=0; i<SYSCALL_NUM; i++)
   {
     if (fuzzer_call_spec_list[i].scid != -1)
       sc_batch_single(fuzzer_call_spec_list[i].scid, times);
   }
}

// call all defined syscalls randomly
// 'times' is same syscall sequence size
void sc_batch_random(int times)
{
  int i = 0;
  int scid;
  do
  {
    i = rand() % SYSCALL_NUM;
  } while( fuzzer_call_spec_list[i].scid == -1 );

  scid = fuzzer_call_spec_list[i].scid;
  sc_batch_single(scid, times);
}

// worker function - never exited
void worker(int id)
{
          // child process run here
          setpgid(0, 0);

          // randomize each child process random ganarator
          srand(rdtsc());

          signal(SIGTSTP,SIG_IGN); /* ignore tty signals */
          signal(SIGTTOU,SIG_IGN);
          signal(SIGTTIN,SIG_IGN);
          signal(SIGHUP, signal_handler); /* catch hangup signal */
          signal(SIGTERM, signal_handler); /* catch kill signal */

          fprintf(get_log_stream(getpid()), "Worker process #%d log. pid=%d\n", id, getpid());
          sleep(1);

          // we need to preallocate some resources - fd's...
          fd_pool_populate();

          while(1)
          {
            switch (id)
            {
              case 0:
                sc_batch_roundrobbin(10);
                break;

              case 1:
                sc_batch_roundrobbin(1);
                break;

              case 2:
                sc_batch_random(10);
                break;

              case 3:
                sc_batch_random(1);
                break;

              default:
                sc_batch_roundrobbin(1);
              break;
            }
            sleep(1);
          }

        unregister_process(getpid(), PROC_TYPE_DEF);
        close_log(getpid());
        return;
}

// execution starts here
int main()
{
  char  dir_pid[8];
  int   id;
  pid_t fork_res;

  DIR *dir;
  struct dirent *ent;
  int tick = 0;

  if ((dir = opendir ("pid/")) != NULL)
  {
    while ((ent = readdir (dir)) != NULL)
    {
      if (sscanf(ent->d_name, "main_%4s.pid", dir_pid) == 1)
      {
        printf("Fuzzer main process (pid=%s) already running. Please see log updates...\n\n", dir_pid);
        closedir (dir);
        return 1;
      }
    }
  }

  // subprocess creation starts here
  for (id=0;id<WORKER_NUM;id++)
  {
      fork_res=fork();

      if (fork_res > 0 && id==0)
      {
        sprintf(log_strbuf, "Fuzzer v.%s Logging started.\n", SELF_VERSION);
        puts(log_strbuf);
        log_(getpid(), log_strbuf, PROC_TYPE_MAIN );
      }

      if (fork_res > 0)
        setpgid(fork_res, 0);  // set parent to be a process group leader

      if (fork_res == -1)
      {
        printf("Can't create child process. Exiting...\n");
        exit(1);
      }

      // process children termination
      signal(SIGCHLD, SIGCHLD_handler);

      //init tasks which are common for parent & child
      register_new_process(getpid(), fork_res? PROC_TYPE_MAIN : PROC_TYPE_WORKER, id, 0);

      if (fork_res == 0)
        worker(id);  // never returns !!!

      //main process continues here after next worker creation
      sprintf( log_strbuf, "Just created child worker process #%d with pid=%d.", id, fork_res);

      log_(getpid(), log_strbuf, PROC_TYPE_DEF );

      // register this child in our main table
       register_new_process(fork_res, PROC_TYPE_WORKER, id, 0);
  }

  //main process continues run HERE after ALL worker processes creation

  // fork watchdog here
  fork_res=fork();

  if (fork_res == 0)
  {
      // we are wd-process
      setpgid(0, 0);
      register_new_process(getpid(), PROC_TYPE_WD, id, 0);
      log_(getpid(), "Logging started", PROC_TYPE_WD );
      signal(SIGCHLD,SIG_IGN);  /* ignore child */
      signal(SIGTSTP,SIG_IGN); /* ignore tty signals */
      signal(SIGTTOU,SIG_IGN);
      signal(SIGTTIN,SIG_IGN);
      signal(SIGHUP,signal_handler); /* catch hangup signal */
      signal(SIGTERM,signal_handler); /* catch kill signal */

      log_(getpid(), "WatchDog process log start.", PROC_TYPE_DEF );

      // WD loop never returns
      while(1)
      {
          int i=0;
          // display main process table
          for (i=0;i<proc_desc_cnt;i++)
          {
              if (ppd[i].pid != 0)
              {
                log_(getpid(), "Watching for workers... ", PROC_TYPE_DEF );
              }
          }
          sleep(30);
      }
  }

  // main process runs HERE after WD creation
  sprintf( log_strbuf, "Just created WatchDog process with pid=%d.", fork_res);
  log_(getpid(), log_strbuf, PROC_TYPE_DEF );

  id = 0;

  while(1)
  {
      int i;

      //let's try to recreate died workers if any
      for (i=0; i<proc_desc_cnt; i++)
      {
        if (ppd[i].ptype != PROC_TYPE_WORKER || !ppd[i].pid || !ppd[i].died)
          continue;

        sprintf(log_strbuf, "Reforking worker #%d with new pid=%d\n", ppd[i].id, fork_res);
        puts(log_strbuf);
        log_(getpid(), log_strbuf, PROC_TYPE_MAIN );

        fork_res=fork();

        // main process continue to check for died
         if (fork_res > 0)
         {
            // update ppd for reforked child worker
            register_new_process(fork_res, PROC_TYPE_WORKER, ppd[i].id, ppd[i].pid);
            dump_ppd();
            continue;
         }

        // we are a new child
        register_new_process(getpid(), PROC_TYPE_WORKER, ppd[i].id, ppd[i].pid);  // last arg mean old pid to replace instead of allocating new worker

        worker(ppd[i].id);  // never returns !!!
      }

      printf("Nothing to do for main process... %d\n", tick);
      dump_ppd();
      sleep(5);
      tick++;
  }

  return 0;
}
