#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <assert.h>
#include <dirent.h>
#include <signal.h>


//include all supported by fuzzer syscall definition structures
#include "syscall_def.h"


#define  SELF_VERSION           "0.1 alpha"

#define MAX_LEN_STR		        4000
#define MAX_LEN_PATH		    1024
#define MAX_LEN_FNAME           128
#define PROB_STR_NONASCII	    5  // percents

//multiprocess defines
#define WORKER_NUM          4

#define PROC_TYPE_DEF       -1   // default,  used as argument to autodetect, etc
#define PROC_TYPE_MAIN      0
#define PROC_TYPE_WD        1
#define PROC_TYPE_WORKER    2
#define PROC_TYPE_SHELL     3   // process is command line shell to display status, etc



// global shared multiprocess data
typedef struct {
  FILE *flog;
  int pid;
  int ptype;     // one of the def, main, wd, worker

} proc_desc;

static proc_desc ppd[WORKER_NUM+2];
static proc_desc_cnt = 0;

//return our worker process description structure by pid
proc_desc* get_proc_desc(int pid)
{
  int i;
  for (i=0;i<proc_desc_cnt;i++)
  {
      if (ppd[i].pid == pid)
        return &ppd[i];
  }

  return NULL;
}

// register new process - main, worker or watchdog
proc_desc* register_new_process(int pid, int ptype)
{
  char str[64], str2[64];
  FILE *fpid;
  proc_desc *pd = NULL;
  char prefix = 0;

  if (get_proc_desc(pid)) // check if proc_desc record already exists for this pid
     return -1;

  //check if pid file exists

  //allocate next available record
  pd = &(ppd[proc_desc_cnt]);
  proc_desc_cnt++;

  pd->pid = pid;
  pd->ptype = ptype;

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

// restore ppd array from pid files


// write log
static int log(int pid, const char *src, int ptype)
{
  proc_desc *pd = get_proc_desc(pid);

  if (!pd && ptype == PROC_TYPE_DEF) return -1;  //can't write log

  if (!pd)
    pd = register_new_process(pid, ptype);

  fprintf(pd->flog, "[%d] %s\n", pid, src);

  // flush last log entries to disk to protect from possible process crash
  fflush(pd->flog);
  fsync(pd->flog);

  return 0;
}

// another log call with custom params
//static int log(int pid, int ptype = PROC_TYPE_DEF)
//{

//}

// close log
static int close_log(int pid)
{
   proc_desc *pd = get_proc_desc(pid);

   if (!pd) return -1;

   log(pid, "Normal process shutdown due to `close_log()` call...", PROC_TYPE_DEF);
   log(pid, "\n\n", PROC_TYPE_DEF);

   fclose(pd->flog);

   return 0;
}


char strbuf [64*1024];
char outbuf [64*1024];

int rrand(int min, int max)
{
  assert(min <= max);
  return min + rand() % (max - min + 1);
}

//int helper_gen_fuz_str(char* ptr, int cnt);

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


//****************************************************
void helper_gen_fuz_str(char* ptr, int cnt)
{
int i;

for (i=0; i<cnt; i++)
  {
    *(ptr+i) =  (rand()%100 < PROB_STR_NONASCII)? rand() % 256 : rrand(97, 122);
  }



}


//***************************************************
const char*   gen_fuz_path_dir()
{


  int len =  rand() % MAX_LEN_PATH;
  int chunk_len;
  int cnt = 1;

  strbuf[0] = '/';

  while (cnt < len)
  {
    chunk_len = rand() % MAX_LEN_FNAME;
    helper_gen_fuz_str(strbuf+cnt, chunk_len);
    cnt += (chunk_len-1);
    strbuf[cnt] = '/'; cnt++;

  }

  strbuf[cnt] = 0;



}

void signal_handler(sig)
{

	switch(sig) {
	case SIGHUP:
	    log(getpid(), "hangup signal catched", PROC_TYPE_DEF );
        close_log(getpid());
        unregister_process(getpid(), PROC_TYPE_DEF);
		break;
	case SIGTERM:
	    log(getpid(), "terminate signal catched", PROC_TYPE_DEF );
        close_log(getpid());
        unregister_process(getpid(), PROC_TYPE_DEF);
		exit(0);
		break;
	}
}

int main()
{
  //FILE *fp;
  char log_strbuf[2048];

  char* sp, str[128], dir_pid[8];
  long ret;
  int  i, sysPID = syscall(SYS_getpid);
   pid_t fork_res;

  //if main pid file exist we should start in shell-only mode (display statuses, etc
  DIR *dir;
  struct dirent *ent;


  if ((dir = opendir ("pid/")) != NULL)
  {
    while ((ent = readdir (dir)) != NULL)
    {
      //printf ("%s\n", ent->d_name);
      if (sscanf(ent->d_name, "main_%4s.pid", dir_pid) == 1)
      {
        printf("Fuzzer main process (pid=%s) already running. Please see log updates...\n\n", dir_pid);
        closedir (dir);
        return 1;
      }
    }
  }

  // subprocess creation starts here
  for (i=0;i<WORKER_NUM;i++)
  {
      fork_res=fork();

      if (fork_res > 0)
        setpgid(fork_res, 0);  // set parent to be a process group leader

      if (fork_res == -1)
      {
        printf("Can't create child process. Exiting...\n");
        exit(1);
      }

      //init tasks similar for parent & child
      register_new_process(getpid(), fork_res? PROC_TYPE_MAIN : PROC_TYPE_WORKER);

      if (!fork_res || i==0)  // print start log msg for main process only once
        log(getpid(), "Logging started",PROC_TYPE_DEF );

      if (fork_res == 0)
      { // child process goes here
          setpgid(0, 0);

          /*signal(SIGCHLD,SIG_IGN);*/ /* ignore child */
          signal(SIGTSTP,SIG_IGN); /* ignore tty signals */
          signal(SIGTTOU,SIG_IGN);
          signal(SIGTTIN,SIG_IGN);
          signal(SIGHUP,signal_handler); /* catch hangup signal */
          signal(SIGTERM,signal_handler); /* catch kill signal */

          sprintf( log_strbuf, "Worker process #%d log.", i );
          log(getpid(), log_strbuf, PROC_TYPE_DEF );

          //for (i=0; i<20; i++)
          while(1)
          {
            sp = gen_fuz_path_dir();
            helper_log_fix_str(strbuf, outbuf);

            log(getpid(), "***********************************************", PROC_TYPE_DEF );
            sprintf( log_strbuf, "call -> sys_chdir(#1), \n\n#1 = `%s`\n\n", outbuf);
            log(getpid(), log_strbuf, PROC_TYPE_DEF );

            // SYSTEM CALL is here
            ret = syscall(SYS_chdir, strbuf);

            sprintf( log_strbuf, "ret: %ld\n\n", ret );
            log(getpid(), log_strbuf, PROC_TYPE_DEF );

            sleep(1);
            // wait for worker exit
          }

        unregister_process(getpid(), PROC_TYPE_DEF);
        close_log(getpid());
        return 1;
      }

   //log(getpid(), "Main process log.",PROC_TYPE_DEF );
   sprintf( log_strbuf, "Just created child worker process #%d with pid=%d.", i, fork_res);
   log(getpid(), log_strbuf, PROC_TYPE_DEF );

   // register this child in our main table
   register_new_process(fork_res, PROC_TYPE_WORKER);

   sleep(1);
  }

  //close_log(getpid());
  //unregister_process(getpid(), PROC_TYPE_MAIN);

  // fork watchdog here
  fork_res=fork();

  if (fork_res == 0)
  {
      // we are wd-process
      setpgid(0, 0);
      register_new_process(getpid(), PROC_TYPE_WD);
      log(getpid(), "Logging started", PROC_TYPE_WD );
      /*signal(SIGCHLD,SIG_IGN); */ /* ignore child */
      signal(SIGTSTP,SIG_IGN); /* ignore tty signals */
      signal(SIGTTOU,SIG_IGN);
      signal(SIGTTIN,SIG_IGN);
      signal(SIGHUP,signal_handler); /* catch hangup signal */
      signal(SIGTERM,signal_handler); /* catch kill signal */

      log(getpid(), "WatchDog process log start.", PROC_TYPE_DEF );

      while(1)
      {
          int i=0;
          // display main process table
          for (i=0;i<proc_desc_cnt;i++)
          {
              if (ppd[i].pid != 0)
              {
                //printf("   pid=%d\n", ppd[i].pid);
                log(getpid(), "Watching for workers... ", PROC_TYPE_DEF );
              }
          }

          sleep(10);
      }
  }

  // main process runs here
  sprintf( log_strbuf, "Just created WatchDog process with pid=%d.", fork_res);
  log(getpid(), log_strbuf, PROC_TYPE_DEF );

  i = 0;
  while(1)
  {
      printf("Nothing to do for main process... %d\n", i);
      sleep(1);
      i++;
  }


  return 0;
}

