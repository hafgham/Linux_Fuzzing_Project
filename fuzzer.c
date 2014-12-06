#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <dirent.h>
#include <signal.h>
#include <string.h>
#include <time.h>

#include <sys/wait.h>
#include <sys/resource.h>
//include all supported by fuzzer syscall definition structures

#include "fuzzer.h"
#include "sandbox.h"
//#include "syscall_def.h"


// global shared multiprocess data
typedef struct {
  int  id;       // id of worker
  FILE *flog;
  int pid;
  int ptype;     // one of the def, main, wd, worker
  int died;

} proc_desc;

static volatile proc_desc  ppd[WORKER_NUM+5];
static volatile int proc_desc_cnt = 0;

char log_strbuf[2048*10];

// to use as advance seed for rand() to make random generator much better
// returns the number of cycles used by the processor since the start.
// It can be obtained on x86 processors (Intel, AMD), with the assembly command rdtsc
int rdtsc()
{
  __asm__ __volatile__("rdtsc");
}


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
proc_desc* register_new_process(int pid, int ptype, int id, int replace_died_pid)
{
  char str[64], str2[64];
  FILE *fpid;
  proc_desc *pd = NULL;
  //char prefix = 0;

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

// restore ppd array from pid files


// write log
int log_(int pid, const char *src, int ptype)
{
  proc_desc *pd = get_proc_desc(pid);

  if (!pd && ptype == PROC_TYPE_DEF) return -1;  //can't write log

  if (!pd)
    return -1;
    //pd = register_new_process(pid, ptype);

  fprintf(pd->flog, "[%d] %s\n", pid, src);

  // flush last log entries to disk to protect from possible process crash
  fflush(pd->flog);
  fsync( fileno(pd->flog) );
  //sync();

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


char strbuf [64*1024];
char outbuf [64*1024];

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

// child termination support
void SIGCHLD_handler(sig)
{
  pid_t pid;
  //get_proc_desc;
  proc_desc* pd;
  //proc_desc* self;


  pid = wait(NULL);

  if (!pid)
    return;

  pd = get_proc_desc(pid);

  if (!pd)
    return;

  // flag to recreate worker ASAP
  pd->died = 1;

  printf("Worker #%d crashed. Pid=%d\n", pd->id, pid);

  //self = get_proc_desc( getpid() );
  //fprintf(self->flog, "Worker #%d crashed. Pid=%d\n");
  sprintf( log_strbuf, "Worker #%d crashed. Pid=%d", pd->id, pid);
  log_(getpid(), log_strbuf, PROC_TYPE_DEF );
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
   //char* sp;
   long ret;

   if (scid < 0)
     return -1;

   //fprintf(get_log_stream(getpid()), "... scid %d\n", scid);

   for (i=0; i<times; i++)
   {
     //let's fuzz call #scid once
     //gen_fuz_path_dir( strbuf );

     /*gen_path( FUZ_ARG_PATH_FILE_NONEXIST, strbuf );
     helper_log_fix_str(strbuf, outbuf);


     log(getpid(), "***********************************************", PROC_TYPE_DEF );
     sprintf( log_strbuf, "call -> sys_chdir(#1), \n\n#1 = `%s`\n\n", outbuf);
     log(getpid(), log_strbuf, PROC_TYPE_DEF );

     // SYSTEM CALL is here
     ret = syscall(SYS_chdir, strbuf);
     sprintf( log_strbuf, "ret: %ld\n\n", ret );
     log(getpid(), log_strbuf, PROC_TYPE_DEF );*/


     //log_(getpid(), "***********************************************\n", PROC_TYPE_DEF );
     ret = sandbox_syscall_run( scid, get_log_stream(getpid()) );


     sleep(1);  //replace with nanosleep syscall
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
          //srand((unsigned) time(&t));
          srand(rdtsc());


          signal(SIGTSTP,SIG_IGN); /* ignore tty signals */
          signal(SIGTTOU,SIG_IGN);
          signal(SIGTTIN,SIG_IGN);
          signal(SIGHUP, signal_handler); /* catch hangup signal */
          signal(SIGTERM, signal_handler); /* catch kill signal */

          //sprintf( log_strbuf, "Worker process #%d log.", i );
          //log_(getpid(), log_strbuf, PROC_TYPE_WORKER );
          fprintf(get_log_stream(getpid()), "Worker process #%d log. pid=%d\n", id, getpid());

          sleep(1);

          // we need to preallocate some resources - fd's...
          fd_pool_populate();

          while(1)
          {
            /*sc_batch_single(SYS_read, 1);
            sc_batch_single(SYS_write, 1);
            sc_batch_single(SYS_chdir, 1);
            sc_batch_single(SYS_open, 1);
            sc_batch_single(SYS_close, 1);
            sc_batch_single(SYS_creat, 1);
            sc_batch_single(SYS_link, 1);
            sc_batch_single(SYS_time, 1);
            sc_batch_single(SYS_mknod, 1);
            sc_batch_single(SYS_chmod, 1);
            sc_batch_single(SYS_lchown, 1);
            sc_batch_single(SYS_lseek, 1);
            sc_batch_single(SYS_nanosleep, 1);
*/
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
        return 1;

}




int main()
{
  //FILE *fp;
  char log_strbuf[2048];

  //char str[128];
  char dir_pid[8];
  //long ret;
  int  id; //, sysPID = syscall(SYS_getpid);
  pid_t fork_res;

  //if main pid file exist we should start in shell-only mode (display statuses, etc
  DIR *dir;
  struct dirent *ent;
  int tick = 0;
  //time_t t;



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
  for (id=0;id<WORKER_NUM;id++)
  {
      fork_res=fork();

      if (fork_res > 0 && id==0)
      {
        sprintf(log_strbuf, "Fuzzer v.%s Logging started.\n", SELF_VERSION);
        printf(log_strbuf);
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

      //if (!fork_res || i==0)  // print start log msg for main process only once
      //  log_(getpid(), "Logging started",PROC_TYPE_DEF );


      if (fork_res == 0)
        worker(id);  // never returns !!!


   //main process continues here after next worker creation

   //log(getpid(), "Main process log.",PROC_TYPE_DEF );
   sprintf( log_strbuf, "Just created child worker process #%d with pid=%d.", id, fork_res);

   log_(getpid(), log_strbuf, PROC_TYPE_DEF );

   // register this child in our main table
   register_new_process(fork_res, PROC_TYPE_WORKER, id, 0);

   //sleep(1);
  }

  //main process continues here after ALL worker processes creation

  //close_log(getpid());
  //unregister_process(getpid(), PROC_TYPE_MAIN);

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

      while(1)
      {
          int i=0;
          // display main process table
          for (i=0;i<proc_desc_cnt;i++)
          {
              if (ppd[i].pid != 0)
              {
                //printf("   pid=%d\n", ppd[i].pid);
                log_(getpid(), "Watching for workers... ", PROC_TYPE_DEF );
              }
          }

          sleep(30);
      }
  }

  // main process runs here after WD creation
  sprintf( log_strbuf, "Just created WatchDog process with pid=%d.", fork_res);
  log_(getpid(), log_strbuf, PROC_TYPE_DEF );

  id = 0;

  //wait();
  while(1)
  {
      int i;

      //let's try to recreate died workers if any
      for (i=0; i<proc_desc_cnt; i++)
      {
        if (ppd[i].ptype != PROC_TYPE_WORKER || !ppd[i].pid || !ppd[i].died)
          continue;

        sprintf(log_strbuf, "Reforking worker #%d with new pid=%d\n", ppd[i].id, fork_res);
        printf(log_strbuf);
        log_(getpid(), log_strbuf, PROC_TYPE_MAIN );

        // make sure we don't try to recteate it one more time later
        ppd[i].died = 0;

        fork_res=fork();

        // main process continue to check for died
         if (fork_res > 0)
            continue;

        // we are a new child

        // process children termination
        signal(SIGCHLD, SIGCHLD_handler);

        //init tasks which are common for parent & child
        register_new_process(getpid(), PROC_TYPE_WORKER, ppd[i].id, ppd[i].pid);  // last arg mean old pid to replace instead of allocating new worker

        worker(ppd[i].id);  // never returns !!!
      }


      printf("Nothing to do for main process... %d\n", tick);
      sleep(5);
      tick++;
  }


  return 0;
}

