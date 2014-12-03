/*
CS544 
Linux kernel System Call Fuzzing project
by Li Li, David, Hafed Alghamdi
*/



#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <assert.h>

#define  SELF_VERSION           "0.1 alpha"

#define MAX_LEN_STR		4000
#define MAX_LEN_PATH		1024
#define MAX_LEN_FNAME           128
#define PROB_STR_NONASCII	5  // percents


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

int main()
{

  char* sp;
  long ret;
  int i, sysPID = syscall(SYS_getpid);
  printf("Crazy fuzzer version: `%s` \n", SELF_VERSION);
  printf("main process pid=%d\n", sysPID);
  printf("===================================================\n\n");

  for (i=0; i<20; i++)
  {
    sp = gen_fuz_path_dir();
    helper_log_fix_str(strbuf, outbuf);

    printf("***********************************************\n");
    printf("call -> sys_chdir(#1), \n\n#1 = `%s`\n\n", outbuf);
    ret = syscall(SYS_chdir, strbuf);
    printf("ret: %ld\n\n", ret);

  }
return 0;
}

