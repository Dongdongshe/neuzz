#define _GNU_SOURCE
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> 
#include <unistd.h>
#include <fcntl.h> 
#include <errno.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sched.h>
#include <sys/stat.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <dirent.h>
#include <ctype.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <time.h>

/* Most of code is borrowed directly from AFL fuzzer (https://github.com/mirrorer/afl), credits to Michal Zalewski */

/* Fork server init timeout multiplier: we'll wait the user-selected timeout plus this much for the fork server to spin up. */ 
#define FORK_WAIT_MULT      10
/* Environment variable used to pass SHM ID to the called program. */
#define SHM_ENV_VAR "__AFL_SHM_ID"
/* Local port to communicate with python module. */
#define PORT                12012
/* Maximum line length passed from GCC to 'as' and used for parsing configuration files. */
#define MAX_LINE            8192
/* Designated file descriptors for forkserver commands (the application will use FORKSRV_FD and FORKSRV_FD + 1). */
#define FORKSRV_FD          198
/* Distinctive bitmap signature used to indicate failed execution. */
#define EXEC_FAIL_SIG       0xfee1dead
/* Smoothing divisor for CPU load and exec speed stats (1 - no smoothing). */
#define AVG_SMOOTHING       16
/* Caps on block sizes for inserion and deletion operations. The set of numbers are adaptive to file length and the defalut max file length is 10000. */
/* default setting, will be changed later accroding to file len */
int havoc_blk_small = 2048;
int havoc_blk_medium = 4096;
int havoc_blk_large = 8192;
#define HAVOC_BLK_SMALL     2048
#define HAVOC_BLK_MEDIUM    4096
#define HAVOC_BLK_LARGE     7402
 
#define MEM_BARRIER() \
    asm volatile("" ::: "memory")
/* Map size for the traced binary. */
#define MAP_SIZE            2<<18
 
#define R(x) (random() % (x))
#define likely(_x)   __builtin_expect(!!(_x), 1)
#define unlikely(_x)  __builtin_expect(!!(_x), 0)
#define MIN(_a,_b) ((_a) > (_b) ? (_b) : (_a))
#define MAX(_a,_b) ((_a) > (_b) ? (_a) : (_b))
 
/* Error-checking versions of read() and write() that call RPFATAL() as appropriate. */
#define ck_write(fd, buf, len, fn) do { \
    u32 _len = (len); \
    int _res = write(fd, buf, _len); \
    if (_res != _len) fprintf(stderr, "Short write to %d %s\n",_res, fn); \
} while (0)
 
#define ck_read(fd, buf, len, fn) do { \
    u32 _len = (len); \
    int _res = read(fd, buf, _len); \
    if (_res != _len) fprintf(stderr, "Short read from %d %s\n",_res, fn); \
} while (0)
 
/* User-facing macro to sprintf() to a dynamically allocated buffer. */
#define alloc_printf(_str...) ({ \
    char* _tmp; \
    int _len = snprintf(NULL, 0, _str); \
    if (_len < 0) perror("Whoa, snprintf() fails?!"); \
    _tmp = malloc(_len + 1); \
    snprintf((char*)_tmp, _len + 1, _str); \
    _tmp; \
})


typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
#ifdef __x86_64__
typedef unsigned long long u64;
#else
typedef uint64_t u64;
#endif /* ^__x86_64__ */

unsigned long total_execs;              /* Total number of execs */
static int shm_id;                      /* ID of the SHM region */
static int mem_limit  = 1024;           /* Maximum memory limit for target program */
static int cpu_aff = -1;                /* Selected CPU core */
int round_cnt = 0;                      /* Round number counter */
int edge_gain=0;                        /* If there is new edge gain */
int exec_tmout = 1000;                  /* Exec timeout (ms)                 */

int stage_num = 1;
int old=0;
int now=0;
int fast=1;
char * target_path;                     /* Path to target binary            */
char * trace_bits;                      /* SHM with instrumentation bitmap  */ 
static volatile int stop_soon;          /* Ctrl-C pressed?                  */
static int cpu_core_count;              /* CPU core count                   */
static u64 total_cal_us=0;              /* Total calibration time (us)      */
static volatile int child_timed_out;    /* Traced process timed out?        */
int kill_signal;                        /* Signal that killed the child     */
static int out_fd,                      /* Persistent fd for out_file       */
           dev_urandom_fd = -1,         /* Persistent fd for /dev/urandom   */
           dev_null_fd = -1,            /* Persistent fd for /dev/null      */
           fsrv_ctl_fd,                 /* Fork server control pipe (write) */
           fsrv_st_fd;                  /* Fork server status pipe (read)   */
static int forksrv_pid,                 /* PID of the fork server           */
           child_pid = -1,              /* PID of the fuzzed program        */
           out_dir_fd = -1;             /* FD of the lock file              */

char *in_dir,                           /* Input directory with test cases  */
     *out_file,                         /* File to fuzz, if any             */
     *out_dir;                          /* Working & output directory       */
char virgin_bits[MAP_SIZE];             /* Regions yet untouched by fuzzing */
static int mut_cnt = 0;                 /* Total mutation counter           */
char *out_buf, *out_buf1, *out_buf2, *out_buf3;
size_t len;                             /* Maximum file length for every mutation */
int loc[10000];                         /* Array to store critical bytes locations*/
int sign[10000];                        /* Array to store sign of critical bytes  */

/* more fined grined mutation can have better results but slower*/
//int num_index[23] = {0,2,4,8,16,32,64,128,256,512,1024,1536,2048,2560,3072, 3584,4096,4608,5120, 5632,6144,6656,7103};
/* default setting, will be change according to different file length */
int num_index[14] = {0,2,4,8,16,32,64,128,256,512,1024,2048,4096,8192};

enum {
  /* 00 */ FAULT_NONE,
  /* 01 */ FAULT_TMOUT,
  /* 02 */ FAULT_CRASH,
  /* 03 */ FAULT_ERROR,
  /* 04 */ FAULT_NOINST,
  /* 05 */ FAULT_NOBITS
};

/* Spin up fork server (instrumented mode only). The idea is explained here:
   http://lcamtuf.blogspot.com/2014/10/fuzzing-binaries-without-execve.html
   In essence, the instrumentation allows us to skip execve(), and just keep
   cloning a stopped child. So, we just execute once, and then send commands
   through a pipe. The other part of this logic is in afl-as.h. */
void setup_stdio_file(void) {

  char* fn = alloc_printf("%s/.cur_input", out_dir);

  unlink(fn); /* Ignore errors */

  out_fd = open(fn, O_RDWR | O_CREAT | O_EXCL, 0600);

  if (out_fd < 0) perror("Unable to create .cur_input");

  free(fn);

}

/* Count the number of non-255 bytes set in the bitmap. Used strictly for the
   status screen, several calls per second or so. */
#define FF(_b)  (0xff << ((_b) << 3))
static u32 count_non_255_bytes(u8* mem) {

  u32* ptr = (u32*)mem;
  u32  i   = (MAP_SIZE >> 2);
  u32  ret = 0;

  while (i--) {

    u32 v = *(ptr++);

    /* This is called on the virgin bitmap, so optimize for the most likely
       case. */

    if (v == 0xffffffff) continue;
    if ((v & FF(0)) != FF(0)) ret++;
    if ((v & FF(1)) != FF(1)) ret++;
    if ((v & FF(2)) != FF(2)) ret++;
    if ((v & FF(3)) != FF(3)) ret++;

  }

  return ret;

}

/* Handle stop signal (Ctrl-C, etc). */

static void handle_stop_sig(int sig) {

  stop_soon = 1; 

  if (child_pid > 0) kill(child_pid, SIGKILL);
  if (forksrv_pid > 0) kill(forksrv_pid, SIGKILL);
  printf("total execs %ld edge coverage %d.\n", total_execs,(int)(count_non_255_bytes(virgin_bits)));
  
  //free buffer
  free(out_buf);
  free(out_buf1);
  free(out_buf2);
  free(out_buf3);
  exit(0);
}

/* Check if the current execution path brings anything new to the table.
   Update virgin bits to reflect the finds. Returns 1 if the only change is
   the hit-count for a particular tuple; 2 if there are new tuples seen. 
   Updates the map, so subsequent calls will always return 0.
   This function is called after every exec() on a fairly large buffer, so
   it needs to be fast. We do this in 32-bit and 64-bit flavors. */

static inline char has_new_bits(char* virgin_map) {

#ifdef __x86_64__

  u64* current = (u64*)trace_bits;
  u64* virgin  = (u64*)virgin_map;

  u32  i = (MAP_SIZE >> 3);

#else

  u32* current = (u32*)trace_bits;
  u32* virgin  = (u32*)virgin_map;

  u32  i = (MAP_SIZE >> 2);

#endif /* ^__x86_64__ */

  u8   ret = 0;

  while (i--) {

    /* Optimize for (*current & *virgin) == 0 - i.e., no bits in current bitmap
       that have not been already cleared from the virgin map - since this will
       almost always be the case. */

    if (unlikely(*current) && unlikely(*current & *virgin)) {

      if (likely(ret < 2)) {

        u8* cur = (u8*)current;
        u8* vir = (u8*)virgin;

        /* Looks like we have not found any new bytes yet; see if any non-zero
           bytes in current[] are pristine in virgin[]. */

#ifdef __x86_64__

        if ((cur[0] && vir[0] == 0xff) || (cur[1] && vir[1] == 0xff) ||
            (cur[2] && vir[2] == 0xff) || (cur[3] && vir[3] == 0xff) ||
            (cur[4] && vir[4] == 0xff) || (cur[5] && vir[5] == 0xff) ||
            (cur[6] && vir[6] == 0xff) || (cur[7] && vir[7] == 0xff)) ret = 2;
        else ret = 1;

#else

        if ((cur[0] && vir[0] == 0xff) || (cur[1] && vir[1] == 0xff) ||
            (cur[2] && vir[2] == 0xff) || (cur[3] && vir[3] == 0xff)) ret = 2;
        else ret = 1;

#endif /* ^__x86_64__ */

      }

      *virgin &= ~*current;

    }

    current++;
    virgin++;

  }

  return ret;

}


/* Handle timeout (SIGALRM). */

static void handle_timeout(int sig) {

  if (child_pid > 0) {

    child_timed_out = 1; 
    kill(child_pid, SIGKILL);

  } else if (child_pid == -1 && forksrv_pid > 0) {

    child_timed_out = 1; 
    kill(forksrv_pid, SIGKILL);

  }

}

/* Set up signal handlers. More complicated that needs to be, because libc on
   Solaris doesn't resume interrupted reads(), sets SA_RESETHAND when you call
   siginterrupt(), and does other stupid things. */

void setup_signal_handlers(void) {

  struct sigaction sa;

  sa.sa_handler   = NULL;
  sa.sa_flags     = SA_RESTART;
  sa.sa_sigaction = NULL;

  sigemptyset(&sa.sa_mask);

  /* Various ways of saying "stop". */

  sa.sa_handler = handle_stop_sig;
  sigaction(SIGHUP, &sa, NULL);
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);

  /* Exec timeout notifications. */

  sa.sa_handler = handle_timeout;
  sigaction(SIGALRM, &sa, NULL);

  /* Things we don't care about. */

  sa.sa_handler = SIG_IGN;
  sigaction(SIGTSTP, &sa, NULL);
  sigaction(SIGPIPE, &sa, NULL);

}

void init_forkserver(char** argv) {

  static struct itimerval it;
  int st_pipe[2], ctl_pipe[2];
  int status;
  int rlen;
  char* cwd = getcwd(NULL, 0);
  out_file = alloc_printf("%s/%s/.cur_input",cwd, out_dir);
  printf("Spinning up the fork server...\n");

  if (pipe(st_pipe) || pipe(ctl_pipe)) perror("pipe() failed");

  forksrv_pid = fork();

  if (forksrv_pid < 0) perror("fork() failed");

  if (!forksrv_pid) {

    struct rlimit r;

    /* Umpf. On OpenBSD, the default fd limit for root users is set to
       soft 128. Let's try to fix that... */

    if (!getrlimit(RLIMIT_NOFILE, &r) && r.rlim_cur < FORKSRV_FD + 2) {

      r.rlim_cur = FORKSRV_FD + 2;
      setrlimit(RLIMIT_NOFILE, &r); /* Ignore errors */

    }

    if (mem_limit) {

      r.rlim_max = r.rlim_cur = ((rlim_t)mem_limit) << 20;

#ifdef RLIMIT_AS

      setrlimit(RLIMIT_AS, &r); /* Ignore errors */

#else

      /* This takes care of OpenBSD, which doesn't have RLIMIT_AS, but
         according to reliable sources, RLIMIT_DATA covers anonymous
         maps - so we should be getting good protection against OOM bugs. */

      setrlimit(RLIMIT_DATA, &r); /* Ignore errors */

#endif /* ^RLIMIT_AS */


    }

    /* Dumping cores is slow and can lead to anomalies if SIGKILL is delivered
       before the dump is complete. */

    r.rlim_max = r.rlim_cur = 0;

    setrlimit(RLIMIT_CORE, &r); /* Ignore errors */

    /* Isolate the process and configure standard descriptors. If out_file is
       specified, stdin is /dev/null; otherwise, out_fd is cloned instead. */

    setsid();

    dup2(dev_null_fd, 1);
    dup2(dev_null_fd, 2);

    if (out_file) {

      dup2(dev_null_fd, 0);

    } else {

      dup2(out_fd, 0);
      close(out_fd);

    }

    /* Set up control and status pipes, close the unneeded original fds. */

    if (dup2(ctl_pipe[0], FORKSRV_FD) < 0) perror("dup2() failed");
    if (dup2(st_pipe[1], FORKSRV_FD + 1) < 0) perror("dup2() failed");

    close(ctl_pipe[0]);
    close(ctl_pipe[1]);
    close(st_pipe[0]);
    close(st_pipe[1]);

    close(out_dir_fd);
    close(dev_null_fd);
    close(dev_urandom_fd);

    /* This should improve performance a bit, since it stops the linker from
       doing extra work post-fork(). */

    if (!getenv("LD_BIND_LAZY")) setenv("LD_BIND_NOW", "1", 0);


    execv(target_path, argv);
    
    /* Use a distinctive bitmap signature to tell the parent about execv()
       falling through. */
    *(int *)trace_bits = EXEC_FAIL_SIG;
    exit(0);

  }

  /* Close the unneeded endpoints. */

  close(ctl_pipe[0]);
  close(st_pipe[1]);

  fsrv_ctl_fd = ctl_pipe[1];
  fsrv_st_fd  = st_pipe[0];

  /* Wait for the fork server to come up, but don't wait too long. */

  it.it_value.tv_sec = ((exec_tmout * FORK_WAIT_MULT) / 1000);
  it.it_value.tv_usec = ((exec_tmout * FORK_WAIT_MULT) % 1000) * 1000;

  setitimer(ITIMER_REAL, &it, NULL);

  rlen = read(fsrv_st_fd, &status, 4);

  it.it_value.tv_sec = 0;
  it.it_value.tv_usec = 0;

  setitimer(ITIMER_REAL, &it, NULL);

  /* If we have a four-byte "hello" message from the server, we're all set.
     Otherwise, try to figure out what went wrong. */

  if (rlen == 4) {
    printf("All right - fork server is up.");
    return;
  }

  if (child_timed_out)
    perror("Timeout while initializing fork server (adjusting -t may help)");

  if (waitpid(forksrv_pid, &status, 0) <= 0)
    perror("waitpid() failed");

  if (WIFSIGNALED(status)) {

    fprintf(stderr, "Fork server crashed with signal %d", WTERMSIG(status));

  }

  if (*(int*)trace_bits == EXEC_FAIL_SIG)
    fprintf(stderr, "Unable to execute target application ('%s')", argv[0]);

  perror("Fork server handshake failed");
  
}

/* Get rid of shared memory (atexit handler). */

static void remove_shm(void) {

  shmctl(shm_id, IPC_RMID, NULL);

}

/* Configure shared memory and virgin_bits. This is called at startup. */

void setup_shm(void) {

  char* shm_str;

  memset(virgin_bits, 255, MAP_SIZE);

  shm_id = shmget(IPC_PRIVATE, MAP_SIZE, IPC_CREAT | IPC_EXCL | 0600);

  if (shm_id < 0) perror("shmget() failed");

  atexit(remove_shm);

  shm_str = alloc_printf("%d", shm_id);

  /* If somebody is asking us to fuzz instrumented binaries in dumb mode,
     we don't want them to detect instrumentation, since we won't be sending
     fork server commands. This should be replaced with better auto-detection
     later on, perhaps? */

  setenv(SHM_ENV_VAR, shm_str, 1);

  free(shm_str);

  trace_bits = shmat(shm_id, NULL, 0);

  if (!trace_bits) perror("shmat() failed");

}

void setup_dirs_fds(void) {

  char* tmp;
  int fd;

  printf("Setting up output directories...");


  if (mkdir(out_dir, 0700)) {

    if (errno != EEXIST) fprintf(stderr,"Unable to create %s\n", out_dir);

  }

  /* Generally useful file descriptors. */

  dev_null_fd = open("/dev/null", O_RDWR);
  if (dev_null_fd < 0) perror("Unable to open /dev/null");

  dev_urandom_fd = open("/dev/urandom", O_RDONLY);
  if (dev_urandom_fd < 0) perror("Unable to open /dev/urandom");

}


/* Detect @@ in args. */

void detect_file_args(char** argv) {

  int i = 0;
  char* cwd = getcwd(NULL, 0);

  if (!cwd) perror("getcwd() failed");

  while (argv[i]) {

    char* aa_loc = strstr(argv[i], "@@");

    if (aa_loc) {

      char *aa_subst, *n_arg;

      /* If we don't have a file name chosen yet, use a safe default. */

      if (!out_file)
        out_file = alloc_printf("%s/.cur_input", out_dir);

      /* Be sure that we're always using fully-qualified paths. */

      if (out_file[0] == '/') aa_subst = out_file;
      else aa_subst = alloc_printf("%s/%s", cwd, out_file);

      /* Construct a replacement argv value. */

      *aa_loc = 0;
      n_arg = alloc_printf("%s%s%s", argv[i], aa_subst, aa_loc + 2);
      argv[i] = n_arg;
      *aa_loc = '@';

      if (out_file[0] != '/') free(aa_subst);

    }

    i++;

  }

  free(cwd); /* not tracked */

}

/* set up target path */ 
void setup_targetpath(char * argvs){
    char* cwd = getcwd(NULL, 0);
    target_path = alloc_printf("%s/%s", cwd, argvs);
    argvs = target_path;
}

/* Destructively classify execution counts in a trace. This is used as a
   preprocessing step for any newly acquired traces. Called on every exec,
   must be fast. */
static const u8 count_class_lookup8[256] = {

  [0]           = 0,
  [1]           = 1,
  [2]           = 2,
  [3]           = 4,
  [4 ... 7]     = 8,
  [8 ... 15]    = 16,
  [16 ... 31]   = 32,
  [32 ... 127]  = 64,
  [128 ... 255] = 128

};

static u16 count_class_lookup16[65536];


void init_count_class16(void) {

  u32 b1, b2;

  for (b1 = 0; b1 < 256; b1++)
    for (b2 = 0; b2 < 256; b2++)
      count_class_lookup16[(b1 << 8) + b2] =
        (count_class_lookup8[b1] << 8) |
        count_class_lookup8[b2];

}


#ifdef __x86_64__

static inline void classify_counts(u64* mem) {

  u32 i = MAP_SIZE >> 3;

  while (i--) {

    /* Optimize for sparse bitmaps. */

    if (unlikely(*mem)) {

      u16* mem16 = (u16*)mem;

      mem16[0] = count_class_lookup16[mem16[0]];
      mem16[1] = count_class_lookup16[mem16[1]];
      mem16[2] = count_class_lookup16[mem16[2]];
      mem16[3] = count_class_lookup16[mem16[3]];

    }

    mem++;

  }

}

#else

static inline void classify_counts(u32* mem) {

  u32 i = MAP_SIZE >> 2;

  while (i--) {

    /* Optimize for sparse bitmaps. */

    if (unlikely(*mem)) {

      u16* mem16 = (u16*)mem;

      mem16[0] = count_class_lookup16[mem16[0]];
      mem16[1] = count_class_lookup16[mem16[1]];

    }

    mem++;

  }

}

#endif /* ^__x86_64__ */


/* Get the number of runnable processes, with some simple smoothing. */

static double get_runnable_processes(void) {

  static double res;

#if defined(__APPLE__) || defined(__FreeBSD__) || defined (__OpenBSD__)

  /* I don't see any portable sysctl or so that would quickly give us the
     number of runnable processes; the 1-minute load average can be a
     semi-decent approximation, though. */

  if (getloadavg(&res, 1) != 1) return 0;

#else

  /* On Linux, /proc/stat is probably the best way; load averages are
     computed in funny ways and sometimes don't reflect extremely short-lived
     processes well. */

  FILE* f = fopen("/proc/stat", "r");
  u8 tmp[1024];
  u32 val = 0;

  if (!f) return 0;

  while (fgets(tmp, sizeof(tmp), f)) {

    if (!strncmp(tmp, "procs_running ", 14) ||
        !strncmp(tmp, "procs_blocked ", 14)) val += atoi(tmp + 14);

  }
 
  fclose(f);

  if (!res) {

    res = val;

  } else {

    res = res * (1.0 - 1.0 / AVG_SMOOTHING) +
          ((double)val) * (1.0 / AVG_SMOOTHING);

  }

#endif /* ^(__APPLE__ || __FreeBSD__ || __OpenBSD__) */

  return res;

}


/* Count the number of logical CPU cores. */

static void get_core_count(void) {

  u32 cur_runnable = 0;

#if defined(__APPLE__) || defined(__FreeBSD__) || defined (__OpenBSD__)

  size_t s = sizeof(cpu_core_count);

  /* On *BSD systems, we can just use a sysctl to get the number of CPUs. */

#ifdef __APPLE__

  if (sysctlbyname("hw.logicalcpu", &cpu_core_count, &s, NULL, 0) < 0)
    return;

#else

  int s_name[2] = { CTL_HW, HW_NCPU };

  if (sysctl(s_name, 2, &cpu_core_count, &s, NULL, 0) < 0) return;

#endif /* ^__APPLE__ */

#else

#ifdef HAVE_AFFINITY

  cpu_core_count = sysconf(_SC_NPROCESSORS_ONLN);

#else

  FILE* f = fopen("/proc/stat", "r");
  u8 tmp[1024];

  if (!f) return;

  while (fgets(tmp, sizeof(tmp), f))
    if (!strncmp(tmp, "cpu", 3) && isdigit(tmp[3])) cpu_core_count++;

  fclose(f);

#endif /* ^HAVE_AFFINITY */

#endif /* ^(__APPLE__ || __FreeBSD__ || __OpenBSD__) */

  if (cpu_core_count > 0) {

    cur_runnable = (u32)get_runnable_processes();

#if defined(__APPLE__) || defined(__FreeBSD__) || defined (__OpenBSD__)

    /* Add ourselves, since the 1-minute average doesn't include that yet. */

    cur_runnable++;

#endif /* __APPLE__ || __FreeBSD__ || __OpenBSD__ */

    printf("You have %u CPU core%s and %u runnable tasks (utilization: %0.0f%%).\n",
        cpu_core_count, cpu_core_count > 1 ? "s" : "",
        cur_runnable, cur_runnable * 100.0 / cpu_core_count);

    if (cpu_core_count > 1) {

      if (cur_runnable > cpu_core_count * 1.5) {

        printf("System under apparent load, performance may be spotty.\n");

      }

    }

  } else {

    cpu_core_count = 0;
    printf("Unable to figure out the number of CPU cores.\n");

  }

}

/* Build a list of processes bound to specific cores. Returns -1 if nothing
   can be found. Assumes an upper bound of 4k CPUs. */
static void bind_to_free_cpu(void) {

  DIR* d;
  struct dirent* de;
  cpu_set_t c;

  u8 cpu_used[4096] = { 0 };
  u32 i;

  if (cpu_core_count < 2) return;

  if (getenv("AFL_NO_AFFINITY")) {

    perror("Not binding to a CPU core (AFL_NO_AFFINITY set).");
    return;

  }

  d = opendir("/proc");

  if (!d) {

    perror("Unable to access /proc - can't scan for free CPU cores.");
    return;

  }

  printf("Checking CPU core loadout...\n");

  /* Introduce some jitter, in case multiple AFL tasks are doing the same
     thing at the same time... */

  usleep(R(1000) * 250);

  /* Scan all /proc/<pid>/status entries, checking for Cpus_allowed_list.
     Flag all processes bound to a specific CPU using cpu_used[]. This will
     fail for some exotic binding setups, but is likely good enough in almost
     all real-world use cases. */

  while ((de = readdir(d))) {

    u8* fn;
    FILE* f;
    u8 tmp[MAX_LINE];
    u8 has_vmsize = 0;

    if (!isdigit(de->d_name[0])) continue;

    fn = alloc_printf("/proc/%s/status", de->d_name);

    if (!(f = fopen(fn, "r"))) {
      free(fn);
      continue;
    }

    while (fgets(tmp, MAX_LINE, f)) {

      u32 hval;

      /* Processes without VmSize are probably kernel tasks. */

      if (!strncmp(tmp, "VmSize:\t", 8)) has_vmsize = 1;

      if (!strncmp(tmp, "Cpus_allowed_list:\t", 19) &&
          !strchr(tmp, '-') && !strchr(tmp, ',') &&
          sscanf(tmp + 19, "%u", &hval) == 1 && hval < sizeof(cpu_used) &&
          has_vmsize) {

        cpu_used[hval] = 1;
        break;

      }

    }

    free(fn);
    fclose(f);

  }

  closedir(d);

  for (i = 0; i < cpu_core_count; i++) if (!cpu_used[i]) break;

  if (i == cpu_core_count) {
    printf("No more free CPU cores\n");

  }

  printf("Found a free CPU core, binding to #%u.\n", i);

  cpu_aff = i;

  CPU_ZERO(&c);
  CPU_SET(i, &c);

  if (sched_setaffinity(0, sizeof(c), &c))
    perror("sched_setaffinity failed\n");

}

 /* Get unix time in microseconds */
 
 static u64 get_cur_time_us(void) {
 
   struct timeval tv;
   struct timezone tz;
 
   gettimeofday(&tv, &tz);
 
   return (tv.tv_sec * 1000000ULL) + tv.tv_usec;
 
 }


/* Execute target application, monitoring for timeouts. Return status
   information. The called program will update trace_bits[]. */

static u8 run_target(int timeout) {

  static struct itimerval it;
  static u32 prev_timed_out = 0;

  int status = 0;

  child_timed_out = 0;

  /* After this memset, trace_bits[] are effectively volatile, so we
     must prevent any earlier operations from venturing into that
     territory. */

  memset(trace_bits, 0, MAP_SIZE);
  MEM_BARRIER();

    int res;

    /* In non-dumb mode, we have the fork server up and running, so simply
       tell it to have at it, and then read back PID. */

    if ((res = write(fsrv_ctl_fd, &prev_timed_out, 4)) != 4) {

      if (stop_soon) return 0;
      fprintf(stderr,"err%d: Unable to request new process from fork server (OOM?)", res);

    }

    if ((res = read(fsrv_st_fd, &child_pid, 4)) != 4) {

      if (stop_soon) return 0;
      fprintf(stderr, "err%d: Unable to request new process from fork server (OOM?)",res);

    }
    if (child_pid <= 0) perror("Fork server is misbehaving (OOM?)");


  /* Configure timeout, as requested by user, then wait for child to terminate. */

  it.it_value.tv_sec = (timeout / 1000);
  it.it_value.tv_usec = (timeout % 1000) * 1000;

  setitimer(ITIMER_REAL, &it, NULL);

  /* The SIGALRM handler simply kills the child_pid and sets child_timed_out. */



    if ((res = read(fsrv_st_fd, &status, 4)) != 4) {

      if (stop_soon) return 0;
      fprintf(stderr, "err%d: Unable to communicate with fork server (OOM?)",res);

    }


  if (!WIFSTOPPED(status)) child_pid = 0;

  it.it_value.tv_sec = 0;
  it.it_value.tv_usec = 0;

  setitimer(ITIMER_REAL, &it, NULL);

  total_execs++;

  /* Any subsequent operations on trace_bits must not be moved by the
     compiler below this point. Past this location, trace_bits[] behave
     very normally and do not have to be treated as volatile. */

  MEM_BARRIER();


#ifdef __x86_64__
  classify_counts((u64*)trace_bits);
#else
  classify_counts((u32*)trace_bits);
#endif /* ^__x86_64__ */

  prev_timed_out = child_timed_out;

  /* Report outcome to caller. */

  if (WIFSIGNALED(status) && !stop_soon) {

    kill_signal = WTERMSIG(status);

    if (child_timed_out && kill_signal == SIGKILL) return FAULT_TMOUT;

    return FAULT_CRASH;

  }
  return FAULT_NONE;

}

/* Write modified data to file for testing. If out_file is set, the old file
   is unlinked and a new one is created. Otherwise, out_fd is rewound and
   truncated. */

static void write_to_testcase(void* mem, u32 len) {

  int fd = out_fd;

    unlink(out_file); /* Ignore errors. */

    fd = open(out_file, O_WRONLY | O_CREAT | O_EXCL, 0600);

    if (fd < 0) perror("Unable to create file");


  ck_write(fd, mem, len, out_file);

  close(fd);

}

/* Check CPU governor. */

static void check_cpu_governor(void) {

  FILE* f;
  u8 tmp[128];
  u64 min = 0, max = 0;

  if (getenv("AFL_SKIP_CPUFREQ")) return;

  f = fopen("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor", "r");
  if (!f) return;

  printf("Checking CPU scaling governor...\n");

  if (!fgets(tmp, 128, f)) perror("fgets() failed");

  fclose(f);

  if (!strncmp(tmp, "perf", 4)) return;

  f = fopen("/sys/devices/system/cpu/cpu0/cpufreq/scaling_min_freq", "r");

  if (f) {
    if (fscanf(f, "%llu", &min) != 1) min = 0;
    fclose(f);
  }

  f = fopen("/sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq", "r");

  if (f) {
    if (fscanf(f, "%llu", &max) != 1) max = 0;
    fclose(f);
  }

  if (min == max) return;

  printf("Err: Suboptimal CPU scaling governor\n");

}

/* parse one line of gradient string into array */
void parse_array(char * str, int * array){
    
    int i=0;
    
    char* token = strtok(str,",");
    
    while(token != NULL){
        array[i]=atoi(token);
        i++;
        token = strtok(NULL, ",");
    }

    return;
}

/* Helper to choose random block len for block operations in fuzz_one().
   Doesn't return zero, provided that max_len is > 0. */

static u32 choose_block_len(u32 limit) {

  u32 min_value, max_value;

  switch ((random()%3)) {

    case 0:  min_value = 1;
             max_value = havoc_blk_small;
             break;

    case 1:  min_value = havoc_blk_small;
             max_value = havoc_blk_medium;
             break;

    case 2:  min_value = havoc_blk_medium;
             max_value = havoc_blk_large;
  }

  if (min_value >= limit) min_value = 1;

  return min_value + (random()%(MIN(max_value, limit) - min_value + 1));

}

/* gradient guided mutation */
void gen_mutate(){
    int tmout_cnt = 0;
    
    /* flip interesting locations within 14 iterations */
    for(int iter=0 ;iter<13; iter=iter+1){
        memcpy(out_buf1, out_buf, len);        
        memcpy(out_buf2, out_buf, len);        
        
        /* find mutation range for every iteration */
        int low_index = num_index[iter];
        int up_index = num_index[iter+1];
        u8 up_step = 0;
        u8 low_step = 0;
        for(int index=low_index; index<up_index; index=index+1){
            int cur_up_step = 0;
            int cur_low_step = 0;
            if(sign[index] == 1){
                cur_up_step = (255 - (u8)out_buf[loc[index]]);
                if(cur_up_step > up_step)
                    up_step = cur_up_step;
                cur_low_step = (u8)(out_buf[loc[index]]);
                if(cur_low_step > low_step)
                    low_step = cur_low_step;
            }
            else{
                cur_up_step = (u8)out_buf[loc[index]];
                if(cur_up_step > up_step)
                    up_step = cur_up_step;
                cur_low_step = (255 - (u8)out_buf[loc[index]]);
                if(cur_low_step > low_step)
                    low_step = cur_low_step;
            }
        }
        
        /* up direction mutation(up to 255) */
        for(int step=0;step<up_step;step=step+1){
            int mut_val;
            for(int index=low_index; index<up_index; index=index+1){
                mut_val = ((u8)out_buf1[loc[index]] + sign[index]);
                if(mut_val < 0)
                    out_buf1[loc[index]] = 0;
                else if (mut_val > 255)
                    out_buf1[loc[index]] = 255;
                else
                    out_buf1[loc[index]] = mut_val;
            }

            write_to_testcase(out_buf1, len);    
            int fault = run_target(exec_tmout); 
            if (fault != 0){
                if(fault == FAULT_CRASH){
                    char* mut_fn = alloc_printf("%s/crash_%d_%06d", "./crashes",round_cnt, mut_cnt);
                    int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
                    ck_write(mut_fd, out_buf1, len, mut_fn);
                    free(mut_fn);
                    close(mut_fd);
                    mut_cnt = mut_cnt + 1;
                }
                else if((fault = FAULT_TMOUT) && (tmout_cnt < 20)){
                    tmout_cnt = tmout_cnt + 1;
                    fault = run_target(1000); 
                    if(fault == FAULT_CRASH){
                        char* mut_fn = alloc_printf("%s/crash_%d_%06d", "./crashes",round_cnt, mut_cnt);
                        int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
                        ck_write(mut_fd, out_buf1, len, mut_fn);
                        free(mut_fn);
                        close(mut_fd);
                        mut_cnt = mut_cnt + 1;
                    } 
                }
            }
            /* save mutations that find new edges. */
            int ret = has_new_bits(virgin_bits);
            if(ret == 2){
                char* mut_fn = alloc_printf("%s/id_%d_%d_%06d_cov", out_dir, round_cnt, iter, mut_cnt);
                int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
                ck_write(mut_fd, out_buf1, len, mut_fn);
                free(mut_fn);
                close(mut_fd);
                mut_cnt = mut_cnt + 1;
            }
            if(ret == 1){
                char* mut_fn = alloc_printf("%s/id_%d_%d_%06d", out_dir, round_cnt, iter, mut_cnt);
                int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
                ck_write(mut_fd, out_buf1, len, mut_fn);
                free(mut_fn);
                close(mut_fd);
                mut_cnt = mut_cnt + 1;
            }
            
        }
        
        /* low direction mutation(up to 255) */
        for(int step=0;step<low_step;step=step+1){
            for(int index=low_index; index<up_index;index=index+1){
                int mut_val = ((u8)out_buf2[loc[index]] - sign[index]);
                if(mut_val < 0)
                    out_buf2[loc[index]] = 0;
                else if (mut_val > 255)
                    out_buf2[loc[index]] = 255;
                else
                    out_buf2[loc[index]] = mut_val;
            }
            
            write_to_testcase(out_buf2, len);    
            int fault = run_target(exec_tmout); 
            if (fault != 0){
                if(fault == FAULT_CRASH){
                    char* mut_fn = alloc_printf("%s/crash_%d_%06d", "./crashes",round_cnt, mut_cnt);
                    int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
                    ck_write(mut_fd, out_buf2, len, mut_fn);
                    free(mut_fn);
                    close(mut_fd);
                    mut_cnt = mut_cnt + 1;
                }
                else if((fault = FAULT_TMOUT) && (tmout_cnt < 20)){
                    tmout_cnt = tmout_cnt + 1;
                    fault = run_target(1000); 
                    if(fault == FAULT_CRASH){
                        char* mut_fn = alloc_printf("%s/crash_%d_%06d", "./crashes",round_cnt, mut_cnt);
                        int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
                        ck_write(mut_fd, out_buf2, len, mut_fn);
                        free(mut_fn);
                        close(mut_fd);
                        mut_cnt = mut_cnt + 1;
                    } 
                }
            }
            
            /* save mutations that find new edges. */
            int ret = has_new_bits(virgin_bits);
            if(ret == 2){
                char* mut_fn = alloc_printf("%s/id_%d_%d_%06d_cov", out_dir, round_cnt, iter, mut_cnt);
                int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
                ck_write(mut_fd, out_buf2, len, mut_fn);
                close(mut_fd);
                free(mut_fn);
                mut_cnt = mut_cnt + 1;
            }
            if(ret == 1){
                char* mut_fn = alloc_printf("%s/id_%d_%d_%06d", out_dir, round_cnt, iter, mut_cnt);
                int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
                ck_write(mut_fd, out_buf2, len, mut_fn);
                close(mut_fd);
                free(mut_fn);
                mut_cnt = mut_cnt + 1;
            }
            
        }
    }
    
    /* random insertion/deletion */
    int cut_len = 0;
    int del_loc = 0;
    int rand_loc = 0;
    for(int del_count=0; del_count < 1024;del_count= del_count+1){
        del_loc = loc[del_count];
        if ((len- del_loc) <= 2)
            continue;
        cut_len = choose_block_len(len-1-del_loc);
        
        /* random deletion at a critical offset */
        memcpy(out_buf1, out_buf,del_loc);
        memcpy(out_buf1+del_loc, out_buf+del_loc+cut_len, len-del_loc-cut_len);
        
        write_to_testcase(out_buf1, len-cut_len);    
        
        int fault = run_target(exec_tmout); 
        if (fault != 0){
            if(fault == FAULT_CRASH){
                char* mut_fn = alloc_printf("%s/crash_%d_%06d", "./crashes",round_cnt, mut_cnt);
                int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
                ck_write(mut_fd, out_buf1, len-cut_len, mut_fn);
                free(mut_fn);
                close(mut_fd);
                mut_cnt = mut_cnt + 1;
            }
            else if((fault = FAULT_TMOUT) && (tmout_cnt < 20)){
                tmout_cnt = tmout_cnt + 1;
                fault = run_target(1000); 
                if(fault == FAULT_CRASH){
                    char* mut_fn = alloc_printf("%s/crash_%d_%06d", "./crashes",round_cnt, mut_cnt);
                    int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
                    ck_write(mut_fd, out_buf1, len - cut_len, mut_fn);
                    free(mut_fn);
                    close(mut_fd);
                    mut_cnt = mut_cnt + 1;
                } 
            }
        }
                 
        /* save mutations that find new edges. */
        int ret = has_new_bits(virgin_bits);
        if(ret==2){
            char* mut_fn = alloc_printf("%s/id_%d_%06d_cov", out_dir,round_cnt, mut_cnt);
            int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
            ck_write(mut_fd, out_buf1, len-cut_len, mut_fn);
            free(mut_fn);
            close(mut_fd);
            mut_cnt = mut_cnt + 1;
        }
        else if(ret==1){
            char* mut_fn = alloc_printf("%s/id_%d_%06d", out_dir,round_cnt, mut_cnt);
            int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
            ck_write(mut_fd, out_buf1, len-cut_len, mut_fn);
            free(mut_fn);
            close(mut_fd);
            mut_cnt = mut_cnt + 1;
        }

        cut_len = choose_block_len(len-1);
        rand_loc = (random()%cut_len);
        
        /* random insertion at a critical offset */
        memcpy(out_buf3, out_buf, del_loc);
        memcpy(out_buf3+del_loc, out_buf+rand_loc, cut_len);
        memcpy(out_buf3+del_loc+cut_len, out_buf+del_loc, len-del_loc);
        
        write_to_testcase(out_buf3, len+cut_len);    
        
        fault = run_target(exec_tmout); 
        if (fault != 0){
            if(fault == FAULT_CRASH){
                char* mut_fn = alloc_printf("%s/crash_%d_%06d", "./crashes",round_cnt, mut_cnt);
                int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
                ck_write(mut_fd, out_buf3, len+cut_len, mut_fn);
                free(mut_fn);
                close(mut_fd);
                mut_cnt = mut_cnt + 1;
            }
            else if((fault = FAULT_TMOUT) && (tmout_cnt < 20)){
                tmout_cnt = tmout_cnt + 1;
                fault = run_target(1000); 
                if(fault == FAULT_CRASH){
                    char* mut_fn = alloc_printf("%s/crash_%d_%06d", "./crashes",round_cnt, mut_cnt);
                    int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
                    ck_write(mut_fd, out_buf3, len + cut_len, mut_fn);
                    free(mut_fn);
                    close(mut_fd);
                    mut_cnt = mut_cnt + 1;
                } 
            }
        }
        
        /* save mutations that find new edges. */
        ret = has_new_bits(virgin_bits);
        if(ret == 2){
            char* mut_fn = alloc_printf("%s/id_%d_%06d_cov", "vari_seeds",round_cnt, mut_cnt);
            int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
            ck_write(mut_fd, out_buf3, len+cut_len, mut_fn);
            free(mut_fn);
            close(mut_fd);
            mut_cnt = mut_cnt + 1;
        }
        else if(ret == 1){
            char* mut_fn = alloc_printf("%s/id_%d_%06d", "vari_seeds",round_cnt, mut_cnt);
            int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
            ck_write(mut_fd, out_buf3, len+cut_len, mut_fn);
            free(mut_fn);
            close(mut_fd);
            mut_cnt = mut_cnt + 1;
        }
    }
}

/* only pop up the slow mutation when NEUZZ starts to stall */
void gen_mutate_slow(){
    int tmout_cnt = 0;
    
    /* flip interesting locations within 14 iterations */
    for(int iter=0 ;iter<13; iter=iter+1){
        memcpy(out_buf1, out_buf, len);        
        memcpy(out_buf2, out_buf, len);        
        
        /* find mutation range for every iteration */
        int low_index = num_index[iter];
        int up_index = num_index[iter+1];
        u8 up_step = 0;
        u8 low_step = 0;
        for(int index=low_index; index<up_index; index=index+1){
            int cur_up_step = 0;
            int cur_low_step = 0;
            if(sign[index] == 1){
                cur_up_step = (255 - (u8)out_buf[loc[index]]);
                if(cur_up_step > up_step)
                    up_step = cur_up_step;
                cur_low_step = (u8)(out_buf[loc[index]]);
                if(cur_low_step > low_step)
                    low_step = cur_low_step;
            }
            else{
                cur_up_step = (u8)out_buf[loc[index]];
                if(cur_up_step > up_step)
                    up_step = cur_up_step;
                cur_low_step = (255 - (u8)out_buf[loc[index]]);
                if(cur_low_step > low_step)
                    low_step = cur_low_step;
            }
        }
        
        /* up direction mutation(up to 255) */
        for(int step=0;step<up_step;step=step+1){
            int mut_val;
            for(int index=low_index; index<up_index; index=index+1){
                mut_val = ((u8)out_buf1[loc[index]] + sign[index]);
                if(mut_val < 0)
                    out_buf1[loc[index]] = 0;
                else if (mut_val > 255)
                    out_buf1[loc[index]] = 255;
                else
                    out_buf1[loc[index]] = mut_val;
            }

            write_to_testcase(out_buf1, len);    
            int fault = run_target(exec_tmout); 
            if (fault != 0){
                if(fault == FAULT_CRASH){
                    char* mut_fn = alloc_printf("%s/crash_%d_%06d", "./crashes",round_cnt, mut_cnt);
                    int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
                    ck_write(mut_fd, out_buf1, len, mut_fn);
                    free(mut_fn);
                    close(mut_fd);
                    mut_cnt = mut_cnt + 1;
                }
                else if((fault = FAULT_TMOUT) && (tmout_cnt < 20)){
                    tmout_cnt = tmout_cnt + 1;
                    fault = run_target(1000); 
                    if(fault == FAULT_CRASH){
                        char* mut_fn = alloc_printf("%s/crash_%d_%06d", "./crashes",round_cnt, mut_cnt);
                        int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
                        ck_write(mut_fd, out_buf1, len, mut_fn);
                        free(mut_fn);
                        close(mut_fd);
                        mut_cnt = mut_cnt + 1;
                    } 
                }
            }
            
            /* save mutations that find new edges. */
            int ret = has_new_bits(virgin_bits);
            if(ret == 2){
                char* mut_fn = alloc_printf("%s/id_%d_%d_%06d_cov", out_dir, round_cnt, iter, mut_cnt);
                int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
                ck_write(mut_fd, out_buf1, len, mut_fn);
                free(mut_fn);
                close(mut_fd);
                mut_cnt = mut_cnt + 1;
            }
            if(ret == 1){
                char* mut_fn = alloc_printf("%s/id_%d_%d_%06d", out_dir, round_cnt, iter, mut_cnt);
                int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
                ck_write(mut_fd, out_buf1, len, mut_fn);
                free(mut_fn);
                close(mut_fd);
                mut_cnt = mut_cnt + 1;
            }
            
        }
        
        /* low direction mutation(up to 255) */
        for(int step=0;step<low_step;step=step+1){
            for(int index=low_index; index<up_index;index=index+1){
                int mut_val = ((u8)out_buf2[loc[index]] - sign[index]);
                if(mut_val < 0)
                    out_buf2[loc[index]] = 0;
                else if (mut_val > 255)
                    out_buf2[loc[index]] = 255;
                else
                    out_buf2[loc[index]] = mut_val;
            }
            
            write_to_testcase(out_buf2, len);    
            int fault = run_target(exec_tmout); 
            if (fault != 0){
                if(fault == FAULT_CRASH){
                    char* mut_fn = alloc_printf("%s/crash_%d_%06d", "./crashes",round_cnt, mut_cnt);
                    int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
                    ck_write(mut_fd, out_buf2, len, mut_fn);
                    free(mut_fn);
                    close(mut_fd);
                    mut_cnt = mut_cnt + 1;
                }
                else if((fault = FAULT_TMOUT) && (tmout_cnt < 20)){
                    tmout_cnt = tmout_cnt + 1;
                    fault = run_target(1000); 
                    if(fault == FAULT_CRASH){
                        char* mut_fn = alloc_printf("%s/crash_%d_%06d", "./crashes",round_cnt, mut_cnt);
                        int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
                        ck_write(mut_fd, out_buf2, len, mut_fn);
                        free(mut_fn);
                        close(mut_fd);
                        mut_cnt = mut_cnt + 1;
                    } 
                }
            }
            
            /* save mutations that find new edges. */
            int ret = has_new_bits(virgin_bits);
            if(ret == 2){
                char* mut_fn = alloc_printf("%s/id_%d_%d_%06d_cov", out_dir, round_cnt, iter, mut_cnt);
                int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
                ck_write(mut_fd, out_buf2, len, mut_fn);
                close(mut_fd);
                free(mut_fn);
                mut_cnt = mut_cnt + 1;
            }
            if(ret == 1){
                char* mut_fn = alloc_printf("%s/id_%d_%d_%06d", out_dir, round_cnt, iter, mut_cnt);
                int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
                ck_write(mut_fd, out_buf2, len, mut_fn);
                close(mut_fd);
                free(mut_fn);
                mut_cnt = mut_cnt + 1;
            }
            
        }
    }
    
    /* more random insertion/deletion than normal round */
    int cut_len = 0;
    int del_loc = 0;
    int rand_loc = 0;
    for(int del_count=0; del_count < 4096;del_count= del_count+1){
        del_loc = loc[del_count];
        if ((len- del_loc) <= 2)
            continue;
        cut_len = choose_block_len(len-1-del_loc);
        
        /* random deletion at a critical offset */
        memcpy(out_buf1, out_buf,del_loc);
        memcpy(out_buf1+del_loc, out_buf+del_loc+cut_len, len-del_loc-cut_len);
        
        write_to_testcase(out_buf1, len-cut_len);    
        
        int fault = run_target(exec_tmout); 
        if (fault != 0){
            if(fault == FAULT_CRASH){
                char* mut_fn = alloc_printf("%s/crash_%d_%06d", "./crashes",round_cnt, mut_cnt);
                int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
                ck_write(mut_fd, out_buf1, len-cut_len, mut_fn);
                free(mut_fn);
                close(mut_fd);
                mut_cnt = mut_cnt + 1;
            }
            else if((fault = FAULT_TMOUT) && (tmout_cnt < 20)){
                tmout_cnt = tmout_cnt + 1;
                fault = run_target(1000); 
                if(fault == FAULT_CRASH){
                    char* mut_fn = alloc_printf("%s/crash_%d_%06d", "./crashes",round_cnt, mut_cnt);
                    int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
                    ck_write(mut_fd, out_buf1, len - cut_len, mut_fn);
                    free(mut_fn);
                    close(mut_fd);
                    mut_cnt = mut_cnt + 1;
                } 
            }
        }
                 
        /* save mutations that find new edges. */ 
        int ret = has_new_bits(virgin_bits);
        if(ret==2){
            char* mut_fn = alloc_printf("%s/id_%d_%06d_cov", out_dir,round_cnt, mut_cnt);
            int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
            ck_write(mut_fd, out_buf1, len-cut_len, mut_fn);
            free(mut_fn);
            close(mut_fd);
            mut_cnt = mut_cnt + 1;
        }
        else if(ret==1){
            char* mut_fn = alloc_printf("%s/id_%d_%06d", out_dir,round_cnt, mut_cnt);
            int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
            ck_write(mut_fd, out_buf1, len-cut_len, mut_fn);
            free(mut_fn);
            close(mut_fd);
            mut_cnt = mut_cnt + 1;
        }

        cut_len = choose_block_len(len-1);
        rand_loc = (random()%cut_len);
        
        /* random insertion at a critical offset */
        memcpy(out_buf3, out_buf, del_loc);
        memcpy(out_buf3+del_loc, out_buf+rand_loc, cut_len);
        memcpy(out_buf3+del_loc+cut_len, out_buf+del_loc, len-del_loc);
        
        write_to_testcase(out_buf3, len+cut_len);    
        
        fault = run_target(exec_tmout); 
        if (fault != 0){
            if(fault == FAULT_CRASH){
                char* mut_fn = alloc_printf("%s/crash_%d_%06d", "./crashes",round_cnt, mut_cnt);
                int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
                ck_write(mut_fd, out_buf3, len+cut_len, mut_fn);
                free(mut_fn);
                close(mut_fd);
                mut_cnt = mut_cnt + 1;
            }
            else if((fault = FAULT_TMOUT) && (tmout_cnt < 20)){
                tmout_cnt = tmout_cnt + 1;
                fault = run_target(1000); 
                if(fault == FAULT_CRASH){
                    char* mut_fn = alloc_printf("%s/crash_%d_%06d", "./crashes",round_cnt, mut_cnt);
                    int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
                    ck_write(mut_fd, out_buf3, len + cut_len, mut_fn);
                    free(mut_fn);
                    close(mut_fd);
                    mut_cnt = mut_cnt + 1;
                } 
            }
        }
        
        /* save mutations that find new edges. */
        ret = has_new_bits(virgin_bits);
        if(ret == 2){
            char* mut_fn = alloc_printf("%s/id_%d_%06d_cov", "vari_seeds",round_cnt, mut_cnt);
            int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
            ck_write(mut_fd, out_buf3, len+cut_len, mut_fn);
            free(mut_fn);
            close(mut_fd);
            mut_cnt = mut_cnt + 1;
        }
        else if(ret == 1){
            char* mut_fn = alloc_printf("%s/id_%d_%06d", "vari_seeds",round_cnt, mut_cnt);
            int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
            ck_write(mut_fd, out_buf3, len+cut_len, mut_fn);
            free(mut_fn);
            close(mut_fd);
            mut_cnt = mut_cnt + 1;
        }
    }
}

/* dry run the seeds at dir, when stage == 1, save interesting seeds to out_dir; when stage == 2, compute the average exec time */
void dry_run(char* dir, int stage){
    DIR *dp;
    struct dirent *entry;
    struct stat statbuf;
    if((dp = opendir(dir)) == NULL) {
        fprintf(stderr,"cannot open directory: %s\n", dir);
        return;
    }
    if(chdir(dir)== -1)
        perror("chdir failed\n");
    int cnt = 0;
    u64 start_us, stop_us;
    while((entry = readdir(dp)) != NULL) { 
        if(stat(entry->d_name,&statbuf) == -1)
            continue;
        if(S_ISREG(statbuf.st_mode)) {
            char * tmp = NULL;
            tmp = strstr(entry->d_name,".");
            if(tmp != entry->d_name){
                int fd_tmp = open(entry->d_name, O_RDONLY);
                if(fd_tmp == -1)
                    perror("open failed");
                int file_len = statbuf.st_size;
                memset(out_buf1, 0, len);
                ck_read(fd_tmp, out_buf1,file_len, entry->d_name);
                
                start_us = get_cur_time_us();
                write_to_testcase(out_buf1, file_len);
                int fault = run_target(exec_tmout); 
                if (fault != 0){
                    if(fault == FAULT_CRASH){
                        char* mut_fn = alloc_printf("%s/crash_%d_%06d", "./crashes",round_cnt, mut_cnt);
                        int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
                        ck_write(mut_fd, out_buf1, file_len, mut_fn);
                        free(mut_fn);
                        close(mut_fd);
                        mut_cnt = mut_cnt + 1;
                    }
                    else if(fault = FAULT_TMOUT){
                        fault = run_target(1000); 
                        if(fault == FAULT_CRASH){
                            char* mut_fn = alloc_printf("%s/crash_%d_%06d", "./crashes",round_cnt, mut_cnt);
                            int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
                            ck_write(mut_fd, out_buf1, file_len, mut_fn);
                            free(mut_fn);
                            close(mut_fd);
                            mut_cnt = mut_cnt + 1;
                        } 
                    }
                }
                
                int ret = has_new_bits(virgin_bits);
                if (ret!=0){
                    if(stage == 1){
                        char* mut_fn = alloc_printf("../%s/id_%d_%06d", out_dir,round_cnt, mut_cnt);
                        int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
                        ck_write(mut_fd, out_buf1, len, mut_fn);
                        free(mut_fn);
                        close(mut_fd);
                        mut_cnt = mut_cnt + 1;
                    }
                }
                
                stop_us = get_cur_time_us();
                total_cal_us = total_cal_us - start_us + stop_us;
                cnt = cnt + 1;
                close(fd_tmp);
            }
        }
    }
    if(chdir("..") == -1)
        perror("chdir failed\n");
    closedir(dp);
    
    /* estimate the average exec time at the beginning*/
    if(stage ==2 ){
        u64 avg_us = (u64)(total_cal_us / cnt);
        if (avg_us > 50000) exec_tmout = avg_us * 2 / 1000;
        else if (avg_us > 10000) exec_tmout = avg_us * 3 / 1000;
        else exec_tmout = avg_us * 5 / 1000;

        exec_tmout = (exec_tmout + 20) / 20 * 20;
        exec_tmout =  exec_tmout;
        printf("avg %d time out %d cnt %d sum %lld \n.",(int)avg_us, exec_tmout, cnt,total_cal_us);
    }

    printf("dry run %ld edge coverage %d.\n", total_execs,count_non_255_bytes(virgin_bits));
    return;
}


void copy_file(char* src, char* dst){
    FILE *fptr1, *fptr2;
    int c;
    fptr1 = fopen(src, "r");
    if (fptr1 == NULL)
    {
        printf("Cannot open file %s \n", src);
        exit(0);
    }

    fptr2 = fopen(dst, "w");
    if (fptr2 == NULL)
    {
        printf("Cannot open file %s \n", dst);
        exit(0);
    }

    c = fgetc(fptr1);
    while (c != EOF)
    {
        fputc(c, fptr2);
        c = fgetc(fptr1);
    }

    fclose(fptr1);
    fclose(fptr2);
    return;
}

/* copy seeds from in_idr to out_dir */
void copy_seeds(char * in_dir, char * out_dir){
    struct dirent *de;
    DIR *dp;
    if((dp = opendir(in_dir)) == NULL) {
        fprintf(stderr,"cannot open directory: %s\n", in_dir);
        return;
    }
    char src[128], dst[128];
    while((de = readdir(dp)) != NULL){ 
         if(strcmp(".",de->d_name) == 0 || strcmp("..",de->d_name) == 0)
            continue;
        sprintf(src, "%s/%s", in_dir, de->d_name);
        sprintf(dst, "%s/%s", out_dir, de->d_name);
        copy_file(src, dst);
    }
    closedir(dp);
    return ;
}

/* parse the gradient to guide fuzzing */
void fuzz_lop(char * grad_file, int sock){
    dry_run("./splice_seeds/", 1); 
    copy_file("gradient_info_p", grad_file);
    FILE *stream = fopen(grad_file, "r");
    char *line = NULL;
    size_t llen = 0;
    ssize_t nread;
    if (stream == NULL) {
        perror("fopen");
        exit(EXIT_FAILURE);
    }
    int line_cnt=0;
    
    int retrain_interval = 1000;
    if(round_cnt == 0)
        retrain_interval = 750;
    
    while ((nread = getline(&line, &llen, stream)) != -1) {        
        line_cnt = line_cnt+1;
        
        /* send message to python module */
        if(line_cnt == retrain_interval){
            round_cnt++;
            now = count_non_255_bytes(virgin_bits);
            edge_gain = now - old;
            old = now;
            if((edge_gain > 30) || (fast == 0)){
                send(sock,"train", 5,0);
                fast = 1;
                printf("fast stage\n");
            }
            else{
                send(sock,"sloww",5,0);
                fast = 0;
                printf("slow stage\n");
            }
        }
         
        /* parse gradient info */
        char* loc_str = strtok(line,"|");
        char* sign_str = strtok(NULL,"|");
        char* fn = strtok(strtok(NULL,"|"),"\n"); 
        parse_array(loc_str,loc);
        parse_array(sign_str,sign);
        
        /* print edge coverage per 10 files*/
        if((line_cnt % 10) == 0){ 
            printf("$$$$&&&& fuzz %s line_cnt %d\n",fn, line_cnt);
            printf("edge num %d\n",count_non_255_bytes(virgin_bits));
            fflush(stdout);
        }

        /* read seed into mem */
        int fn_fd = open(fn,O_RDONLY);
        if(fn_fd == -1){
            perror("open failed");
            exit(0);
        }
        struct stat st;
        int ret = fstat(fn_fd,&st);
        int file_len = st.st_size;
        memset(out_buf1,0,len);
        memset(out_buf2,0,len);
        memset(out_buf,0, len);
        memset(out_buf3,0, 20000);
        ck_read(fn_fd, out_buf, file_len, fn);
        
        /* generate mutation */
        if(stage_num == 1)
            gen_mutate();
        else
            gen_mutate_slow();
        close(fn_fd);
    }
    stage_num = fast;
    free(line);
    fclose(stream);
}

/* connect to python NN module, then read the gradient file to guide fuzzing */
void start_fuzz(int f_len){
    
    /* connect to python module */    
    struct sockaddr_in address;
    int sock = 0;
    struct sockaddr_in serv_addr;
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0){
        perror("Socket creation error");
        exit(0);
    }
    memset(&serv_addr, '0', sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    if(inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr)<=0){
        perror("Invalid address/ Address not supported");
        exit(0);
    }
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0){
        perror("Connection Failed");
        exit(0);
    }
    
    /* set up buffer */
    out_buf = malloc(10000);
    if(!out_buf)
        perror("malloc failed");
    out_buf1 = malloc(10000);
    if(!out_buf1)
        perror("malloc failed");
    out_buf2 = malloc(10000);
    if(!out_buf2)
        perror("malloc failed");
    out_buf3 = malloc(20000);
    if(!out_buf3)
        perror("malloc failed");
    
    len = f_len;
    /* dry run seeds*/
    dry_run(out_dir, 2);
    
    /* start fuzz */
    char buf[16];
    while(1){
        if(read(sock , buf, 5)== -1)
            perror("received failed\n");
        fuzz_lop("gradient_info", sock);
        printf("receive\n");
    }
    return;
}

/* function for local debugging, replace it with start_fuzz */
void start_fuzz_test(int f_len){
    int sock = 0;
    
    /* set up buffer */
    out_buf = malloc(10000);
    if(!out_buf)
        perror("malloc failed");
    out_buf1 = malloc(10000);
    if(!out_buf1)
        perror("malloc failed");
    out_buf2 = malloc(10000);
    if(!out_buf2)
        perror("malloc failed");
    out_buf3 = malloc(20000);
    if(!out_buf3)
        perror("malloc failed");
    
    len = f_len;
    /* dry run */
    dry_run(out_dir, 0);
    /* fuzz */
        fuzz_lop("gradient_info", sock);
    return;
}


void main(int argc, char*argv[]){
    int opt;
    while ((opt = getopt(argc, argv, "+i:o:l:")) > 0)

    switch (opt) {

      case 'i': /* input dir */

        if (in_dir) perror("Multiple -i options not supported");
        in_dir = optarg;

        break;

      case 'o': /* output dir */

        if (out_dir) perror("Multiple -o options not supported");
        out_dir = optarg;
        break;
      
      case 'l': /* file len */
         sscanf (optarg,"%ld",&len);
         /* change num_index and havoc_blk_* according to file len */
         if(len > 7000)
         {
             num_index[13] = (len - 1);
             havoc_blk_large = (len - 1);
         }
         else if (len > 4000)
         {
             num_index[13] = (len - 1);
             num_index[12] = 3072;
             havoc_blk_large = (len - 1);
             havoc_blk_medium = 2048; 
             havoc_blk_small = 1024;
         }
         printf("num_index %d %d small %d medium %d large %d\n", num_index[12], num_index[13], havoc_blk_small, havoc_blk_medium, havoc_blk_large);
         printf("mutation len: %ld\n", len);
         break;
      
    default:
        printf("no manual...");
    }
    
    setup_signal_handlers();
    check_cpu_governor();
    get_core_count();
    bind_to_free_cpu();
    setup_shm();
    init_count_class16();
    setup_dirs_fds();
    if (!out_file) setup_stdio_file();
    detect_file_args(argv + optind + 1);
    setup_targetpath(argv[optind]);
    
    copy_seeds(in_dir, out_dir);
    init_forkserver(argv+optind);
   
    start_fuzz(len);   
    printf("total execs %ld edge coverage %d.\n", total_execs, count_non_255_bytes(virgin_bits));
    return;
}

