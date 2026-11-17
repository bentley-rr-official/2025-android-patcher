// crashlog.cpp - logs WHERE the process dies (pc/lr/sp, module+RVA, bytes at pc, a stack walk) to logcat,
// then hands the signal on to whoever was installed before us (debuggerd / Unity / ART via sigchain).
//
// Compiled into libvrsupport.so (the hook lib), which is the first DT_NEEDED of libmain.so, so it is armed
// before libil2cpp/libwebrtc load. Logcat tag: CRASHLOG.  Only async-signal-safe calls inside the handler
// (open/read/write/close, prctl, raw string formatting; no malloc, no stdio, no dl_iterate_phdr).
//
// Unity installs its own signal handlers later, which could replace ours; a watcher thread re-arms ours every
// 20 ms for the first 60 s and keeps whatever it replaced as the "previous" handler to chain to.
#include <android/log.h>
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <ucontext.h>
#include <unistd.h>

#define CL_TAG "CRASHLOG"

static const int kSigs[] = {SIGILL, SIGSEGV, SIGBUS, SIGFPE, SIGABRT, SIGTRAP};
static struct sigaction g_prev[65];
static int g_pipe[2] = {-1, -1};
static volatile int g_busy = 0;
static volatile int g_events = 0;
static volatile int g_dying = 0;            // set once a synchronous fault is clearly not going to resolve
static volatile uint64_t g_last_pc = 0, g_last_fault = 0;
static volatile int g_repeat = 0;           // consecutive identical (pc, fault addr) faults
static char g_maps[1 << 21];   // bss; only touched on a crash
static size_t g_maps_n = 0;

// ---------------------------------------------------------------- tiny formatter
struct Out {
    char b[500]; int n; int prio;   // prio: FATAL for crash reports, INFO for the hang sampler
    Out(int p = ANDROID_LOG_FATAL) : n(0), prio(p) { b[0] = 0; }
    void s(const char* t) { while (*t && n < (int)sizeof(b) - 1) b[n++] = *t++; b[n] = 0; }
    void sn(const char* t, size_t l) { while (l-- && *t && n < (int)sizeof(b) - 1) b[n++] = *t++; b[n] = 0; }
    void x(uint64_t v) {
        char t[20]; int k = 0;
        do { t[k++] = "0123456789abcdef"[v & 15]; v >>= 4; } while (v);
        s("0x"); while (k) { if (n < (int)sizeof(b) - 1) b[n++] = t[--k]; } b[n] = 0;
    }
    void d(long v) {
        char t[24]; int k = 0; bool neg = v < 0; unsigned long u = neg ? -v : v;
        do { t[k++] = '0' + (u % 10); u /= 10; } while (u);
        if (neg) s("-"); while (k) { if (n < (int)sizeof(b) - 1) b[n++] = t[--k]; } b[n] = 0;
    }
    void flush() { __android_log_write(prio, CL_TAG, b); n = 0; b[0] = 0; }
};

// ---------------------------------------------------------------- safe memory read (write() to a pipe -> EFAULT)
static void drain() { char t[256]; while (g_pipe[0] >= 0 && read(g_pipe[0], t, sizeof t) > 0) {} }
static bool safe_read(uint64_t addr, void* out, size_t n) {
    if (g_pipe[1] < 0 || n > 64 || addr < 0x1000) return false;
    ssize_t w = write(g_pipe[1], (const void*)addr, n);
    if (w != (ssize_t)n) { drain(); return false; }
    return read(g_pipe[0], out, n) == (ssize_t)n;
}

// ---------------------------------------------------------------- /proc/self/maps lookup
struct Line { uint64_t s, e, off; char perms[5]; const char* path; size_t plen; };
static const char* hexp(const char* p, uint64_t* v) {
    uint64_t r = 0;
    for (;; p++) {
        char c = *p; int d;
        if (c >= '0' && c <= '9') d = c - '0'; else if (c >= 'a' && c <= 'f') d = c - 'a' + 10; else break;
        r = (r << 4) | d;
    }
    *v = r; return p;
}
static const char* next_line(const char* p, const char* end, Line& L) {
    if (p >= end) return nullptr;
    const char* q = hexp(p, &L.s); if (*q == '-') q++;
    q = hexp(q, &L.e); while (*q == ' ') q++;
    for (int i = 0; i < 4; i++) L.perms[i] = q[i] ? q[i] : '-'; L.perms[4] = 0; q += 4; while (*q == ' ') q++;
    q = hexp(q, &L.off); while (*q == ' ') q++;
    while (*q && *q != ' ' && *q != '\n') q++; while (*q == ' ') q++;   // dev
    while (*q && *q != ' ' && *q != '\n') q++; while (*q == ' ') q++;   // inode
    L.path = q; while (*q && *q != '\n') q++; L.plen = q - L.path;
    return (q < end) ? q + 1 : end;
}
static void index_lines();
static void load_maps() {
    int fd = open("/proc/self/maps", O_RDONLY | O_CLOEXEC); size_t n = 0;
    if (fd >= 0) {
        while (n < sizeof(g_maps) - 1) { ssize_t r = read(fd, g_maps + n, sizeof(g_maps) - 1 - n); if (r <= 0) break; n += r; }
        close(fd);
    }
    g_maps[n] = 0; g_maps_n = n; index_lines();
}
struct Hit { bool ok; uint64_t base; char perms[5]; const char* path; size_t plen; const char* name; };
static const char* g_lines[40000]; static int g_nlines = 0;
static void index_lines() {
    const char* p = g_maps; const char* end = g_maps + g_maps_n; Line L; g_nlines = 0;
    while (g_nlines < 40000) { const char* q = p; if (!(p = next_line(p, end, L))) break; g_lines[g_nlines++] = q; }
}
static bool lookup(uint64_t a, Hit& h) {
    h.ok = false; h.base = 0; h.perms[0] = 0; h.path = ""; h.plen = 0; h.name = "";
    const char* end = g_maps + g_maps_n; Line L; int idx = -1;
    for (int i = 0; i < g_nlines; i++) {
        next_line(g_lines[i], end, L);
        if (a >= L.s && a < L.e) { memcpy(h.perms, L.perms, 5); h.path = L.path; h.plen = L.plen; h.ok = true; h.base = L.s; idx = i; break; }
    }
    if (!h.ok) return false;
    if (h.plen == 0 || h.path[0] != '/') return true;                       // anon / [stack] etc
    // Base = the offset-0 mapping of THIS load of the file: walk backwards over the adjacent lines of the same
    // path (or anonymous .bss/gap lines). Taking the lowest mapping of the path anywhere is wrong when the file
    // is also mapped elsewhere (that gave bogus RVAs like libil2cpp+0x1a31e8578 in run6).
    uint64_t base = h.base;
    for (int i = idx, steps = 0; i >= 0 && steps < 64; i--, steps++) {
        next_line(g_lines[i], end, L);
        bool same = (L.plen == h.plen && memcmp(L.path, h.path, h.plen) == 0);
        if (!same && L.plen != 0) break;
        if (same) { base = L.s; if (L.off == 0) break; }
    }
    h.base = base;
    const char* nm = h.path; for (size_t i = 0; i < h.plen; i++) if (h.path[i] == '/') nm = h.path + i + 1;
    h.name = nm; return true;
}
static void put_addr(Out& o, uint64_t a) {
    Hit h; o.x(a);
    if (lookup(a, h) && h.name[0]) { o.s(" ("); o.sn(h.name, h.plen - (h.name - h.path)); o.s("+"); o.x(a - h.base); o.s(" "); o.s(h.perms); o.s(")"); }
    else if (h.ok) { o.s(" (anon "); o.s(h.perms); o.s(")"); }
    else o.s(" (unmapped)");
}

// ---------------------------------------------------------------- report
struct Regs { uint64_t pc, sp, fp, lr, fault; uint64_t x[31]; };
static void get_regs(void* ctx, Regs& r) {
    memset(&r, 0, sizeof r);
    ucontext_t* uc = (ucontext_t*)ctx; if (!uc) return;
#if defined(__aarch64__)
    r.pc = uc->uc_mcontext.pc; r.sp = uc->uc_mcontext.sp; r.fault = uc->uc_mcontext.fault_address;
    for (int i = 0; i < 31; i++) r.x[i] = uc->uc_mcontext.regs[i];
    r.fp = r.x[29]; r.lr = r.x[30];
#elif defined(__x86_64__)   // host self-test only
    r.pc = uc->uc_mcontext.gregs[REG_RIP]; r.sp = uc->uc_mcontext.gregs[REG_RSP]; r.fp = uc->uc_mcontext.gregs[REG_RBP];
#endif
}

static void report(int sig, siginfo_t* si, void* ctx) {
    load_maps();
    Regs r; get_regs(ctx, r);
    char tn[20] = {0}; prctl(PR_GET_NAME, (unsigned long)tn, 0, 0, 0);
    long tid = syscall(SYS_gettid);
    Out o;
    o.s("=== CRASH sig="); o.d(sig); o.s(" code="); o.d(si ? si->si_code : 0);
    o.s(" tid="); o.d(tid); o.s(" thread='"); o.s(tn); o.s("' si_addr="); o.x(si ? (uint64_t)si->si_addr : 0);
    o.s(" fault="); o.x(r.fault); o.flush();
    o.s("pc  = "); put_addr(o, r.pc); o.flush();
    o.s("lr  = "); put_addr(o, r.lr); o.flush();
    o.s("sp  = "); o.x(r.sp); o.s("  fp = "); o.x(r.fp); o.flush();
    // 32 bytes at pc: all-ones / high-entropy garbage means the code is still PairIP-encrypted
    uint8_t cb[32];
    if (safe_read(r.pc, cb, 32)) {
        o.s("code@pc:");
        for (int i = 0; i < 32; i += 4) { uint32_t w; memcpy(&w, cb + i, 4); o.s(" "); o.x(w); }
        o.flush();
    } else { o.s("code@pc: unreadable"); o.flush(); }
    for (int i = 0; i < 31; i += 4) {
        o.s("x"); o.d(i); o.s("=");
        for (int k = i; k < i + 4 && k < 31; k++) { o.x(r.x[k]); o.s(k + 1 < i + 4 && k + 1 < 31 ? " " : ""); }
        o.flush();
    }
    // frame-pointer walk
    uint64_t fp = r.fp; int fr = 0;
    for (; fr < 20; fr++) {
        uint64_t rec[2]; if (!safe_read(fp, rec, 16)) break;
        o.s("fp#"); o.d(fr); o.s(" "); put_addr(o, rec[1]); o.flush();
        if (rec[0] <= fp) break; fp = rec[0];
    }
    // heuristic: code addresses sitting on the stack (works when the code has no frame pointers)
    int hits = 0;
    for (int i = 0; i < 768 && hits < 24; i += 8) {
        uint64_t w[8]; if (!safe_read(r.sp + (uint64_t)i * 8, w, 64)) break;
        for (int k = 0; k < 8 && hits < 24; k++) {
            uint64_t v = w[k]; if (v < 0x7000000000ULL || v > 0x7fffffffffULL || (v & 3)) continue;
            Hit h; if (!lookup(v, h) || !h.name[0] || h.perms[2] != 'x') continue;
            o.s("stk+"); o.x((uint64_t)(i + k) * 8); o.s(" "); put_addr(o, v); o.flush(); hits++;
        }
    }
    o.s("=== end of CRASH report"); o.flush();
}

static void chain(int sig, siginfo_t* si, void* ctx);
static void die_default(int sig) {
    // restore the default action for every signal we own so the re-executed faulting instruction kills the
    // process instead of looping, and so the watcher below stops re-arming us
    g_dying = 1;
    struct sigaction d; memset(&d, 0, sizeof d); d.sa_handler = SIG_DFL;
    for (int s : kSigs) sigaction(s, &d, nullptr);
    (void)sig;
}
static void handler(int sig, siginfo_t* si, void* ctx) {
    if (g_dying) { die_default(sig); return; }
    // A fault that comes straight back at the same pc/address after the previous handler "handled" it is a
    // crash that someone forwards but never terminates on (run9: 1.58M "Forwarding signal 11" lines; run12: UnityMain
    // pegged at 100% for 40 s). Allow a few repeats for genuinely benign faults, then let it kill us.
    uint64_t pc = 0, fa = 0;
#if defined(__aarch64__)
    if (ctx) { ucontext_t* uc = (ucontext_t*)ctx; pc = uc->uc_mcontext.pc; fa = uc->uc_mcontext.fault_address; }
#endif
    if (sig == SIGSEGV || sig == SIGBUS || sig == SIGILL) {
        if (pc && pc == g_last_pc && fa == g_last_fault) g_repeat++;
        else { g_last_pc = pc; g_last_fault = fa; g_repeat = 0; }
    }
    if (__sync_bool_compare_and_swap(&g_busy, 0, 1)) {
        if (__sync_fetch_and_add(&g_events, 1) < 4) report(sig, si, ctx);   // cap: a benign handled fault may repeat
        g_busy = 0;
    }
    if (g_repeat >= 8) { die_default(sig); return; }                       // same fault 9x in a row: give up and die
    chain(sig, si, ctx);
}
static void chain(int sig, siginfo_t* si, void* ctx) {
    struct sigaction* o = &g_prev[sig];
    if ((o->sa_flags & SA_SIGINFO) && o->sa_sigaction && o->sa_sigaction != handler) { o->sa_sigaction(sig, si, ctx); return; }
    if (!(o->sa_flags & SA_SIGINFO) && o->sa_handler != SIG_DFL && o->sa_handler != SIG_IGN && o->sa_handler) { o->sa_handler(sig); return; }
    struct sigaction d; memset(&d, 0, sizeof d); d.sa_handler = SIG_DFL; sigaction(sig, &d, nullptr);   // re-fault -> default kill
}

static void install(int sig) {
    struct sigaction cur;
    if (sigaction(sig, nullptr, &cur) == 0 && (cur.sa_flags & SA_SIGINFO) && cur.sa_sigaction == handler) return;
    struct sigaction sa; memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = handler; sigemptyset(&sa.sa_mask); sa.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_NODEFER;
    struct sigaction old; memset(&old, 0, sizeof old);
    if (sigaction(sig, &sa, &old) == 0) g_prev[sig] = old;
}

static void* watcher(void*) {
    prctl(PR_SET_NAME, (unsigned long)"crashlog", 0, 0, 0);
    for (int i = 0; i < 3000 && !g_dying; i++) { for (int s : kSigs) install(s); usleep(20000); }
    return nullptr;
}

// ---------------------------------------------------------------- hang sampler
// For "black screen, no crash" cases: N seconds after load (default 25 and 45; env CRASHLOG_SAMPLE_S="a,b" overrides,
// CRASHLOG_SAMPLE_S=0 turns it off) a helper thread walks /proc/self/task, logs each thread's name / state / CPU ticks, then
// interrupts it with a realtime signal whose handler logs pc, lr and code addresses found on that thread's stack.
// Compare the two rounds: utime/stime growing = busy loop, state S with the same pc = blocked. Logcat tag CRASHLOG, "SAMPLE".
static const int kSampleSig = SIGRTMIN + 3;
static volatile int g_samp_seq = 0;
static void sample_handler(int, siginfo_t*, void* ctx) {
    Regs r; get_regs(ctx, r);
    Out o(ANDROID_LOG_INFO); o.s("  pc="); put_addr(o, r.pc); o.flush();
    o.s("  lr="); put_addr(o, r.lr); o.flush();
    int hits = 0;
    for (int i = 0; i < 256 && hits < 8; i += 8) {
        uint64_t w[8]; if (!safe_read(r.sp + (uint64_t)i * 8, w, 64)) break;
        for (int k = 0; k < 8 && hits < 8; k++) {
            uint64_t v = w[k]; if (v < 0x7000000000ULL || v > 0x7fffffffffULL || (v & 3)) continue;
            Hit h; if (!lookup(v, h) || !h.name[0] || h.perms[2] != 'x') continue;
            o.s("  stk+"); o.x((uint64_t)(i + k) * 8); o.s(" "); put_addr(o, v); o.flush(); hits++;
        }
    }
    __sync_fetch_and_add(&g_samp_seq, 1);
}
static void sample_all(int round) {
    load_maps();
    struct sigaction sa; memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = sample_handler; sigemptyset(&sa.sa_mask); sa.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_RESTART;
    sigaction(kSampleSig, &sa, nullptr);
    long self = syscall(SYS_gettid); int pid = getpid();
    __android_log_print(ANDROID_LOG_INFO, CL_TAG, "SAMPLE round %d begin (pid %d)", round, pid);
    DIR* d = opendir("/proc/self/task"); if (!d) return;
    int n = 0; struct dirent* e;
    while ((e = readdir(d)) && n < 200) {
        int tid = atoi(e->d_name); if (tid <= 0 || tid == self) continue;
        char path[64], buf[600]; snprintf(path, sizeof path, "/proc/self/task/%d/stat", tid);
        int fd = open(path, O_RDONLY | O_CLOEXEC); if (fd < 0) continue;
        ssize_t l = read(fd, buf, sizeof buf - 1); close(fd); if (l <= 0) continue; buf[l] = 0;
        char* lp = strchr(buf, '('); char* rp = strrchr(buf, ')'); if (!lp || !rp) continue;
        *rp = 0; char st = '?'; unsigned long ut = 0, stm = 0;
        sscanf(rp + 2, "%c %*d %*d %*d %*d %*d %*u %*lu %*lu %*lu %*lu %lu %lu", &st, &ut, &stm);
        __android_log_print(ANDROID_LOG_INFO, CL_TAG, "T tid=%d '%s' state=%c utime=%lu stime=%lu", tid, lp + 1, st, ut, stm);
        int before = g_samp_seq; syscall(SYS_tgkill, pid, tid, kSampleSig);
        for (int i = 0; i < 60 && g_samp_seq == before; i++) usleep(2000);
        n++;
    }
    closedir(d);
    __android_log_print(ANDROID_LOG_INFO, CL_TAG, "SAMPLE round %d end (%d threads)", round, n);
}
static void* sampler(void*) {
    prctl(PR_SET_NAME, (unsigned long)"crashlog-smp", 0, 0, 0);
    const char* env = getenv("CRASHLOG_SAMPLE_S"); char spec[64]; snprintf(spec, sizeof spec, "%s", env ? env : "25,45");
    int prev = 0, round = 0;
    for (char* tok = strtok(spec, ","); tok; tok = strtok(nullptr, ",")) {
        int t = atoi(tok); if (t <= 0) return nullptr;
        if (t > prev) sleep(t - prev); prev = t; sample_all(++round);
    }
    return nullptr;
}

__attribute__((constructor(101))) static void crashlog_init() {
    if (pipe2(g_pipe, O_NONBLOCK | O_CLOEXEC) != 0) g_pipe[0] = g_pipe[1] = -1;
    for (int s : kSigs) install(s);
    __android_log_print(ANDROID_LOG_INFO, CL_TAG, "armed (SIGILL/SEGV/BUS/FPE/ABRT/TRAP); fatal reports log to this tag");
    pthread_t t; if (pthread_create(&t, nullptr, watcher, nullptr) == 0) pthread_detach(t);
    pthread_t t2; if (pthread_create(&t2, nullptr, sampler, nullptr) == 0) pthread_detach(t2);
}
