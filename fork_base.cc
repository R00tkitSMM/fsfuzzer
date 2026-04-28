// Build:
//   protoc --cpp_out=. fs_session.proto
//   clang++ -std=c++17 -O2 -fsanitize=fuzzer,address \
//     -I. fuzz_fs.cc fs_session.pb.cc \
//     -L"$(brew --prefix)/lib" -lprotobuf-mutator-libfuzzer -lprotobuf-mutator
//     \
//     $(pkg-config --cflags --libs protobuf) \
//     -o fuzz_fs
//
// Run (examples):
//   ./fuzz_fs corpus -timeout=5 -rss_limit_mb=4096
//   ./fuzz_fs saved_input.pb               # with DEFINE_BINARY_PROTO_FUZZER

#define FSFUZZ_AVOID_FSYNC 1 // define to skip potentially slow fsync

#include <aio.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <iomanip>
#include <mutex>
#include <memory>
#include <poll.h>
#include <dirent.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/vfs.h>
#include <sys/xattr.h>
#include <thread>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>
#include <linux/fs.h>

#include <vector>

#include "fuzz_filesys.pb.h"
#include "src/libfuzzer/libfuzzer_macro.h"
#include <fuzzer/FuzzedDataProvider.h>

// Linux libFuzzer auto-scans every byte of any ELF section named
// __libfuzzer_extra_counters and uses it as additional coverage signal — see
// compiler-rt's FuzzerExtraCounters.cpp, which iterates from
// __start___libfuzzer_extra_counters to __stop___libfuzzer_extra_counters
// (synthesized by the linker for any section with that name). So just dropping
// our kcov-derived counters into that section is enough; no
// __sanitizer_cov_8bit_counters_init() call is required.
extern "C" __attribute__((section("__libfuzzer_extra_counters"), used,
                          aligned(64)))
unsigned char libfuzzer_coverage[32 << 10] = {};

#include <csignal> // or <signal.h>

static void ignore_sigxfsz() {

  struct sigaction sa;
  sa.sa_handler = SIG_IGN;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;

  sigaction(SIGXFSZ, &sa, nullptr);
}

static void ignore_sigpipe() {
  struct sigaction sa;
  sa.sa_handler = SIG_IGN;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;

  sigaction(SIGPIPE, &sa, nullptr);
}

static void ignore_async_aio_signals() {
  struct sigaction sa;
  sa.sa_handler = SIG_IGN;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;

  sigaction(SIGUSR1, &sa, nullptr);
  sigaction(SIGUSR2, &sa, nullptr);
}

static void ignore_all_child_signals() {
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = SIG_IGN;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;

  for (int sig = 1; sig < NSIG; ++sig) {
    if (sig == SIGKILL || sig == SIGSTOP)
      continue;
    (void)sigaction(sig, &sa, nullptr);
  }
}

static bool async_event_syscalls_enabled() {
  static const bool enabled = []() {
    const char *env = std::getenv("FSFUZZ_ENABLE_ASYNC_UNSAFE");
    if (!env || env[0] == '\0')
      return true;
    return !(env[0] == '0' && env[1] == '\0');
  }();
  return enabled;
}

// Current soft cap from RLIMIT_FSIZE; if ∞, fall back to a sane cap.
static off_t max_file_cap_bytes() {
  struct rlimit rl{};
  if (getrlimit(RLIMIT_FSIZE, &rl) == 0 && rl.rlim_cur != RLIM_INFINITY) {
    // keep a safety margin to avoid boundary signals
    if (rl.rlim_cur > 4096)
      return (off_t)(rl.rlim_cur - 4096);
    return (off_t)rl.rlim_cur;
  }
  // default cap: 8 MiB for sparse truncates/writes
  return (off_t)(8 * 1024 * 1024);
}

// Clamp offset/len so (off + len) <= cap and never negative.
static void clamp_off_len(off_t cap, off_t &off, size_t &len) {
  if (cap < 0)
    cap = 0;
  if (off < 0)
    off = 0;
  if (off > cap)
    off = cap;
  size_t maxlen = (off <= cap)
                      ? (size_t)std::min<int64_t>(
                            (int64_t)(cap - off),
                            (int64_t)std::numeric_limits<int32_t>::max())
                      : 0;
  if (len > maxlen)
    len = maxlen;
}

static size_t clamp_fd_write_len(int fd, size_t len) {
  if (fd < 0 || len == 0)
    return 0;

  struct stat st{};
  if (::fstat(fd, &st) != 0)
    return len;
  if (!S_ISREG(st.st_mode))
    return len;

  off_t cur = ::lseek(fd, 0, SEEK_CUR);
  if (cur < 0)
    return 0;

  off_t cap = max_file_cap_bytes();
  clamp_off_len(cap, cur, len);
  return len;
}

static int aio_fsync_op_from_raw(uint32_t raw) {
#ifdef O_DSYNC
  return (raw & 1u) ? O_DSYNC : O_SYNC;
#else
  (void)raw;
  return O_SYNC;
#endif
}

static int lio_mode_from_raw(uint32_t raw) {
  (void)raw;
  return LIO_NOWAIT;
}

static int aio_opcode_from_raw(uint32_t raw, int fallback) {
  switch (raw % 3) {
  case 0:
    return LIO_NOP;
  case 1:
    return LIO_READ;
  case 2:
    return LIO_WRITE;
  default:
    return fallback;
  }
}

static int aio_reqprio_from_raw(int32_t raw) {
  return std::clamp(raw, -16, 16);
}

static void fill_sigevent(struct sigevent &sev, bool use_sigev, int32_t signo,
                          int32_t value) {
  memset(&sev, 0, sizeof(sev));
  // In fuzzing we keep AIO completion side-effect free: signal delivery can
  // stop LLDB, interrupt unrelated syscalls with EINTR, and generally make the
  // harness flaky without improving syscall surface coverage.
  (void)use_sigev;
  (void)signo;
  sev.sigev_notify = SIGEV_NONE;
  sev.sigev_value.sival_int = value;
}

static inline uint32_t clampu32(uint32_t v, uint32_t lo, uint32_t hi) {
  if (v < lo)
    return lo;
  if (v > hi)
    return hi;
  return v;
}
static inline uint64_t clampu64(uint64_t v, uint64_t lo, uint64_t hi) {
  if (v < lo)
    return lo;
  if (v > hi)
    return hi;
  return v;
}

static size_t mmap_len_from_raw(uint32_t raw) {
  size_t len = static_cast<size_t>(clampu32(raw, 1, 1u << 16));
  long page = sysconf(_SC_PAGESIZE);
  size_t page_size = page > 0 ? static_cast<size_t>(page) : 4096u;
  len = ((len + page_size - 1) / page_size) * page_size;
  return std::max<size_t>(len, page_size);
}

static int mmap_prot_from_mask(uint32_t raw) {
  int prot = 0;
  if (raw & (1u << 0))
    prot |= PROT_READ;
  if (raw & (1u << 1))
    prot |= PROT_WRITE;
  if (raw & (1u << 2))
    prot |= PROT_EXEC;
  return prot ? prot : PROT_READ;
}

static int mmap_flags_from_mask(uint32_t raw) {
  int flags = (raw & 1u) ? MAP_PRIVATE : MAP_SHARED;
#ifdef MAP_NOCACHE
  if (raw & (1u << 1))
    flags |= MAP_NOCACHE;
#endif
  return flags;
}

static int msync_flags_from_mask(uint32_t raw) {
  // MS_SYNC blocks until pages are durable, so we never expose it. MS_ASYNC
  // is always set so msync() schedules and returns immediately.
  int flags = 0;
#ifdef MS_INVALIDATE
  if (raw & 1u) flags |= MS_INVALIDATE;
#endif
  flags |= MS_ASYNC;
  return flags;
}

// -------- Non-blocking helpers --------
static void set_nonblock(int fd) {
  if (fd < 0)
    return;
  int cur = fcntl(fd, F_GETFL, 0);
  if (cur != -1)
    (void)fcntl(fd, F_SETFL, cur | O_NONBLOCK);
}

static bool writable_now(int fd) {
  struct pollfd p{fd, POLLOUT, 0};
  return poll(&p, 1, 0) > 0 && (p.revents & (POLLOUT | POLLERR | POLLHUP));
}
static bool readable_now(int fd) {
  struct pollfd p{fd, POLLIN, 0};
  return poll(&p, 1, 0) > 0 && (p.revents & (POLLIN | POLLERR | POLLHUP));
}

// Linux open(2) flag bitmap. OF_SYNC / OF_DSYNC / OF_RSYNC are intentionally
// dropped on the floor: setting them turns every subsequent write on the fd
// into a blocking durability barrier. O_NONBLOCK is always forced so open()
// itself never waits on a FIFO or special file.
static int flags_from_mask(uint32_t mask) {
  int oflags = 0;
  auto has = [&](int bit) { return (mask & (1u << bit)) != 0; };

  if (has(2))      oflags |= O_RDWR;
  else if (has(1)) oflags |= O_WRONLY;
  else             oflags |= O_RDONLY;

  if (has(3))  oflags |= O_CREAT;
  if (has(4))  oflags |= O_TRUNC;
  if (has(5))  oflags |= O_EXCL;
  if (has(6))  oflags |= O_APPEND;
#ifdef O_CLOEXEC
  if (has(7))  oflags |= O_CLOEXEC;
#endif
#ifdef O_DIRECTORY
  if (has(8))  oflags |= O_DIRECTORY;
#endif
#ifdef O_NOFOLLOW
  if (has(9))  oflags |= O_NOFOLLOW;
#endif
  if (has(10)) oflags |= O_NONBLOCK;
  // 11 OF_SYNC, 12 OF_DSYNC, 13 OF_RSYNC are *not* applied: blocking writes.
#ifdef O_DIRECT
  if (has(14)) oflags |= O_DIRECT;
#endif
#ifdef O_NOATIME
  if (has(15)) oflags |= O_NOATIME;
#endif
#ifdef O_PATH
  if (has(16)) oflags |= O_PATH;
#endif
#ifdef O_TMPFILE
  if (has(17)) oflags |= O_TMPFILE;
#endif
#ifdef O_LARGEFILE
  if (has(18)) oflags |= O_LARGEFILE;
#endif
#ifdef O_ASYNC
  if (has(19)) oflags |= O_ASYNC;
#endif
#ifdef O_NOCTTY
  if (has(20)) oflags |= O_NOCTTY;
#endif

  oflags |= O_NONBLOCK;  // belt-and-suspenders: never block on open
  return oflags;
}

static int access_from_mode(uint32_t m) {
  switch (m) {
  case 0:
    return F_OK;
  case 1:
    return R_OK;
  case 2:
    return W_OK;
  case 3:
    return X_OK;
  default:
    return F_OK;
  }
}

static int flock_from_mask(uint32_t m) {
  int op = 0;
  if (m & (1u << 0))
    op |= LOCK_SH;
  if (m & (1u << 1))
    op |= LOCK_EX;
  if (m & (1u << 2))
    op |= LOCK_UN;
  op |= LOCK_NB; // force non-blocking
  if (!op)
    op = LOCK_SH | LOCK_NB;
  return op;
}

static short poll_events_from_mask(uint32_t m) {
  short ev = 0;
  if (m & (1u << 0))
    ev |= POLLIN;
  if (m & (1u << 1))
    ev |= POLLOUT;
  if (m & (1u << 2))
    ev |= POLLPRI;
#ifdef POLLRDHUP
  if (m & (1u << 3))
    ev |= POLLRDHUP;
#endif
  if (ev == 0)
    ev = POLLIN;
  return ev;
}

// Linux fcntl(2) command surface. We deliberately exclude F_SETLKW and
// F_OFD_SETLKW (blocking lock acquisition) and F_NOTIFY (raises SIGIO).
static int safe_fcntl_cmd(uint32_t raw) {
  static const int cmds[] = {
    F_GETFD, F_SETFD, F_GETFL, F_SETFL, F_DUPFD,
#ifdef F_DUPFD_CLOEXEC
    F_DUPFD_CLOEXEC,
#endif
    F_GETOWN, F_SETOWN,
#ifdef F_GETSIG
    F_GETSIG,
#endif
#ifdef F_SETSIG
    F_SETSIG,
#endif
#ifdef F_GETLEASE
    F_GETLEASE,
#endif
#ifdef F_SETLEASE
    F_SETLEASE,
#endif
#ifdef F_GETPIPE_SZ
    F_GETPIPE_SZ,
#endif
#ifdef F_SETPIPE_SZ
    F_SETPIPE_SZ,
#endif
#ifdef F_ADD_SEALS
    F_ADD_SEALS,
#endif
#ifdef F_GET_SEALS
    F_GET_SEALS,
#endif
  };
  return cmds[raw % (sizeof(cmds) / sizeof(cmds[0]))];
}

static int safe_fcntl_arg(int cmd, uint32_t raw) {
  switch (cmd) {
  case F_SETFD:
    return (raw & 1u) ? FD_CLOEXEC : 0;
  case F_SETFL: {
    // O_SYNC / O_DSYNC are intentionally absent: enabling them on an open fd
    // turns subsequent writes into blocking durability barriers.
    int fl = 0;
    if (raw & (1u << 0)) fl |= O_APPEND;
    if (raw & (1u << 1)) fl |= O_NONBLOCK;
#ifdef O_DIRECT
    if (raw & (1u << 2)) fl |= O_DIRECT;
#endif
#ifdef O_NOATIME
    if (raw & (1u << 3)) fl |= O_NOATIME;
#endif
#ifdef O_ASYNC
    if (raw & (1u << 4)) fl |= O_ASYNC;
#endif
    return fl;
  }
  case F_SETOWN:
    return 0;  // never deliver SIGIO to a real pid
#ifdef F_SETSIG
  case F_SETSIG:
    return 0;
#endif
#ifdef F_SETLEASE
  case F_SETLEASE:
    switch (raw % 3) {
    case 0:  return F_RDLCK;
    case 1:  return F_WRLCK;
    default: return F_UNLCK;
    }
#endif
#ifdef F_SETPIPE_SZ
  case F_SETPIPE_SZ:
    return 4096 << (raw & 0x7);
#endif
#ifdef F_ADD_SEALS
  case F_ADD_SEALS: {
    int sl = 0;
#ifdef F_SEAL_SEAL
    if (raw & 1u)  sl |= F_SEAL_SEAL;
#endif
#ifdef F_SEAL_SHRINK
    if (raw & 2u)  sl |= F_SEAL_SHRINK;
#endif
#ifdef F_SEAL_GROW
    if (raw & 4u)  sl |= F_SEAL_GROW;
#endif
#ifdef F_SEAL_WRITE
    if (raw & 8u)  sl |= F_SEAL_WRITE;
#endif
#ifdef F_SEAL_FUTURE_WRITE
    if (raw & 16u) sl |= F_SEAL_FUTURE_WRITE;
#endif
    return sl;
  }
#endif
  case F_DUPFD:
#ifdef F_DUPFD_CLOEXEC
  case F_DUPFD_CLOEXEC:
#endif
    return static_cast<int>(raw % 64);
  default:
    return static_cast<int>(raw);
  }
}

static int safe_socket_domain(uint32_t raw) {
  switch (raw % 2) {
  case 0:
    return AF_UNIX;
  default:
    return AF_LOCAL;
  }
}

static int safe_socket_type(uint32_t raw) {
  int type = (raw & 1u) ? SOCK_DGRAM : SOCK_STREAM;
#ifdef SOCK_CLOEXEC
  if (raw & (1u << 1))
    type |= SOCK_CLOEXEC;
#endif
#ifdef SOCK_NONBLOCK
  if (raw & (1u << 2))
    type |= SOCK_NONBLOCK;
#endif
  return type;
}

static std::string sanitize(std::string s) {
  // Keep fuzz confined to sandbox; kill absolute paths & traversal.
  while (!s.empty() && s[0] == '/')
    s.erase(0, 1);
  if (s.find("..") != std::string::npos)
    s = "f";
  // replace slashes to keep flat-ish tree inside sandbox
  std::replace(s.begin(), s.end(), '/', '_');
  if (s.empty())
    s = "f";
  return s;
}

struct Pools {
  struct SharedHandleSlot {
    int fd = -1;
    uint64_t generation = 0;
    bool live = false;
  };

  struct SharedHandleTable {
    std::mutex mu;
    std::vector<SharedHandleSlot> slots;
  };

  struct InteractionTracker;

  struct SharedState {
    SharedHandleTable fds;
    SharedHandleTable dirfds;
    SharedHandleTable kqfds;
    std::shared_ptr<InteractionTracker> interaction_tracker;
  };

  std::vector<std::string> paths; // relative to root_path
  std::vector<int> fds;           // open file descriptors
  std::vector<int> dirfds;        // open directory fds
  std::vector<int> kqfds;         // kqueue descriptors
  struct Mapping {
    void *addr = MAP_FAILED;
    size_t len = 0;
    bool live = false;
  };
  struct AsyncReq {
    struct aiocb cb;
    std::string storage;
    bool submitted = false;
    bool returned = false;

    AsyncReq() { memset(&cb, 0, sizeof(cb)); }
  };
  std::vector<std::unique_ptr<AsyncReq>> aio_reqs;
  std::vector<Mapping> mappings;
  std::string root_path;
  int root_dirfd = -1;
  int cwd_dirfd = AT_FDCWD;
  bool owns_root = true;
  std::shared_ptr<SharedState> shared_state;
};

namespace fs = std::filesystem;

static const size_t kMaxFDs = 128; // hard caps to avoid EMFILE
static const size_t kMaxDirFDs = 32;
static const size_t kMaxKqFDs = 32;
static const size_t kMaxAioReqs = 64;

static Pools::AsyncReq *get_aio_req(Pools &P, uint32_t idx);
static void reset_aio_req(std::unique_ptr<Pools::AsyncReq> &req);
static Pools::AsyncReq *ensure_aio_req(Pools &P, uint32_t idx);
static void cancel_aio_for_fd(Pools &P, int fd);
static Pools::Mapping *get_mapping(Pools &P, uint32_t idx);
static Pools::Mapping *ensure_mapping_slot(Pools &P, uint32_t idx);
static bool take_idx(size_t sz, uint32_t idx, size_t &out);

static void set_cloexec(int fd) {
  if (fd < 0)
    return;
  int fl = fcntl(fd, F_GETFD, 0);
  if (fl != -1)
    (void)fcntl(fd, F_SETFD, fl | FD_CLOEXEC);
}

static bool uses_shared_handles(const Pools &P) {
  return static_cast<bool>(P.shared_state);
}

static size_t shared_slot_count(Pools::SharedHandleTable &table) {
  std::lock_guard<std::mutex> lock(table.mu);
  return table.slots.size();
}

static void push_shared_handle_capped(Pools::SharedHandleTable &table,
                                      size_t cap, int fd, bool nonblock,
                                      bool cloexec) {
  if (fd < 0)
    return;
  if (nonblock)
    set_nonblock(fd);
  if (cloexec)
    set_cloexec(fd);
  std::lock_guard<std::mutex> lock(table.mu);
  if (table.slots.size() >= cap) {
    (void)close(fd);
    return;
  }
  table.slots.push_back({fd, 1, true});
}

static int get_shared_handle_fd(Pools::SharedHandleTable &table, size_t idx) {
  std::lock_guard<std::mutex> lock(table.mu);
  if (idx >= table.slots.size() || !table.slots[idx].live)
    return -1;
  return table.slots[idx].fd;
}

static int get_shared_handle_fd_by_hint(Pools::SharedHandleTable &table,
                                        uint32_t idx_hint) {
  std::lock_guard<std::mutex> lock(table.mu);
  if (table.slots.empty())
    return -1;
  size_t idx = static_cast<size_t>(idx_hint) % table.slots.size();
  if (!table.slots[idx].live)
    return -1;
  return table.slots[idx].fd;
}

static int mark_shared_handle_closed(Pools::SharedHandleTable &table,
                                     size_t idx) {
  std::lock_guard<std::mutex> lock(table.mu);
  if (idx >= table.slots.size() || !table.slots[idx].live)
    return -1;
  table.slots[idx].live = false;
  ++table.slots[idx].generation;
  return table.slots[idx].fd;
}

static bool replace_shared_handle(Pools::SharedHandleTable &table, size_t idx,
                                  int fd) {
  if (fd < 0)
    return false;
  std::lock_guard<std::mutex> lock(table.mu);
  if (idx >= table.slots.size())
    return false;
  table.slots[idx].fd = fd;
  table.slots[idx].live = true;
  ++table.slots[idx].generation;
  return true;
}

static void mark_shared_handles_closed_by_value(Pools::SharedHandleTable &table,
                                                int fd) {
  if (fd < 0)
    return;
  std::lock_guard<std::mutex> lock(table.mu);
  for (auto &slot : table.slots) {
    if (slot.live && slot.fd == fd) {
      slot.live = false;
      ++slot.generation;
    }
  }
}

static void replace_shared_handles_by_value(Pools::SharedHandleTable &table,
                                            int oldfd, int newfd) {
  if (oldfd < 0 || newfd < 0)
    return;
  std::lock_guard<std::mutex> lock(table.mu);
  for (auto &slot : table.slots) {
    if (slot.live && slot.fd == oldfd) {
      slot.fd = newfd;
      ++slot.generation;
    }
  }
}

static void close_shared_handle_table(Pools::SharedHandleTable &table) {
  std::lock_guard<std::mutex> lock(table.mu);
  std::unordered_set<int> closed;
  for (auto &slot : table.slots) {
    if (slot.fd >= 0 && closed.insert(slot.fd).second)
      (void)close(slot.fd);
    slot.fd = -1;
    slot.live = false;
  }
  table.slots.clear();
}

static void push_fd_capped(std::vector<int> &v, int fd) {
  if (fd < 0)
    return;
  set_nonblock(fd);
  set_cloexec(fd);
  if (v.size() >= kMaxFDs) {
    (void)close(fd);
    return;
  }
  v.push_back(fd);
}

static void push_fd_capped(Pools &P, int fd) {
  if (uses_shared_handles(P)) {
    push_shared_handle_capped(P.shared_state->fds, kMaxFDs, fd, true, true);
    return;
  }
  push_fd_capped(P.fds, fd);
}

static void push_dirfd_capped(std::vector<int> &v, int fd) {
  if (fd < 0)
    return;
  set_nonblock(fd);
  set_cloexec(fd);
  if (v.size() >= kMaxDirFDs) {
    (void)close(fd);
    return;
  }
  v.push_back(fd);
}

static void push_dirfd_capped(Pools &P, int fd) {
  if (uses_shared_handles(P)) {
    push_shared_handle_capped(P.shared_state->dirfds, kMaxDirFDs, fd, true,
                              true);
    return;
  }
  push_dirfd_capped(P.dirfds, fd);
}

static void push_kqfd_capped(std::vector<int> &v, int fd) {
  if (fd < 0)
    return;
  set_cloexec(fd);
  if (v.size() >= kMaxKqFDs) {
    (void)close(fd);
    return;
  }
  v.push_back(fd);
}

static void push_kqfd_capped(Pools &P, int fd) {
  if (uses_shared_handles(P)) {
    push_shared_handle_capped(P.shared_state->kqfds, kMaxKqFDs, fd, false,
                              true);
    return;
  }
  push_kqfd_capped(P.kqfds, fd);
}

static size_t fd_slot_count(const Pools &P) {
  return uses_shared_handles(P) ? shared_slot_count(P.shared_state->fds)
                                : P.fds.size();
}

static size_t dirfd_slot_count(const Pools &P) {
  return uses_shared_handles(P) ? shared_slot_count(P.shared_state->dirfds)
                                : P.dirfds.size();
}

static size_t kqfd_slot_count(const Pools &P) {
  return uses_shared_handles(P) ? shared_slot_count(P.shared_state->kqfds)
                                : P.kqfds.size();
}

static int fd_from_slot(const Pools &P, size_t idx) {
  return uses_shared_handles(P) ? get_shared_handle_fd(P.shared_state->fds, idx)
                                : ((idx < P.fds.size()) ? P.fds[idx] : -1);
}

static int dirfd_from_slot(const Pools &P, size_t idx) {
  return uses_shared_handles(P)
             ? get_shared_handle_fd(P.shared_state->dirfds, idx)
             : ((idx < P.dirfds.size()) ? P.dirfds[idx] : -1);
}

static int kqfd_from_slot(const Pools &P, size_t idx) {
  return uses_shared_handles(P) ? get_shared_handle_fd(P.shared_state->kqfds,
                                                       idx)
                                : ((idx < P.kqfds.size()) ? P.kqfds[idx] : -1);
}

static bool take_fd_idx(const Pools &P, uint32_t idx, size_t &out) {
  return take_idx(fd_slot_count(P), idx, out);
}

static bool take_dirfd_idx(const Pools &P, uint32_t idx, size_t &out) {
  return take_idx(dirfd_slot_count(P), idx, out);
}

static std::string rand_name(FuzzedDataProvider &fdp, bool want_dir) {
  std::string stem = want_dir ? "d_" : "f_";
  char buf[32];
  unsigned v = fdp.ConsumeIntegral<unsigned>();
  snprintf(buf, sizeof(buf), "%08x", v);
  std::string s = stem + std::string(buf);
  if (fdp.ConsumeBool()) {
    char b2[16];
    snprintf(b2, sizeof(b2), "%x", fdp.ConsumeIntegral<unsigned>() & 0xFFF);
    s = (std::string("dir_") + b2) + "/" + s;
  }
  return s;
}

static void close_and_forget(std::vector<int> &v, size_t idx) {
  if (idx >= v.size())
    return;
  if (v[idx] >= 0)
    (void)close(v[idx]);
  v.erase(v.begin() + idx);
}

static bool take_idx(size_t sz, uint32_t idx, size_t &out) {
  if (sz == 0)
    return false;
  out = idx % sz;
  return true;
}

static void set_rlimits() {
  struct rlimit rf{32u * 1024u * 1024u,
                   32u * 1024u * 1024u}; // 32 MB max file size
  (void)setrlimit(RLIMIT_FSIZE, &rf);
  struct rlimit rn{1024, 1024}; // max fds
  (void)setrlimit(RLIMIT_NOFILE, &rn);
}

static std::atomic<uint64_t> g_worker_id{0};
static int g_initial_cwd_fd = -1;
static mode_t g_initial_umask = 022;
static int kcov_fd = -1;

static bool is_protected_fd(int fd) {
  return fd >= 0 &&
         (fd == STDIN_FILENO || fd == STDOUT_FILENO || fd == STDERR_FILENO ||
          fd == g_initial_cwd_fd || fd == kcov_fd);
}

static void restore_process_cwd() {
  if (g_initial_cwd_fd >= 0)
    (void)::fchdir(g_initial_cwd_fd);
}

static void restore_process_umask() {
  (void)::umask(g_initial_umask);
}

// All filesystem operations (per-worker workspaces, every open/read/write/etc.
// the fuzzer issues) happen under this directory. On the VM it's the ntfs3
// mount point.
static constexpr const char *kSandboxRoot = "/tmp/ntfs";

static std::string sandbox_tmp_root() { return kSandboxRoot; }

static void initialize_sandbox_tmp_root() {
  std::error_code ec;
  if (!fs::create_directories(kSandboxRoot, ec) && ec) {
    fprintf(stderr, "fsfuzz: cannot create sandbox root '%s': %s\n",
            kSandboxRoot, ec.message().c_str());
  }
}

static std::string create_workspace_root(uint64_t wid) {
  std::error_code ec;
  const fs::path base = sandbox_tmp_root();
  (void)fs::create_directories(base, ec);

  const std::string templ =
      (base / ("fsfuzz." + std::to_string(wid) + ".XXXXXX")).string();
  if (templ.size() < PATH_MAX) {
    std::vector<char> buf(templ.begin(), templ.end());
    buf.push_back('\0');
    if (char *root = mkdtemp(buf.data()))
      return root;
  }

  const fs::path fallback =
      base / ("fsfuzz." + std::to_string(wid) + ".fallback." +
              std::to_string(static_cast<unsigned long long>(getpid())));
  ec.clear();
  (void)fs::create_directories(fallback, ec);
  return fallback.string();
}

struct ScopedProcessState {
  ScopedProcessState() {
    restore_process_cwd();
    restore_process_umask();
  }

  ~ScopedProcessState() {
    restore_process_cwd();
    restore_process_umask();
  }
};

static std::string abs_path(const Pools &P, const std::string &rel) {
  if (rel.empty())
    return P.root_path;
  return P.root_path + "/" + rel;
}

static std::string path_to_rel(const Pools &P, const std::string &abs) {
  if (abs == P.root_path)
    return "";
  const std::string prefix = P.root_path + "/";
  if (abs.rfind(prefix, 0) == 0)
    return abs.substr(prefix.size());
  return sanitize(abs);
}

static std::string dirfd_relpath(const Pools &P, int dirfd) {
  if (dirfd == AT_FDCWD || dirfd == P.cwd_dirfd)
    dirfd = P.cwd_dirfd;
  if (dirfd == P.root_dirfd)
    return "";
#ifdef F_GETPATH
  char buf[PATH_MAX] = {0};
  if (dirfd >= 0 && fcntl(dirfd, F_GETPATH, buf) != -1)
    return path_to_rel(P, std::string(buf));
#endif
  return "";
}

static std::string rel_from_dirfd_name(const Pools &P, int dirfd,
                                       const std::string &name) {
  std::string clean = sanitize(name);
  std::string base = dirfd_relpath(P, dirfd);
  return base.empty() ? clean : (base + "/" + clean);
}

static void ensure_parent_dirs(const Pools &P, const std::string &rel) {
  fs::path p(abs_path(P, rel));
  std::error_code ec;
  if (p.has_parent_path())
    (void)fs::create_directories(p.parent_path(), ec);
}

static void track_path(Pools &P, const std::string &rel) {
  if (rel.empty())
    return;
  if (std::find(P.paths.begin(), P.paths.end(), rel) == P.paths.end())
    P.paths.push_back(rel);
}

static void maybe_open_dirfd(Pools &P, const std::string &rel) {
  int d = open(abs_path(P, rel).c_str(), O_RDONLY | O_DIRECTORY | O_NONBLOCK);
  if (d >= 0)
    push_dirfd_capped(P, d);
}

static void seed_workspace_paths(Pools &P) {
  track_path(P, "seed_file");
  track_path(P, "seed_dir");
}

static void seed_workspace_common(Pools &P, bool create_shared_objects = true) {
  std::error_code ec;
  seed_workspace_paths(P);
  if (!create_shared_objects)
    return;
  (void)fs::create_directories(fs::path(P.root_path) / "seed_dir", ec);
  int fd = open((fs::path(P.root_path) / "seed_file").c_str(),
                O_CREAT | O_RDWR | O_NONBLOCK, 0644);
  if (fd >= 0)
    push_fd_capped(P, fd);
  maybe_open_dirfd(P, "seed_dir");
}

static void seed_workspace(Pools &P) {
  uint64_t wid = g_worker_id.fetch_add(1, std::memory_order_relaxed);
  P.root_path = create_workspace_root(wid);
  P.root_dirfd = open(P.root_path.c_str(), O_RDONLY | O_DIRECTORY | O_NONBLOCK);
  P.cwd_dirfd = (P.root_dirfd >= 0) ? P.root_dirfd : AT_FDCWD;
  P.owns_root = true;

  seed_workspace_common(P);
}

static void attach_workspace(Pools &P, const std::string &root_path,
                             int shared_root_fd,
                             std::shared_ptr<Pools::SharedState> shared_state =
                                 nullptr) {
  P.root_path = root_path;
  P.root_dirfd = dup(shared_root_fd);
  if (P.root_dirfd >= 0) {
    set_nonblock(P.root_dirfd);
    set_cloexec(P.root_dirfd);
  }
  P.cwd_dirfd = P.root_dirfd;
  P.owns_root = false;
  P.shared_state = std::move(shared_state);
  seed_workspace_common(P, !uses_shared_handles(P));
}

static void cleanup_session(Pools &P) {
  for (auto &req : P.aio_reqs)
    reset_aio_req(req);
  P.aio_reqs.clear();
  for (auto &mapping : P.mappings) {
    if (mapping.live && mapping.addr != MAP_FAILED)
      (void)::munmap(mapping.addr, mapping.len);
  }
  P.mappings.clear();

  std::unordered_set<int> closed;
  if (uses_shared_handles(P)) {
    if (P.owns_root) {
      close_shared_handle_table(P.shared_state->fds);
      close_shared_handle_table(P.shared_state->dirfds);
      close_shared_handle_table(P.shared_state->kqfds);
    }
  } else {
    for (int fd : P.fds)
      if (fd >= 0 && closed.insert(fd).second)
        (void)close(fd);
    for (int d : P.dirfds)
      if (d >= 0 && closed.insert(d).second)
        (void)close(d);
    for (int kq : P.kqfds)
      if (kq >= 0 && closed.insert(kq).second)
        (void)close(kq);
    P.fds.clear();
    P.dirfds.clear();
    P.kqfds.clear();
  }
  if (P.root_dirfd >= 0 && closed.insert(P.root_dirfd).second)
    (void)close(P.root_dirfd);

  P.paths.clear();
  P.cwd_dirfd = AT_FDCWD;
  P.root_dirfd = -1;
  P.shared_state.reset();

  if (P.owns_root && !P.root_path.empty()) {
    std::error_code ec;
    (void)fs::remove_all(P.root_path, ec);
  }
  P.root_path.clear();
}

static std::string ensure_path(Pools &P, FuzzedDataProvider &fdp,
                               uint32_t want_idx, bool want_dir,
                               bool mkparents) {
  if (want_idx < P.paths.size())
    return P.paths[want_idx];
  std::string name = sanitize(rand_name(fdp, want_dir));
  if (mkparents)
    ensure_parent_dirs(P, name);
  if (want_dir) {
    (void)mkdir(abs_path(P, name).c_str(), 0755);
    maybe_open_dirfd(P, name);
  } else {
    int fd =
        open(abs_path(P, name).c_str(), O_CREAT | O_RDWR | O_NONBLOCK, 0644);
    if (fd >= 0)
      (void)close(fd);
  }
  track_path(P, name);
  return name;
}

static int pick_dirfd(const Pools &P, int idx_hint) {
  if (idx_hint < 0 || dirfd_slot_count(P) == 0)
    return (P.cwd_dirfd >= 0) ? P.cwd_dirfd : P.root_dirfd;
  int dirfd = uses_shared_handles(P)
                  ? get_shared_handle_fd_by_hint(P.shared_state->dirfds,
                                                 static_cast<uint32_t>(idx_hint))
                  : dirfd_from_slot(P, static_cast<size_t>(idx_hint) %
                                           dirfd_slot_count(P));
  return dirfd >= 0 ? dirfd
                    : ((P.cwd_dirfd >= 0) ? P.cwd_dirfd : P.root_dirfd);
}

static Pools::AsyncReq *get_aio_req(Pools &P, uint32_t idx) {
  if (P.aio_reqs.empty())
    return nullptr;
  size_t slot = idx % P.aio_reqs.size();
  return P.aio_reqs[slot] ? P.aio_reqs[slot].get() : nullptr;
}

static void reset_aio_req(std::unique_ptr<Pools::AsyncReq> &req) {
  if (!req)
    return;
  if (req->submitted && req->cb.aio_fildes >= 0)
    (void)::aio_cancel(req->cb.aio_fildes, &req->cb);
  req.reset();
}

static Pools::AsyncReq *ensure_aio_req(Pools &P, uint32_t idx) {
  size_t slot = idx % kMaxAioReqs;
  if (P.aio_reqs.size() <= slot)
    P.aio_reqs.resize(slot + 1);
  reset_aio_req(P.aio_reqs[slot]);
  P.aio_reqs[slot] = std::make_unique<Pools::AsyncReq>();
  return P.aio_reqs[slot].get();
}

static Pools::Mapping *get_mapping(Pools &P, uint32_t idx) {
  if (P.mappings.empty())
    return nullptr;
  size_t slot = idx % P.mappings.size();
  return P.mappings[slot].live ? &P.mappings[slot] : nullptr;
}

static Pools::Mapping *ensure_mapping_slot(Pools &P, uint32_t idx) {
  size_t slot = idx % kMaxAioReqs;
  if (P.mappings.size() <= slot)
    P.mappings.resize(slot + 1);
  if (P.mappings[slot].live && P.mappings[slot].addr != MAP_FAILED)
    (void)::munmap(P.mappings[slot].addr, P.mappings[slot].len);
  P.mappings[slot] = {};
  return &P.mappings[slot];
}

static void cancel_aio_for_fd(Pools &P, int fd) {
  if (fd < 0)
    return;
  for (auto &req : P.aio_reqs) {
    if (!req)
      continue;
    if (req->submitted && req->cb.aio_fildes == fd)
      (void)::aio_cancel(fd, &req->cb);
  }
}

static void close_fd_from_pool(Pools &P, size_t idx) {
  int fd = -1;
  if (uses_shared_handles(P)) {
    fd = mark_shared_handle_closed(P.shared_state->fds, idx);
    mark_shared_handles_closed_by_value(P.shared_state->dirfds, fd);
  } else {
    if (idx >= P.fds.size())
      return;
    fd = P.fds[idx];
    if (fd >= 0)
      (void)close(fd);
    P.fds.erase(P.fds.begin() + idx);
  }
  if (fd < 0)
    return;
  cancel_aio_for_fd(P, fd);
  if (!uses_shared_handles(P)) {
    for (auto it = P.dirfds.begin(); it != P.dirfds.end();) {
      if (*it == fd) {
        if (P.cwd_dirfd == fd)
          P.cwd_dirfd = (P.root_dirfd >= 0) ? P.root_dirfd : AT_FDCWD;
        it = P.dirfds.erase(it);
      } else {
        ++it;
      }
    }
  } else if (P.cwd_dirfd == fd) {
    P.cwd_dirfd = (P.root_dirfd >= 0) ? P.root_dirfd : AT_FDCWD;
  }
}

static mode_t safe_mode_bits(uint32_t raw) {
  return static_cast<mode_t>(raw & 07777);
}

static mode_t safe_mknod_mode(uint32_t raw) {
  mode_t mode = static_cast<mode_t>(raw);
  mode_t type = mode & S_IFMT;
  mode_t perm = mode & 07777;
  if (type == 0 || type == S_IFCHR || type == S_IFBLK || type == S_IFSOCK)
    type = S_IFIFO;
  return type | perm;
}

static void do_command(const Command &c, Pools &P, FuzzedDataProvider &fdp) {
  ScopedProcessState process_state;
  auto path_at = [&](uint32_t idx, std::string &out_abs) -> bool {
    size_t i;
    if (!take_idx(P.paths.size(), idx, i))
      return false;
    out_abs = abs_path(P, P.paths[i]);
    return true;
  };
  auto fd_at = [&](uint32_t idx, int &out_fd) -> bool {
    size_t i;
    if (!take_fd_idx(P, idx, i))
      return false;
    out_fd = fd_from_slot(P, i);
    return out_fd >= 0;
  };
  auto dirfd_at = [&](uint32_t idx, int &out_fd) -> bool {
    size_t i;
    if (!take_dirfd_idx(P, idx, i))
      return false;
    out_fd = dirfd_from_slot(P, i);
    return out_fd >= 0;
  };

  switch (c.command_case()) {

  // ---------- Open / Close ----------
  case Command::kOpen: {
    const auto &m = c.open();
    std::string path =
        ensure_path(P, fdp, m.has_path_idx() ? m.path_idx() : UINT32_MAX,
                    (m.flags() & (1u << 8)) != 0, m.ensure_dir());
    int flags = flags_from_mask(m.flags());
    int fd = open(abs_path(P, path).c_str(), flags, safe_mode_bits(m.mode()));
    if (fd >= 0) {
      push_fd_capped(P, fd);
      if (flags & O_DIRECTORY) {
        int dupfd = dup(fd);
        if (dupfd >= 0)
          push_dirfd_capped(P, dupfd);
      }
    }
    break;
  }
  case Command::kOpenAt: {
    const auto &m = c.open_at();
    int dirfd = pick_dirfd(P, m.has_dirfd_idx() ? m.dirfd_idx() : -1);
    bool want_dir = (m.flags() & (1u << 8)) != 0;
    std::string name = m.has_name_hint() ? sanitize(m.name_hint())
                                         : sanitize(rand_name(fdp, want_dir));
    if (m.ensure_dir())
      ensure_parent_dirs(P, rel_from_dirfd_name(P, dirfd, name));
    int oflags = flags_from_mask(m.flags());
    int fd = openat(dirfd, name.c_str(), oflags, safe_mode_bits(m.mode()));
    if (fd >= 0) {
      push_fd_capped(P, fd);
      if (oflags & O_DIRECTORY) {
        int dupfd = dup(fd);
        if (dupfd >= 0)
          push_dirfd_capped(P, dupfd);
      }
    }
    track_path(P, rel_from_dirfd_name(P, dirfd, name));
    break;
  }
  case Command::kClose: {
    const auto &m = c.close();
    size_t i;
    if (take_fd_idx(P, m.fd_idx(), i))
      close_fd_from_pool(P, i);
    break;
  }
  case Command::kDup: {
    const auto &m = c.dup();
    int srcfd = -1;
    if (!fd_at(m.fd_idx(), srcfd))
      break;
    int fd = ::dup(srcfd);
    if (fd >= 0)
      push_fd_capped(P, fd);
    break;
  }
  case Command::kDup2: {
    const auto &m = c.dup2();
    size_t src_i;
    if (!take_fd_idx(P, m.old_fd_idx(), src_i))
      break;
    size_t dst_i;
    if (!take_fd_idx(P, m.new_fd(), dst_i))
      break;
    int oldfd = fd_from_slot(P, src_i);
    int newfd = fd_from_slot(P, dst_i);
    if (oldfd == newfd || is_protected_fd(oldfd) || is_protected_fd(newfd))
      break;
    int fd = ::dup2(oldfd, newfd);
    if (fd >= 0) {
      if (uses_shared_handles(P)) {
        (void)replace_shared_handle(P.shared_state->fds, dst_i, fd);
        replace_shared_handles_by_value(P.shared_state->dirfds, newfd, fd);
      } else {
        P.fds[dst_i] = fd;
        for (auto &dirfd : P.dirfds) {
          if (dirfd == newfd)
            dirfd = fd;
        }
      }
      if (P.cwd_dirfd == newfd)
        P.cwd_dirfd = fd;
    }
    break;
  }
  case Command::kFcntl: {
    const auto &m = c.fcntl();
    int fd = -1;
    if (!fd_at(m.fd_idx(), fd))
      break;
    int cmd = safe_fcntl_cmd(m.cmd());
    if (m.cmd() % 8 == 7) {
#ifdef F_GETPATH
      char pathbuf[PATH_MAX] = {0};
      (void)::fcntl(fd, F_GETPATH, pathbuf);
#endif
      break;
    }
    int arg = safe_fcntl_arg(cmd, m.arg());
    int rv = ::fcntl(fd, cmd, arg);
    if ((cmd == F_DUPFD
#ifdef F_DUPFD_CLOEXEC
         || cmd == F_DUPFD_CLOEXEC
#endif
         ) && rv >= 0) {
      push_fd_capped(P, rv);
    }
    break;
  }
  case Command::kPipe: {
    const auto &m = c.pipe();
    int fds[2] = {-1, -1};
    int flags = 0;
    if (m.nonblock())
      flags |= O_NONBLOCK;
    if (m.cloexec())
      flags |= O_CLOEXEC;
    if (::pipe2(fds, flags) == 0) {
      push_fd_capped(P, fds[0]);
      push_fd_capped(P, fds[1]);
    }
    break;
  }
  case Command::kSocketpair: {
    const auto &m = c.socketpair();
    int sv[2] = {-1, -1};
    int domain = safe_socket_domain(m.domain());
    int type = safe_socket_type(m.type());
    if (::socketpair(domain, type, 0, sv) == 0) {
      push_fd_capped(P, sv[0]);
      push_fd_capped(P, sv[1]);
    }
    break;
  }
  case Command::kSendmsg: {
    const auto &m = c.sendmsg();
    int sockfd = -1;
    if (!fd_at(m.sock_fd_idx(), sockfd) || !writable_now(sockfd))
      break;
    char data_buf[256] = {0};
    const std::string payload = m.has_data() ? m.data() : std::string();
    const size_t payload_len = std::min(payload.size(), sizeof(data_buf));
    if (payload_len > 0)
      memcpy(data_buf, payload.data(), payload_len);
    struct iovec iov{data_buf, payload_len};
    char control[CMSG_SPACE(sizeof(int))];
    memset(control, 0, sizeof(control));
    struct msghdr msg{};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    if (m.send_rights()) {
      int rights_fd = -1;
      if (!fd_at(m.rights_fd_idx(), rights_fd))
        break;
      msg.msg_control = control;
      msg.msg_controllen = sizeof(control);
      struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
      if (!cmsg)
        break;
      cmsg->cmsg_level = SOL_SOCKET;
      cmsg->cmsg_type = SCM_RIGHTS;
      cmsg->cmsg_len = CMSG_LEN(sizeof(int));
      memcpy(CMSG_DATA(cmsg), &rights_fd, sizeof(int));
      msg.msg_controllen = cmsg->cmsg_len;
    }
    (void)::sendmsg(sockfd, &msg, MSG_DONTWAIT);
    break;
  }
  case Command::kRecvmsg: {
    const auto &m = c.recvmsg();
    int sockfd = -1;
    if (!fd_at(m.sock_fd_idx(), sockfd) || !readable_now(sockfd))
      break;
    std::string data(clampu32(m.maxlen(), 1, 1024), '\0');
    struct iovec iov{data.data(), data.size()};
    char control[CMSG_SPACE(sizeof(int))];
    memset(control, 0, sizeof(control));
    struct msghdr msg{};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control;
    msg.msg_controllen = sizeof(control);
    ssize_t n = ::recvmsg(sockfd, &msg, MSG_DONTWAIT);
    if (n < 0 || !m.accept_rights())
      break;
    for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg); cmsg != nullptr;
         cmsg = CMSG_NXTHDR(&msg, cmsg)) {
      if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS)
        continue;
      size_t rights_len = cmsg->cmsg_len > CMSG_LEN(0)
                              ? cmsg->cmsg_len - CMSG_LEN(0)
                              : 0;
      const int *fds = reinterpret_cast<const int *>(CMSG_DATA(cmsg));
      size_t count = rights_len / sizeof(int);
      for (size_t idx = 0; idx < count; ++idx)
        push_fd_capped(P, fds[idx]);
    }
    break;
  }
  case Command::kPoll: {
    const auto &m = c.poll();
    int cnt = std::min(m.fd_idx_size(), 8);
    if (cnt <= 0)
      break;
    std::vector<struct pollfd> pfds;
    pfds.reserve(cnt);
    for (int n = 0; n < cnt; ++n) {
      int fd = -1;
      if (!fd_at(m.fd_idx(n), fd))
        continue;
      pfds.push_back({fd, poll_events_from_mask(m.events()), 0});
    }
    if (!pfds.empty())
      (void)::poll(pfds.data(), pfds.size(), std::clamp(m.timeout_ms(), 0, 10));
    break;
  }
  // ---------- Links / Unlinks ----------
  case Command::kLink: {
    const auto &m = c.link();
    size_t sidx;
    if (!take_idx(P.paths.size(), m.existing_path_idx(), sidx))
      break;
    std::string src = abs_path(P, P.paths[sidx]);
    std::string dst = ensure_path(
        P, fdp, m.has_new_path_idx() ? m.new_path_idx() : UINT32_MAX, false,
        true);
    (void)unlink(abs_path(P, dst).c_str());
    (void)link(src.c_str(), abs_path(P, dst).c_str());
    break;
  }
  case Command::kLinkAt: {
    const auto &m = c.link_at();
    int od = pick_dirfd(P, m.has_olddirfd_idx() ? m.olddirfd_idx() : -1);
    int nd = pick_dirfd(P, m.has_newdirfd_idx() ? m.newdirfd_idx() : -1);
    int flags = m.follow_symlink() ? AT_SYMLINK_FOLLOW : 0;
    (void)linkat(od, sanitize(m.oldname()).c_str(), nd,
                 sanitize(m.newname()).c_str(), flags);
    track_path(P, rel_from_dirfd_name(P, nd, m.newname()));
    break;
  }
  case Command::kUnlink: {
    const auto &m = c.unlink();
    size_t i;
    if (take_idx(P.paths.size(), m.path_idx(), i)) {
      std::string path = abs_path(P, P.paths[i]);
      if (unlink(path.c_str()) != 0)
        (void)rmdir(path.c_str());
    }
    break;
  }
  case Command::kUnlinkAt: {
    const auto &m = c.unlink_at();
    int d = pick_dirfd(P, m.has_dirfd_idx() ? m.dirfd_idx() : -1);
    const std::string nm = sanitize(m.name());
    if (unlinkat(d, nm.c_str(), 0) != 0)
      (void)unlinkat(d, nm.c_str(), AT_REMOVEDIR);
    break;
  }

  // ---------- Directories ----------
  case Command::kMkdir: {
    const auto &m = c.mkdir();
    std::string p = ensure_path(
        P, fdp, m.has_path_idx() ? m.path_idx() : UINT32_MAX, true, true);
    (void)mkdir(abs_path(P, p).c_str(), safe_mode_bits(m.mode()));
    maybe_open_dirfd(P, p);
    break;
  }
  case Command::kMkdirAt: {
    const auto &m = c.mkdir_at();
    int d = pick_dirfd(P, m.has_dirfd_idx() ? m.dirfd_idx() : -1);
    std::string nm = sanitize(m.name());
    (void)mkdirat(d, nm.c_str(), safe_mode_bits(m.mode()));
    std::string rel = rel_from_dirfd_name(P, d, nm);
    track_path(P, rel);
    maybe_open_dirfd(P, rel);
    break;
  }
  case Command::kRmdir: {
    const auto &m = c.rmdir();
    size_t i;
    if (take_idx(P.paths.size(), m.path_idx(), i))
      (void)rmdir(abs_path(P, P.paths[i]).c_str());
    break;
  }
  case Command::kChdir: {
    const auto &m = c.chdir();
    size_t i;
    if (!take_idx(P.paths.size(), m.path_idx(), i))
      break;
    int d = open(abs_path(P, P.paths[i]).c_str(),
                 O_RDONLY | O_DIRECTORY | O_NONBLOCK);
    if (d >= 0) {
      push_dirfd_capped(P, d);
      P.cwd_dirfd = d;
    }
    break;
  }
  case Command::kFchdir: {
    const auto &m = c.fchdir();
    int dirfd = -1;
    if (dirfd_at(m.fd_idx(), dirfd))
      P.cwd_dirfd = dirfd;
    break;
  }

  // ---------- Symlinks ----------
  case Command::kSymlink: {
    const auto &m = c.symlink();
    size_t tidx;
    if (!take_idx(P.paths.size(), m.target_path_idx(), tidx))
      break;
    std::string target = P.paths[tidx];
    std::string linkp = ensure_path(
        P, fdp, m.has_link_path_idx() ? m.link_path_idx() : UINT32_MAX, false,
        true);
    (void)unlink(abs_path(P, linkp).c_str());
    (void)symlink(target.c_str(), abs_path(P, linkp).c_str());
    break;
  }
  case Command::kSymlinkAt: {
    const auto &m = c.symlink_at();
    int d = pick_dirfd(P, m.has_newdirfd_idx() ? m.newdirfd_idx() : -1);
    std::string tgt = sanitize(m.target());
    std::string lnk = sanitize(m.linkname());
    (void)symlinkat(tgt.c_str(), d, lnk.c_str());
    track_path(P, rel_from_dirfd_name(P, d, lnk));
    break;
  }
  case Command::kReadlink: {
    const auto &m = c.readlink();
    size_t i;
    if (!take_idx(P.paths.size(), m.path_idx(), i))
      break;
    char buf[512];
    (void)readlink(abs_path(P, P.paths[i]).c_str(), buf, sizeof(buf));
    break;
  }
  case Command::kReadlinkAt: {
    const auto &m = c.readlink_at();
    int d = pick_dirfd(P, m.has_dirfd_idx() ? m.dirfd_idx() : -1);
    char buf[512];
    (void)readlinkat(d, sanitize(m.name()).c_str(), buf, sizeof(buf));
    break;
  }
  // ---------- Rename ----------
  case Command::kRename: {
    const auto &m = c.rename();
    size_t i;
    if (!take_idx(P.paths.size(), m.old_path_idx(), i))
      break;
    std::string dst = ensure_path(
        P, fdp, m.has_new_path_idx() ? m.new_path_idx() : UINT32_MAX, false,
        true);
    (void)rename(abs_path(P, P.paths[i]).c_str(), abs_path(P, dst).c_str());
    track_path(P, dst);
    break;
  }
  case Command::kRenameAt: {
    const auto &m = c.rename_at();
    int od = pick_dirfd(P, m.has_olddirfd_idx() ? m.olddirfd_idx() : -1);
    int nd = pick_dirfd(P, m.has_newdirfd_idx() ? m.newdirfd_idx() : -1);
    std::string on = sanitize(m.oldname());
    std::string nn = sanitize(m.newname());
    (void)renameat(od, on.c_str(), nd, nn.c_str());
    track_path(P, rel_from_dirfd_name(P, nd, nn));
    break;
  }
  case Command::kRenameAt2: {
    const auto &m = c.rename_at2();
    int od = pick_dirfd(P, m.has_olddirfd_idx() ? m.olddirfd_idx() : -1);
    int nd = pick_dirfd(P, m.has_newdirfd_idx() ? m.newdirfd_idx() : -1);
    std::string on = sanitize(m.oldname());
    std::string nn = sanitize(m.newname());
    (void)::syscall(SYS_renameat2, od, on.c_str(), nd, nn.c_str(),
                    m.flags());
    track_path(P, rel_from_dirfd_name(P, nd, nn));
    break;
  }

  // ---------- Stat family ----------
  case Command::kStat: {
    const auto &m = c.stat();
    size_t i;
    if (!take_idx(P.paths.size(), m.path_idx(), i))
      break;
    struct stat st;
    (void)::stat(abs_path(P, P.paths[i]).c_str(), &st);
    break;
  }
  case Command::kLstat: {
    const auto &m = c.lstat();
    size_t i;
    if (!take_idx(P.paths.size(), m.path_idx(), i))
      break;
    struct stat st;
    (void)::lstat(abs_path(P, P.paths[i]).c_str(), &st);
    break;
  }
  case Command::kFstat: {
    const auto &m = c.fstat();
    int fd = -1;
    if (!fd_at(m.fd_idx(), fd))
      break;
    struct stat st;
    (void)::fstat(fd, &st);
    break;
  }
  case Command::kFstatAt: {
    const auto &m = c.fstat_at();
    int d = pick_dirfd(P, m.has_dirfd_idx() ? m.dirfd_idx() : -1);
    struct stat st;
    (void)::fstatat(d, sanitize(m.name()).c_str(), &st, m.flags());
    break;
  }

  // ---------- chmod/chown/flags/umask/access ----------
  case Command::kChmod: {
    const auto &m = c.chmod();
    size_t i;
    if (!take_idx(P.paths.size(), m.path_idx(), i))
      break;
    (void)::chmod(abs_path(P, P.paths[i]).c_str(), safe_mode_bits(m.mode()));
    break;
  }
  case Command::kFchmod: {
    const auto &m = c.fchmod();
    int fd = -1;
    if (!fd_at(m.fd_idx(), fd))
      break;
    (void)::fchmod(fd, safe_mode_bits(m.mode()));
    break;
  }
  case Command::kFchmodAt: {
    const auto &m = c.fchmod_at();
    int d = pick_dirfd(P, m.has_dirfd_idx() ? m.dirfd_idx() : -1);
    (void)::fchmodat(d, sanitize(m.name()).c_str(), safe_mode_bits(m.mode()),
                     m.flags());
    break;
  }
  case Command::kChown: {
    const auto &m = c.chown();
    size_t i;
    if (!take_idx(P.paths.size(), m.path_idx(), i))
      break;
    (void)::chown(abs_path(P, P.paths[i]).c_str(), m.has_uid() ? m.uid() : -1,
                  m.has_gid() ? m.gid() : -1);
    break;
  }
  case Command::kLchown: {
    const auto &m = c.lchown();
    size_t i;
    if (!take_idx(P.paths.size(), m.path_idx(), i))
      break;
    (void)::lchown(abs_path(P, P.paths[i]).c_str(), m.has_uid() ? m.uid() : -1,
                   m.has_gid() ? m.gid() : -1);
    break;
  }
  case Command::kFchownAt: {
    const auto &m = c.fchown_at();
    int d = pick_dirfd(P, m.has_dirfd_idx() ? m.dirfd_idx() : -1);
    (void)::fchownat(d, sanitize(m.name()).c_str(), m.has_uid() ? m.uid() : -1,
                     m.has_gid() ? m.gid() : -1, m.flags());
    break;
  }
  case Command::kUmask: {
    // Intentionally skipped: umask is process-global and destabilizes
    // threaded fuzzing in ways that are unrelated to filesystem races.
    break;
  }
  case Command::kAccess: {
    const auto &m = c.access();
    size_t i;
    if (!take_idx(P.paths.size(), m.path_idx(), i))
      break;
    (void)::access(abs_path(P, P.paths[i]).c_str(), access_from_mode(m.mode()));
    break;
  }
  case Command::kFaccessAt: {
    const auto &m = c.faccess_at();
    int d = pick_dirfd(P, m.has_dirfd_idx() ? m.dirfd_idx() : -1);
    (void)::faccessat(d, sanitize(m.name()).c_str(), access_from_mode(m.mode()),
                      m.flags());
    break;
  }

  // ---------- xattrs ----------
  case Command::kGetxattr: {
    const auto &m = c.getxattr();
    size_t i;
    if (!take_idx(P.paths.size(), m.path_idx(), i))
      break;
    std::string buf(clampu32(m.buf_size(), 1, 1u << 14), '\0');
    const std::string p = abs_path(P, P.paths[i]);
    if (m.follow_symlink())
      (void)::getxattr(p.c_str(), m.name().c_str(), buf.data(), buf.size());
    else
      (void)::lgetxattr(p.c_str(), m.name().c_str(), buf.data(), buf.size());
    break;
  }
  case Command::kFgetxattr: {
    const auto &m = c.fgetxattr();
    int fd = -1;
    if (!fd_at(m.fd_idx(), fd))
      break;
    std::string buf(clampu32(m.buf_size(), 1, 1u << 14), '\0');
    (void)::fgetxattr(fd, m.name().c_str(), buf.data(), buf.size());
    break;
  }
  case Command::kSetxattr: {
    const auto &m = c.setxattr();
    size_t i;
    if (!take_idx(P.paths.size(), m.path_idx(), i))
      break;
    const void *data = m.has_value() ? m.value().data() : nullptr;
    size_t len = m.has_value() ? m.value().size() : 0;
    const std::string p = abs_path(P, P.paths[i]);
    if (m.follow_symlink())
      (void)::setxattr(p.c_str(), m.name().c_str(), data, len, m.flags());
    else
      (void)::lsetxattr(p.c_str(), m.name().c_str(), data, len, m.flags());
    break;
  }
  case Command::kFsetxattr: {
    const auto &m = c.fsetxattr();
    int fd = -1;
    if (!fd_at(m.fd_idx(), fd))
      break;
    const void *data = m.has_value() ? m.value().data() : nullptr;
    size_t len = m.has_value() ? m.value().size() : 0;
    (void)::fsetxattr(fd, m.name().c_str(), data, len, m.flags());
    break;
  }
  case Command::kRemovexattr: {
    const auto &m = c.removexattr();
    size_t i;
    if (!take_idx(P.paths.size(), m.path_idx(), i))
      break;
    const std::string p = abs_path(P, P.paths[i]);
    if (m.follow_symlink())
      (void)::removexattr(p.c_str(), m.name().c_str());
    else
      (void)::lremovexattr(p.c_str(), m.name().c_str());
    break;
  }
  case Command::kFremovexattr: {
    const auto &m = c.fremovexattr();
    int fd = -1;
    if (!fd_at(m.fd_idx(), fd))
      break;
    (void)::fremovexattr(fd, m.name().c_str());
    break;
  }
  case Command::kListxattr: {
    const auto &m = c.listxattr();
    size_t i;
    if (!take_idx(P.paths.size(), m.path_idx(), i))
      break;
    std::string buf(clampu32(m.buf_size(), 1, 1u << 14), '\0');
    const std::string p = abs_path(P, P.paths[i]);
    if (m.follow_symlink())
      (void)::listxattr(p.c_str(), buf.data(), buf.size());
    else
      (void)::llistxattr(p.c_str(), buf.data(), buf.size());
    break;
  }
  case Command::kFlistxattr: {
    const auto &m = c.flistxattr();
    int fd = -1;
    if (!fd_at(m.fd_idx(), fd))
      break;
    std::string buf(clampu32(m.buf_size(), 1, 1u << 14), '\0');
    (void)::flistxattr(fd, buf.data(), buf.size());
    break;
  }

  // ---------- I/O ----------
  case Command::kRead: {
    const auto &m = c.read();
    int fd = -1;
    if (!fd_at(m.fd_idx(), fd))
      break;
    uint32_t len = clampu32(m.maxlen(), 1, 1u << 14);
    if (readable_now(fd)) {
      std::string buf(len, '\0');
      (void)::read(fd, buf.data(), buf.size());
    }
    break;
  }

  case Command::kWrite: {
    const auto &m = c.write();
    int fd = -1;
    if (!fd_at(m.fd_idx(), fd))
      break;
    const void *dptr = m.has_data() ? m.data().data() : "";
    size_t dlen = m.has_data() ? m.data().size() : 0;
    // hard cap single write to 64 KiB
    if (dlen > 65536)
      dlen = 65536;
    dlen = clamp_fd_write_len(fd, dlen);
    if (dlen && writable_now(fd))
      (void)::write(fd, dptr, dlen);
    break;
  }
  case Command::kPread: {
    const auto &m = c.pread();
    int fd = -1;
    if (!fd_at(m.fd_idx(), fd))
      break;
    uint32_t len = clampu32(m.maxlen(), 1, 1u << 14);
    std::string buf(len, '\0');
    off_t cap = max_file_cap_bytes();
    off_t off = (off_t)std::min<uint64_t>(m.off(), (uint64_t)cap);
    size_t dummy = len;
    clamp_off_len(cap, off, dummy);
    if (dummy)
      (void)::pread(fd, buf.data(), dummy, off);
    break;
  }

  case Command::kPwrite: {
    const auto &m = c.pwrite();
    int fd = -1;
    if (!fd_at(m.fd_idx(), fd))
      break;
    const void *dptr = m.has_data() ? m.data().data() : "";
    size_t dlen = m.has_data() ? m.data().size() : 0;
    if (dlen > 65536)
      dlen = 65536; // cap write size
    off_t cap = max_file_cap_bytes();
    off_t off = (off_t)std::min<uint64_t>(
        m.off(), (uint64_t)std::numeric_limits<int64_t>::max());
    clamp_off_len(cap, off, dlen); // ensure off+dlen <= cap
    (void)::pwrite(fd, dptr, dlen, off);
    break;
  }
  case Command::kTruncate: {
    const auto &m = c.truncate();
    size_t i;
    if (!take_idx(P.paths.size(), m.path_idx(), i))
      break;
    off_t cap = max_file_cap_bytes();
    off_t len = (off_t)std::min<uint64_t>(m.len(), (uint64_t)cap);
    (void)::truncate(abs_path(P, P.paths[i]).c_str(), len);
    break;
  }
  case Command::kFtruncate: {
    const auto &m = c.ftruncate();
    int fd = -1;
    if (!fd_at(m.fd_idx(), fd))
      break;
    off_t cap = max_file_cap_bytes();
    off_t len = (off_t)std::min<uint64_t>(m.len(), (uint64_t)cap);
    (void)::ftruncate(fd, len);
    break;
  }
  case Command::kFsync: {
#ifndef FSFUZZ_AVOID_FSYNC
    const auto &m = c.fsync();
    int fd = -1;
    if (!fd_at(m.fd_idx(), fd))
      break;
    (void)::fsync(fd);
#endif
    break;
  }
  case Command::kFlock: {
    const auto &m = c.flock();
    int fd = -1;
    if (!fd_at(m.fd_idx(), fd))
      break;
    (void)::flock(fd, flock_from_mask(m.op()));
    break;
  }
  case Command::kReadv: {
    const auto &m = c.readv();
    int fd = -1;
    if (!fd_at(m.fd_idx(), fd) || !readable_now(fd))
      break;
    uint32_t iovcnt = clampu32(m.iovcnt(), 1, 16);
    uint32_t total = clampu32(m.maxlen(), 1, 1u << 14);
    std::vector<std::string> bufs(iovcnt,
                                  std::string((total / iovcnt) + 1, '\0'));
    std::vector<struct iovec> iov(iovcnt);
    for (uint32_t n = 0; n < iovcnt; ++n) {
      iov[n].iov_base = bufs[n].data();
      iov[n].iov_len = bufs[n].size();
    }
    (void)::readv(fd, iov.data(), static_cast<int>(iov.size()));
    break;
  }
  case Command::kWritev: {
    const auto &m = c.writev();
    int fd = -1;
    if (!fd_at(m.fd_idx(), fd) || !writable_now(fd))
      break;
    int cnt = std::min(m.data_size(), 16);
    if (cnt <= 0)
      break;
    std::vector<struct iovec> iov(cnt);
    size_t total_len = 0;
    for (int n = 0; n < cnt; ++n) {
      const std::string &chunk = m.data(n);
      size_t chunk_len = std::min<size_t>(chunk.size(), 4096);
      iov[n].iov_base = const_cast<char *>(chunk.data());
      iov[n].iov_len = chunk_len;
      total_len += chunk_len;
    }
    total_len = clamp_fd_write_len(fd, total_len);
    if (total_len == 0)
      break;
    int usable_cnt = cnt;
    size_t remaining = total_len;
    for (int n = 0; n < cnt; ++n) {
      if (remaining == 0) {
        usable_cnt = n;
        break;
      }
      if (iov[n].iov_len > remaining)
        iov[n].iov_len = remaining;
      remaining -= iov[n].iov_len;
    }
    if (usable_cnt > 0)
      (void)::writev(fd, iov.data(), usable_cnt);
    break;
  }
  case Command::kAioRead: {
    if (!async_event_syscalls_enabled())
      break;
    const auto &m = c.aio_read();
    int fd = -1;
    if (!fd_at(m.fd_idx(), fd))
      break;
    Pools::AsyncReq *req = ensure_aio_req(P, m.req_idx());
    if (!req)
      break;
    uint32_t len = clampu32(m.maxlen(), 0, 1u << 14);
    req->storage.assign(len, '\0');
    req->submitted = false;
    req->returned = false;
    req->cb.aio_fildes = fd;
    req->cb.aio_buf = req->storage.empty() ? nullptr : req->storage.data();
    req->cb.aio_nbytes = req->storage.size();
    req->cb.aio_reqprio = aio_reqprio_from_raw(m.reqprio());
    req->cb.aio_lio_opcode = aio_opcode_from_raw(m.lio_opcode(), LIO_READ);
    fill_sigevent(req->cb.aio_sigevent, m.use_sigev(), m.sigev_signo(),
                  m.sigev_value());
    off_t cap = max_file_cap_bytes();
    off_t off = (off_t)std::min<uint64_t>(
        m.off(), (uint64_t)std::numeric_limits<int64_t>::max());
    size_t usable = req->storage.size();
    clamp_off_len(cap, off, usable);
    req->cb.aio_offset = off;
    req->cb.aio_nbytes = usable;
    if (::aio_read(&req->cb) == 0)
      req->submitted = true;
    break;
  }
  case Command::kAioWrite: {
    if (!async_event_syscalls_enabled())
      break;
    const auto &m = c.aio_write();
    int fd = -1;
    if (!fd_at(m.fd_idx(), fd))
      break;
    Pools::AsyncReq *req = ensure_aio_req(P, m.req_idx());
    if (!req)
      break;
    req->storage = m.has_data() ? m.data() : std::string();
    if (req->storage.size() > 65536)
      req->storage.resize(65536);
    req->submitted = false;
    req->returned = false;
    req->cb.aio_fildes = fd;
    req->cb.aio_buf = req->storage.empty() ? nullptr : req->storage.data();
    req->cb.aio_reqprio = aio_reqprio_from_raw(m.reqprio());
    req->cb.aio_lio_opcode = aio_opcode_from_raw(m.lio_opcode(), LIO_WRITE);
    fill_sigevent(req->cb.aio_sigevent, m.use_sigev(), m.sigev_signo(),
                  m.sigev_value());
    off_t cap = max_file_cap_bytes();
    off_t off = (off_t)std::min<uint64_t>(
        m.off(), (uint64_t)std::numeric_limits<int64_t>::max());
    size_t usable = req->storage.size();
    clamp_off_len(cap, off, usable);
    req->cb.aio_offset = off;
    req->cb.aio_nbytes = usable;
    if (::aio_write(&req->cb) == 0)
      req->submitted = true;
    break;
  }
  case Command::kAioError: {
    if (!async_event_syscalls_enabled())
      break;
    const auto &m = c.aio_error();
    Pools::AsyncReq *req = get_aio_req(P, m.req_idx());
    if (!req || !req->submitted)
      break;
    (void)::aio_error(&req->cb);
    break;
  }
  case Command::kAioReturn: {
    if (!async_event_syscalls_enabled())
      break;
    const auto &m = c.aio_return();
    Pools::AsyncReq *req = get_aio_req(P, m.req_idx());
    if (!req || !req->submitted || req->returned)
      break;
    int err = ::aio_error(&req->cb);
    if (err == 0 || err == ECANCELED) {
      (void)::aio_return(&req->cb);
      req->returned = true;
    }
    break;
  }
  case Command::kAioSuspend: {
    if (!async_event_syscalls_enabled())
      break;
    // Intentionally a no-op: we want AIO submission/completion APIs covered
    // without introducing waits into the fuzz loop.
    break;
  }
  case Command::kAioCancel: {
    if (!async_event_syscalls_enabled())
      break;
    const auto &m = c.aio_cancel();
    int fd = -1;
    if (!fd_at(m.fd_idx(), fd))
      break;
    if (m.has_req_idx()) {
      Pools::AsyncReq *req = get_aio_req(P, m.req_idx());
      if (req && req->submitted)
        (void)::aio_cancel(fd, &req->cb);
      break;
    }
    (void)::aio_cancel(fd, nullptr);
    break;
  }
  case Command::kAioFsync: {
    if (!async_event_syscalls_enabled())
      break;
#ifndef FSFUZZ_AVOID_FSYNC
    const auto &m = c.aio_fsync();
    Pools::AsyncReq *req = get_aio_req(P, m.req_idx());
    if (!req || !req->submitted)
      break;
    (void)::aio_fsync(aio_fsync_op_from_raw(m.op()), &req->cb);
#endif
    break;
  }
  case Command::kLioListio: {
    if (!async_event_syscalls_enabled())
      break;
    const auto &m = c.lio_listio();
    if (m.entries_size() <= 0)
      break;
    std::vector<struct sigevent> sig_storage(1);
    struct sigevent *sigp = nullptr;
    if (m.use_sigp()) {
      fill_sigevent(sig_storage[0], true, m.sigev_signo(), m.sigev_value());
      sigp = &sig_storage[0];
    }
    std::vector<struct aiocb *> raw_list;
    raw_list.reserve(std::min(m.entries_size(), 16));
    for (int n = 0; n < m.entries_size() && raw_list.size() < 16; ++n) {
      const auto &entry = m.entries(n);
      int fd = -1;
      if (!fd_at(entry.fd_idx(), fd))
        continue;
      Pools::AsyncReq *req = ensure_aio_req(P, entry.req_idx());
      if (!req)
        continue;
      uint32_t maxlen = clampu32(entry.maxlen(), 0, 1u << 14);
      req->storage =
          entry.has_data() ? entry.data() : std::string(maxlen, '\0');
      if (req->storage.size() > 65536)
        req->storage.resize(65536);
      req->submitted = false;
      req->returned = false;
      req->cb.aio_fildes = fd;
      req->cb.aio_buf = req->storage.empty() ? nullptr : req->storage.data();
      req->cb.aio_reqprio = aio_reqprio_from_raw(entry.reqprio());
      req->cb.aio_lio_opcode = aio_opcode_from_raw(entry.opcode(), LIO_NOP);
      fill_sigevent(req->cb.aio_sigevent, entry.use_sigev(),
                    entry.sigev_signo(), entry.sigev_value());
      off_t cap = max_file_cap_bytes();
      off_t off = (off_t)std::min<uint64_t>(
          entry.off(), (uint64_t)std::numeric_limits<int64_t>::max());
      size_t usable = req->storage.size();
      clamp_off_len(cap, off, usable);
      req->cb.aio_offset = off;
      req->cb.aio_nbytes = usable;
      raw_list.push_back(&req->cb);
    }
    if (raw_list.empty())
      break;
    if (::lio_listio(lio_mode_from_raw(m.mode()), raw_list.data(),
                     static_cast<int>(raw_list.size()), sigp) == 0) {
      for (auto *cb : raw_list) {
        if (!cb)
          continue;
        for (auto &req : P.aio_reqs) {
          if (req && &req->cb == cb) {
            req->submitted = true;
            break;
          }
        }
      }
    }
    break;
  }
  case Command::kMmap: {
    const auto &m = c.mmap();
    int fd = -1;
    if (!fd_at(m.fd_idx(), fd))
      break;
    Pools::Mapping *mapping = ensure_mapping_slot(P, m.fd_idx());
    if (!mapping)
      break;
    size_t len = mmap_len_from_raw(m.len());
    off_t off = static_cast<off_t>(clampu64(m.off(), 0, max_file_cap_bytes()));
    long page = sysconf(_SC_PAGESIZE);
    size_t page_size = page > 0 ? static_cast<size_t>(page) : 4096u;
    off = static_cast<off_t>((static_cast<uint64_t>(off) / page_size) *
                             static_cast<uint64_t>(page_size));
    void *addr = ::mmap(nullptr, len, mmap_prot_from_mask(m.prot()),
                        mmap_flags_from_mask(m.flags()), fd, off);
    if (addr == MAP_FAILED)
      break;
    mapping->addr = addr;
    mapping->len = len;
    mapping->live = true;
    break;
  }
  case Command::kMunmap: {
    const auto &m = c.munmap();
    Pools::Mapping *mapping = get_mapping(P, m.map_idx());
    if (!mapping)
      break;
    (void)::munmap(mapping->addr, mapping->len);
    *mapping = {};
    break;
  }
  case Command::kMsync: {
    const auto &m = c.msync();
    Pools::Mapping *mapping = get_mapping(P, m.map_idx());
    if (!mapping)
      break;
    (void)::msync(mapping->addr, mapping->len, msync_flags_from_mask(m.flags()));
    break;
  }
  case Command::kMprotect: {
    const auto &m = c.mprotect();
    Pools::Mapping *mapping = get_mapping(P, m.map_idx());
    if (!mapping)
      break;
    (void)::mprotect(mapping->addr, mapping->len, mmap_prot_from_mask(m.prot()));
    break;
  }
  case Command::kLseek: {
    const auto &m = c.lseek();
    int fd = -1;
    if (!fd_at(m.fd_idx(), fd))
      break;
    int whence = SEEK_SET;
    switch (m.whence() % 3) {
    case 1:
      whence = SEEK_CUR;
      break;
    case 2:
      whence = SEEK_END;
      break;
    default:
      break;
    }
    off_t raw_off = static_cast<off_t>(std::min<uint64_t>(
        m.off(), (uint64_t)std::numeric_limits<int64_t>::max()));
    struct stat st{};
    if (::fstat(fd, &st) == 0 && S_ISREG(st.st_mode)) {
      off_t cap = max_file_cap_bytes();
      off_t base = 0;
      switch (whence) {
      case SEEK_CUR: {
        base = ::lseek(fd, 0, SEEK_CUR);
        if (base < 0)
          break;
        break;
      }
      case SEEK_END:
        base = st.st_size;
        break;
      default:
        break;
      }
      if (base >= 0) {
        off_t target = raw_off;
        if (whence == SEEK_CUR || whence == SEEK_END) {
          if (raw_off > cap - std::min(cap, base))
            target = cap - std::min(cap, base);
        } else {
          size_t dummy = 0;
          clamp_off_len(cap, target, dummy);
        }
        (void)::lseek(fd, target, whence);
        break;
      }
    }
    (void)::lseek(fd, raw_off, whence);
    break;
  }
  case Command::kGetdents: {
    const auto &m = c.getdents();
    int fd = -1;
    if (!fd_at(m.fd_idx(), fd))
      break;
    std::string buf(clampu32(m.count(), 1, 1u << 14), '\0');
    (void)::syscall(SYS_getdents64, fd, buf.data(), buf.size());
    break;
  }
  case Command::kSync: {
    // Intentionally skipped: global sync can stall the entire fuzz process.
    break;
  }

  // ---------- FS stats ----------
  case Command::kStatfs: {
    const auto &m = c.statfs();
    size_t i;
    if (!take_idx(P.paths.size(), m.path_idx(), i))
      break;
    struct statfs sfs;
    (void)::statfs(abs_path(P, P.paths[i]).c_str(), &sfs);
    break;
  }
  case Command::kFstatfs: {
    const auto &m = c.fstatfs();
    int fd = -1;
    if (!fd_at(m.fd_idx(), fd))
      break;
    struct statfs sfs;
    (void)::fstatfs(fd, &sfs);
    break;
  }
  case Command::kMknod: {
    const auto &m = c.mknod();
    std::string p =
        ensure_path(P, fdp, m.has_path_idx() ? m.path_idx() : UINT32_MAX, false,
                    m.ensure_dir());
    (void)unlink(abs_path(P, p).c_str());
    (void)::mknod(abs_path(P, p).c_str(), safe_mknod_mode(m.mode()),
                  static_cast<dev_t>(m.dev()));
    break;
  }
  case Command::kMknodAt: {
    const auto &m = c.mknod_at();
    int d = pick_dirfd(P, m.has_dirfd_idx() ? m.dirfd_idx() : -1);
    std::string rel = rel_from_dirfd_name(P, d, m.name());
    if (m.ensure_dir())
      ensure_parent_dirs(P, rel);
    (void)::mknodat(d, sanitize(m.name()).c_str(), safe_mknod_mode(m.mode()),
                    static_cast<dev_t>(m.dev()));
    track_path(P, rel);
    break;
  }
  case Command::kMkfifo: {
    const auto &m = c.mkfifo();
    std::string p =
        ensure_path(P, fdp, m.has_path_idx() ? m.path_idx() : UINT32_MAX, false,
                    m.ensure_dir());
    (void)unlink(abs_path(P, p).c_str());
    (void)::mkfifo(abs_path(P, p).c_str(), safe_mode_bits(m.mode()));
    break;
  }
  case Command::kMkfifoAt: {
    const auto &m = c.mkfifo_at();
    int d = pick_dirfd(P, m.has_dirfd_idx() ? m.dirfd_idx() : -1);
    std::string rel = rel_from_dirfd_name(P, d, m.name());
    if (m.ensure_dir())
      ensure_parent_dirs(P, rel);
    (void)::mkfifoat(d, sanitize(m.name()).c_str(), safe_mode_bits(m.mode()));
    track_path(P, rel);
    break;
  }
  case Command::kUtimes: {
    const auto &m = c.utimes();
    std::string path;
    if (!path_at(m.path_idx(), path))
      break;
    struct timeval tv[2];
    tv[0].tv_sec = m.atime_sec();
    tv[0].tv_usec = m.atime_usec();
    tv[1].tv_sec = m.mtime_sec();
    tv[1].tv_usec = m.mtime_usec();
    (void)::utimes(path.c_str(), tv);
    break;
  }
  case Command::kUtimensat: {
    const auto &m = c.utimensat();
    int d = pick_dirfd(P, m.has_dirfd_idx() ? m.dirfd_idx() : -1);
    struct timespec ts[2];
    ts[0].tv_sec  = m.atime_sec();
    ts[0].tv_nsec = m.atime_nsec();
    ts[1].tv_sec  = m.mtime_sec();
    ts[1].tv_nsec = m.mtime_nsec();
    (void)::utimensat(d, sanitize(m.name()).c_str(), ts, m.flags());
    break;
  }
  case Command::kAcct: {
    // Typically privileged; keep as a no-op in fuzzing mode.
    break;
  }
  case Command::kChroot: {
    // Intentionally skipped: process-global and hazardous in a multi-threaded
    // fuzzer.
    break;
  }

  // ---------- Linux-specific file ops ----------
  case Command::kFallocate: {
    const auto &m = c.fallocate();
    int fd = -1;
    if (!fd_at(m.fd_idx(), fd))
      break;
    off_t cap = max_file_cap_bytes();
    off_t off = static_cast<off_t>(
        std::min<uint64_t>(m.offset(), static_cast<uint64_t>(cap)));
    size_t len = static_cast<size_t>(m.len());
    clamp_off_len(cap, off, len);
    if (len == 0)
      break;
    (void)::fallocate(fd, static_cast<int>(m.mode()), off,
                      static_cast<off_t>(len));
    break;
  }
  case Command::kCopyFileRange: {
    const auto &m = c.copy_file_range();
    int in_fd = -1, out_fd = -1;
    if (!fd_at(m.in_fd_idx(),  in_fd))  break;
    if (!fd_at(m.out_fd_idx(), out_fd)) break;
    if (in_fd == out_fd) break;
    if (!writable_now(out_fd)) break;
    off_t cap = max_file_cap_bytes();
    off_t in_off  = static_cast<off_t>(
        std::min<uint64_t>(m.in_off(),  static_cast<uint64_t>(cap)));
    off_t out_off = static_cast<off_t>(
        std::min<uint64_t>(m.out_off(), static_cast<uint64_t>(cap)));
    size_t len = clampu32(m.len(), 1, 1u << 14);
    len = clamp_fd_write_len(out_fd, len);
    if (len == 0)
      break;
    (void)::copy_file_range(in_fd,  m.use_in_off()  ? &in_off  : nullptr,
                            out_fd, m.use_out_off() ? &out_off : nullptr,
                            len, m.flags());
    break;
  }
  case Command::kSendfile: {
    const auto &m = c.sendfile();
    int in_fd = -1, out_fd = -1;
    if (!fd_at(m.in_fd_idx(),  in_fd))  break;
    if (!fd_at(m.out_fd_idx(), out_fd)) break;
    if (!writable_now(out_fd)) break;
    off_t off = static_cast<off_t>(
        std::min<uint64_t>(m.offset(), static_cast<uint64_t>(max_file_cap_bytes())));
    size_t len = clampu32(m.len(), 1, 1u << 14);
    len = clamp_fd_write_len(out_fd, len);
    if (len == 0)
      break;
    (void)::sendfile(out_fd, in_fd, m.use_offset() ? &off : nullptr, len);
    break;
  }
  case Command::kSplice: {
    const auto &m = c.splice();
    int in_fd = -1, out_fd = -1;
    if (!fd_at(m.fd_in_idx(),  in_fd))  break;
    if (!fd_at(m.fd_out_idx(), out_fd)) break;
    if (in_fd == out_fd) break;
    if (!writable_now(out_fd) || !readable_now(in_fd)) break;
    loff_t off_in  = static_cast<loff_t>(m.off_in());
    loff_t off_out = static_cast<loff_t>(m.off_out());
    size_t len = clampu32(m.len(), 1, 1u << 14);
    unsigned int flags = m.flags() | SPLICE_F_NONBLOCK;
    (void)::splice(in_fd,  m.use_off_in()  ? &off_in  : nullptr,
                   out_fd, m.use_off_out() ? &off_out : nullptr,
                   len, flags);
    break;
  }
  case Command::kTee: {
    const auto &m = c.tee();
    int in_fd = -1, out_fd = -1;
    if (!fd_at(m.fd_in_idx(),  in_fd))  break;
    if (!fd_at(m.fd_out_idx(), out_fd)) break;
    if (in_fd == out_fd) break;
    if (!writable_now(out_fd) || !readable_now(in_fd)) break;
    size_t len = clampu32(m.len(), 1, 1u << 14);
    unsigned int flags = m.flags() | SPLICE_F_NONBLOCK;
    (void)::tee(in_fd, out_fd, len, flags);
    break;
  }
  case Command::kVmsplice: {
    const auto &m = c.vmsplice();
    int fd = -1;
    if (!fd_at(m.fd_idx(), fd)) break;
    if (!writable_now(fd)) break;
    int cnt = std::min(m.data_size(), 16);
    if (cnt <= 0) break;
    std::vector<struct iovec> iov(cnt);
    for (int n = 0; n < cnt; ++n) {
      const std::string &chunk = m.data(n);
      size_t chunk_len = std::min<size_t>(chunk.size(), 4096);
      iov[n].iov_base = const_cast<char *>(chunk.data());
      iov[n].iov_len  = chunk_len;
    }
    unsigned int flags = m.flags() | SPLICE_F_NONBLOCK;
    (void)::vmsplice(fd, iov.data(), iov.size(), flags);
    break;
  }
  case Command::kFadvise: {
    const auto &m = c.fadvise();
    int fd = -1;
    if (!fd_at(m.fd_idx(), fd)) break;
    off_t cap = max_file_cap_bytes();
    off_t off = static_cast<off_t>(
        std::min<uint64_t>(m.offset(), static_cast<uint64_t>(cap)));
    off_t len = static_cast<off_t>(
        std::min<uint64_t>(m.len(), static_cast<uint64_t>(cap)));
    (void)::posix_fadvise(fd, off, len, static_cast<int>(m.advice() % 6));
    break;
  }
  case Command::kReadahead: {
    const auto &m = c.readahead();
    int fd = -1;
    if (!fd_at(m.fd_idx(), fd)) break;
    off_t off = static_cast<off_t>(
        std::min<uint64_t>(m.offset(),
                           static_cast<uint64_t>(max_file_cap_bytes())));
    size_t cnt = clampu32(m.count(), 1, 1u << 14);
    (void)::readahead(fd, off, cnt);
    break;
  }
  case Command::kSyncFileRange: {
#ifndef FSFUZZ_AVOID_FSYNC
    const auto &m = c.sync_file_range();
    int fd = -1;
    if (!fd_at(m.fd_idx(), fd)) break;
    off_t off = static_cast<off_t>(m.offset());
    off_t nb  = static_cast<off_t>(m.nbytes());
    unsigned int flags = SYNC_FILE_RANGE_WRITE;  // never wait on completion
    (void)::sync_file_range(fd, off, nb, flags);
    (void)m;
#endif
    break;
  }
  case Command::kSyncfs: {
#ifndef FSFUZZ_AVOID_FSYNC
    const auto &m = c.syncfs();
    int fd = -1;
    if (!fd_at(m.fd_idx(), fd)) break;
    (void)::syncfs(fd);
#endif
    break;
  }
  case Command::kDup3: {
    const auto &m = c.dup3();
    int oldfd = -1, newfd = -1;
    if (!fd_at(m.old_fd_idx(), oldfd)) break;
    if (!fd_at(m.new_fd_idx(), newfd)) break;
    if (oldfd == newfd) break;
    if (is_protected_fd(oldfd) || is_protected_fd(newfd)) break;
    int fd = ::dup3(oldfd, newfd, m.flags() & O_CLOEXEC);
    if (fd >= 0)
      push_fd_capped(P, fd);
    break;
  }
  case Command::kMemfdCreate: {
    const auto &m = c.memfd_create();
    std::string nm = m.has_name() ? sanitize(m.name()) : std::string("fsfuzz");
    if (nm.empty()) nm = "fsfuzz";
    int fd = static_cast<int>(::syscall(SYS_memfd_create, nm.c_str(),
                                        static_cast<unsigned int>(m.flags())));
    if (fd >= 0)
      push_fd_capped(P, fd);
    break;
  }
  case Command::kCloseRange: {
    const auto &m = c.close_range();
    unsigned int first = std::max<unsigned int>(m.first(), 32);
    unsigned int last  = std::max(first, m.last());
    if (last - first > 64) last = first + 64;
    (void)::syscall(SYS_close_range, first, last,
                    static_cast<unsigned int>(m.flags()));
    break;
  }
  case Command::kStatx: {
    const auto &m = c.statx();
    int d = pick_dirfd(P, m.has_dirfd_idx() ? m.dirfd_idx() : -1);
    struct statx stx;
    (void)::syscall(SYS_statx, d, sanitize(m.name()).c_str(),
                    static_cast<int>(m.flags()),
                    static_cast<unsigned int>(m.mask()), &stx);
    break;
  }
  case Command::kPreadv: {
    const auto &m = c.preadv();
    size_t i;
    if (!take_fd_idx(P, m.fd_idx(), i))
      break;
    int fd = fd_from_slot(P, i);
    uint32_t iovcnt = clampu32(m.iovcnt(), 1, 16);
    uint32_t total  = clampu32(m.maxlen(), 1, 1u << 14);
    std::vector<std::string> bufs(iovcnt,
                                  std::string((total / iovcnt) + 1, '\0'));
    std::vector<struct iovec> iov(iovcnt);
    for (uint32_t n = 0; n < iovcnt; ++n) {
      iov[n].iov_base = bufs[n].data();
      iov[n].iov_len  = bufs[n].size();
    }
    off_t cap = max_file_cap_bytes();
    off_t off = static_cast<off_t>(
        std::min<uint64_t>(m.offset(), static_cast<uint64_t>(cap)));
    (void)::preadv(fd, iov.data(), static_cast<int>(iov.size()), off);
    break;
  }
  case Command::kPwritev: {
    const auto &m = c.pwritev();
    size_t i;
    if (!take_fd_idx(P, m.fd_idx(), i))
      break;
    int fd = fd_from_slot(P, i);
    if (!writable_now(fd))
      break;
    int cnt = std::min(m.data_size(), 16);
    if (cnt <= 0)
      break;
    std::vector<struct iovec> iov(cnt);
    size_t total_len = 0;
    for (int n = 0; n < cnt; ++n) {
      const std::string &chunk = m.data(n);
      size_t chunk_len = std::min<size_t>(chunk.size(), 4096);
      iov[n].iov_base = const_cast<char *>(chunk.data());
      iov[n].iov_len  = chunk_len;
      total_len += chunk_len;
    }
    total_len = clamp_fd_write_len(fd, total_len);
    if (total_len == 0)
      break;
    size_t remaining = total_len;
    int usable_cnt = cnt;
    for (int n = 0; n < cnt; ++n) {
      if (remaining == 0) { usable_cnt = n; break; }
      if (iov[n].iov_len > remaining) iov[n].iov_len = remaining;
      remaining -= iov[n].iov_len;
    }
    off_t cap = max_file_cap_bytes();
    off_t off = static_cast<off_t>(
        std::min<uint64_t>(m.offset(), static_cast<uint64_t>(cap)));
    if (usable_cnt > 0)
      (void)::pwritev(fd, iov.data(), usable_cnt, off);
    break;
  }
  case Command::kFdatasync: {
    const auto &m = c.fdatasync();
    int fd = -1;
    if (!fd_at(m.fd_idx(), fd))
      break;
#ifndef FSFUZZ_AVOID_FSYNC
    (void)::fdatasync(fd);
#endif
    break;
  }
  case Command::kMadvise: {
    const auto &m = c.madvise();
    Pools::Mapping *map = get_mapping(P, m.map_idx());
    if (!map || map->addr == MAP_FAILED)
      break;
    (void)::madvise(map->addr, map->len, static_cast<int>(m.advice()));
    break;
  }

  case Command::COMMAND_NOT_SET:
    break;
  }
}

#include <thread>

enum class RuntimeMode : uint8_t { Off = 0, Race = 1 };
enum class WorkerSemanticRole : uint8_t {
  SetupWatcher = 0,
  IoAioMmap = 1,
  PathMetadata = 2,
};
enum class InteractionObjectKind : uint8_t {
  Fd = 0,
  Dirfd = 1,
  Path = 2,
  Map = 3,
};
enum class InteractionOpClass : uint8_t {
  Other = 0,
  Watch = 1,
  Setup = 2,
  Io = 3,
  Aio = 4,
  Mapping = 5,
  PathMutation = 6,
  Metadata = 7,
  FdTransfer = 8,
};

struct RuntimeSettings {
  RuntimeMode mode = RuntimeMode::Race;
  int worker_count = 3;
  int hot_repeats = 2;
  bool enable_delay_injection = true;
  bool enable_object_replay = true;
  bool enable_interaction_tracking = true;
  bool enable_suspicious_log = false;
};

struct WorkerPlan {
  WorkerSemanticRole role = WorkerSemanticRole::SetupWatcher;
  int hot_repeats = 0;
  int worker_index = 0;
  bool consume_all_commands = false;
  const ThreadCommandList *thread_stream = nullptr;
};

struct InteractionAccess {
  WorkerSemanticRole role = WorkerSemanticRole::SetupWatcher;
  InteractionOpClass op_class = InteractionOpClass::Other;
};

struct Pools::InteractionTracker {
  std::mutex mu;
  std::unordered_map<uint64_t, InteractionAccess> last_access;
  std::unordered_set<uint64_t> seen_pairs;
  std::unordered_map<uint64_t, uint32_t> hot_object_scores;
  bool log_suspicious = false;
};

// One worker runs a full session against its own path state. In the threaded
// mode below, all workers attach to the same logical fd/dirfd/kqueue tables
// and the same filesystem root so they can race on shared kernel objects
// without racing the user-space slot bookkeeping.
static std::string command_message_name(const Command &cmd) {
  const auto *desc = cmd.GetDescriptor();
  const auto *oneof = desc ? desc->FindOneofByName("command") : nullptr;
  const auto *refl = cmd.GetReflection();
  const auto *field =
      (oneof && refl) ? refl->GetOneofFieldDescriptor(cmd, oneof) : nullptr;
  return field ? std::string(field->name()) : std::string("unknown");
}

class DeterministicPhaseBarrier {
public:
  explicit DeterministicPhaseBarrier(int parties) : parties_(parties) {}

  void ArriveAndWait() {
    std::unique_lock<std::mutex> lock(mu_);
    const int generation = generation_;
    if (++arrived_ == parties_) {
      arrived_ = 0;
      ++generation_;
      cv_.notify_all();
      return;
    }
    cv_.wait(lock, [&] { return generation_ != generation; });
  }

private:
  std::mutex mu_;
  std::condition_variable cv_;
  int parties_ = 0;
  int arrived_ = 0;
  int generation_ = 0;
};

static WorkerSemanticRole worker_role_from_hint(uint32_t hint) {
  switch (hint) {
  case ROLE_IO_AIO_MMAP:
    return WorkerSemanticRole::IoAioMmap;
  case ROLE_PATH_METADATA:
    return WorkerSemanticRole::PathMetadata;
  case ROLE_SETUP_WATCHER:
  default:
    return WorkerSemanticRole::SetupWatcher;
  }
}

static uint32_t worker_role_to_hint(WorkerSemanticRole role) {
  switch (role) {
  case WorkerSemanticRole::IoAioMmap:
    return ROLE_IO_AIO_MMAP;
  case WorkerSemanticRole::PathMetadata:
    return ROLE_PATH_METADATA;
  case WorkerSemanticRole::SetupWatcher:
  default:
    return ROLE_SETUP_WATCHER;
  }
}

static const char *worker_role_name(WorkerSemanticRole role) {
  switch (role) {
  case WorkerSemanticRole::SetupWatcher:
    return "setup_watcher";
  case WorkerSemanticRole::IoAioMmap:
    return "io_aio_mmap";
  case WorkerSemanticRole::PathMetadata:
    return "path_metadata";
  }
  return "unknown";
}

static bool env_flag_enabled(const char *name) {
  const char *value = std::getenv(name);
  if (!value || value[0] == '\0')
    return false;
  return !(value[0] == '0' && value[1] == '\0');
}

static bool is_hot_command(const Command &cmd) {
  switch (cmd.command_case()) {
  case Command::kPoll:
  case Command::kLioListio:
  case Command::kAioRead:
  case Command::kAioWrite:
  case Command::kAioError:
  case Command::kAioReturn:
  case Command::kAioCancel:
  case Command::kRead:
  case Command::kWrite:
  case Command::kPread:
  case Command::kPwrite:
  case Command::kFtruncate:
  case Command::kFstat:
  case Command::kLseek:
  case Command::kFlock:
  case Command::kMmap:
  case Command::kMsync:
  case Command::kMprotect:
  case Command::kSendmsg:
  case Command::kRecvmsg:
    return true;
  default:
    return false;
  }
}

static InteractionOpClass command_op_class(const Command &cmd) {
  switch (cmd.command_case()) {
  case Command::kPoll:
  case Command::kReadlink:
  case Command::kReadlinkAt:
  case Command::kGetdents:
    return InteractionOpClass::Watch;

  case Command::kOpen:
  case Command::kOpenAt:
  case Command::kDup:
  case Command::kDup2:
  case Command::kFcntl:
  case Command::kPipe:
  case Command::kSocketpair:
  case Command::kMkdir:
  case Command::kMkdirAt:
  case Command::kRmdir:
  case Command::kChdir:
  case Command::kFchdir:
  case Command::kLink:
  case Command::kLinkAt:
  case Command::kSymlink:
  case Command::kSymlinkAt:
    return InteractionOpClass::Setup;

  case Command::kRead:
  case Command::kWrite:
  case Command::kPread:
  case Command::kPwrite:
  case Command::kReadv:
  case Command::kWritev:
  case Command::kLseek:
  case Command::kFsync:
  case Command::kFlock:
    return InteractionOpClass::Io;

  case Command::kAioRead:
  case Command::kAioWrite:
  case Command::kAioError:
  case Command::kAioReturn:
  case Command::kAioSuspend:
  case Command::kAioCancel:
  case Command::kAioFsync:
  case Command::kLioListio:
    return InteractionOpClass::Aio;

  case Command::kMmap:
  case Command::kMunmap:
  case Command::kMsync:
  case Command::kMprotect:
    return InteractionOpClass::Mapping;

  case Command::kRename:
  case Command::kRenameAt:
  case Command::kRenameAt2:
  case Command::kUnlink:
  case Command::kUnlinkAt:
  case Command::kTruncate:
  case Command::kFtruncate:
  case Command::kFallocate:
  case Command::kCopyFileRange:
  case Command::kSendfile:
    return InteractionOpClass::PathMutation;

  case Command::kStat:
  case Command::kLstat:
  case Command::kFstat:
  case Command::kFstatAt:
  case Command::kChmod:
  case Command::kFchmod:
  case Command::kFchmodAt:
  case Command::kChown:
  case Command::kLchown:
  case Command::kFchownAt:
  case Command::kAccess:
  case Command::kFaccessAt:
  case Command::kGetxattr:
  case Command::kFgetxattr:
  case Command::kSetxattr:
  case Command::kFsetxattr:
  case Command::kRemovexattr:
  case Command::kFremovexattr:
  case Command::kListxattr:
  case Command::kFlistxattr:
  case Command::kStatfs:
  case Command::kFstatfs:
  case Command::kMknod:
  case Command::kMknodAt:
  case Command::kMkfifo:
  case Command::kMkfifoAt:
  case Command::kUtimes:
  case Command::kUtimensat:
    return InteractionOpClass::Metadata;

  case Command::kSendmsg:
  case Command::kRecvmsg:
  case Command::kClose:
    return InteractionOpClass::FdTransfer;

  case Command::COMMAND_NOT_SET:
  default:
    return InteractionOpClass::Other;
  }
}

static bool command_matches_role(const Command &cmd, WorkerSemanticRole role) {
  switch (role) {
  case WorkerSemanticRole::SetupWatcher:
    return command_op_class(cmd) == InteractionOpClass::Watch ||
           command_op_class(cmd) == InteractionOpClass::Setup;
  case WorkerSemanticRole::IoAioMmap:
    return command_op_class(cmd) == InteractionOpClass::Io ||
           command_op_class(cmd) == InteractionOpClass::Aio ||
           command_op_class(cmd) == InteractionOpClass::Mapping ||
           command_op_class(cmd) == InteractionOpClass::FdTransfer;
  case WorkerSemanticRole::PathMetadata:
    return command_op_class(cmd) == InteractionOpClass::PathMutation ||
           command_op_class(cmd) == InteractionOpClass::Metadata;
  }
  return false;
}

static uint64_t interaction_object_key(InteractionObjectKind kind, uint32_t idx) {
  return (static_cast<uint64_t>(kind) << 56) | static_cast<uint64_t>(idx);
}

static void append_interaction_objects(const Command &cmd,
                                       std::vector<uint64_t> &objects) {
  auto add_fd = [&](uint32_t idx) {
    objects.push_back(interaction_object_key(InteractionObjectKind::Fd, idx));
  };
  auto add_dirfd = [&](uint32_t idx) {
    objects.push_back(interaction_object_key(InteractionObjectKind::Dirfd, idx));
  };
  auto add_path = [&](uint32_t idx) {
    objects.push_back(interaction_object_key(InteractionObjectKind::Path, idx));
  };
  auto add_map = [&](uint32_t idx) {
    objects.push_back(interaction_object_key(InteractionObjectKind::Map, idx));
  };

  switch (cmd.command_case()) {
  case Command::kOpen:
  case Command::kMkdir:
  case Command::kRmdir:
  case Command::kChdir:
  case Command::kUnlink:
  case Command::kStat:
  case Command::kLstat:
  case Command::kChmod:
  case Command::kChown:
  case Command::kLchown:
  case Command::kAccess:
  case Command::kGetxattr:
  case Command::kSetxattr:
  case Command::kRemovexattr:
  case Command::kListxattr:
  case Command::kTruncate:
  case Command::kStatfs:
  case Command::kMknod:
  case Command::kMkfifo:
  case Command::kUtimes:
    if (cmd.command_case() == Command::kOpen && cmd.open().has_path_idx())
      add_path(cmd.open().path_idx());
    else if (cmd.command_case() == Command::kMkdir && cmd.mkdir().has_path_idx())
      add_path(cmd.mkdir().path_idx());
    else if (cmd.command_case() == Command::kRmdir)
      add_path(cmd.rmdir().path_idx());
    else if (cmd.command_case() == Command::kChdir)
      add_path(cmd.chdir().path_idx());
    else if (cmd.command_case() == Command::kUnlink)
      add_path(cmd.unlink().path_idx());
    else if (cmd.command_case() == Command::kStat)
      add_path(cmd.stat().path_idx());
    else if (cmd.command_case() == Command::kLstat)
      add_path(cmd.lstat().path_idx());
    else if (cmd.command_case() == Command::kChmod)
      add_path(cmd.chmod().path_idx());
    else if (cmd.command_case() == Command::kChown)
      add_path(cmd.chown().path_idx());
    else if (cmd.command_case() == Command::kLchown)
      add_path(cmd.lchown().path_idx());
    else if (cmd.command_case() == Command::kAccess)
      add_path(cmd.access().path_idx());
    else if (cmd.command_case() == Command::kGetxattr)
      add_path(cmd.getxattr().path_idx());
    else if (cmd.command_case() == Command::kSetxattr)
      add_path(cmd.setxattr().path_idx());
    else if (cmd.command_case() == Command::kRemovexattr)
      add_path(cmd.removexattr().path_idx());
    else if (cmd.command_case() == Command::kListxattr)
      add_path(cmd.listxattr().path_idx());
    else if (cmd.command_case() == Command::kTruncate)
      add_path(cmd.truncate().path_idx());
    else if (cmd.command_case() == Command::kStatfs)
      add_path(cmd.statfs().path_idx());
    else if (cmd.command_case() == Command::kMknod && cmd.mknod().has_path_idx())
      add_path(cmd.mknod().path_idx());
    else if (cmd.command_case() == Command::kMkfifo && cmd.mkfifo().has_path_idx())
      add_path(cmd.mkfifo().path_idx());
    else if (cmd.command_case() == Command::kUtimes)
      add_path(cmd.utimes().path_idx());
    break;

  case Command::kClose:
    add_fd(cmd.close().fd_idx());
    break;
  case Command::kDup:
    add_fd(cmd.dup().fd_idx());
    break;
  case Command::kDup2:
    add_fd(cmd.dup2().old_fd_idx());
    add_fd(cmd.dup2().new_fd());
    break;
  case Command::kFcntl:
    add_fd(cmd.fcntl().fd_idx());
    break;
  case Command::kPoll:
    for (int i = 0; i < cmd.poll().fd_idx_size(); ++i)
      add_fd(cmd.poll().fd_idx(i));
    break;
  case Command::kOpenAt:
    if (cmd.open_at().has_dirfd_idx())
      add_dirfd(static_cast<uint32_t>(std::max(cmd.open_at().dirfd_idx(), 0)));
    break;
  case Command::kLink:
    add_path(cmd.link().existing_path_idx());
    if (cmd.link().has_new_path_idx())
      add_path(cmd.link().new_path_idx());
    break;
  case Command::kLinkAt:
    if (cmd.link_at().has_olddirfd_idx())
      add_dirfd(static_cast<uint32_t>(std::max(cmd.link_at().olddirfd_idx(), 0)));
    if (cmd.link_at().has_newdirfd_idx())
      add_dirfd(static_cast<uint32_t>(std::max(cmd.link_at().newdirfd_idx(), 0)));
    break;
  case Command::kUnlinkAt:
    if (cmd.unlink_at().has_dirfd_idx())
      add_dirfd(static_cast<uint32_t>(std::max(cmd.unlink_at().dirfd_idx(), 0)));
    break;
  case Command::kMkdirAt:
    if (cmd.mkdir_at().has_dirfd_idx())
      add_dirfd(static_cast<uint32_t>(std::max(cmd.mkdir_at().dirfd_idx(), 0)));
    break;
  case Command::kFchdir:
  case Command::kFstat:
  case Command::kFchmod:
  case Command::kFgetxattr:
  case Command::kFsetxattr:
  case Command::kFremovexattr:
  case Command::kFlistxattr:
  case Command::kRead:
  case Command::kWrite:
  case Command::kPread:
  case Command::kPwrite:
  case Command::kReadv:
  case Command::kWritev:
  case Command::kAioRead:
  case Command::kAioWrite:
  case Command::kAioCancel:
  case Command::kFtruncate:
  case Command::kFsync:
  case Command::kFlock:
  case Command::kFstatfs:
  case Command::kMmap:
  case Command::kSendmsg:
  case Command::kRecvmsg:
    switch (cmd.command_case()) {
    case Command::kFchdir: add_fd(cmd.fchdir().fd_idx()); break;
    case Command::kFstat: add_fd(cmd.fstat().fd_idx()); break;
    case Command::kFchmod: add_fd(cmd.fchmod().fd_idx()); break;
    case Command::kFgetxattr: add_fd(cmd.fgetxattr().fd_idx()); break;
    case Command::kFsetxattr: add_fd(cmd.fsetxattr().fd_idx()); break;
    case Command::kFremovexattr: add_fd(cmd.fremovexattr().fd_idx()); break;
    case Command::kFlistxattr: add_fd(cmd.flistxattr().fd_idx()); break;
    case Command::kRead: add_fd(cmd.read().fd_idx()); break;
    case Command::kWrite: add_fd(cmd.write().fd_idx()); break;
    case Command::kPread: add_fd(cmd.pread().fd_idx()); break;
    case Command::kPwrite: add_fd(cmd.pwrite().fd_idx()); break;
    case Command::kReadv: add_fd(cmd.readv().fd_idx()); break;
    case Command::kWritev: add_fd(cmd.writev().fd_idx()); break;
    case Command::kAioRead: add_fd(cmd.aio_read().fd_idx()); break;
    case Command::kAioWrite: add_fd(cmd.aio_write().fd_idx()); break;
    case Command::kAioCancel: add_fd(cmd.aio_cancel().fd_idx()); break;
    case Command::kFtruncate: add_fd(cmd.ftruncate().fd_idx()); break;
    case Command::kFsync: add_fd(cmd.fsync().fd_idx()); break;
    case Command::kFlock: add_fd(cmd.flock().fd_idx()); break;
    case Command::kFstatfs: add_fd(cmd.fstatfs().fd_idx()); break;
    case Command::kMmap: add_fd(cmd.mmap().fd_idx()); break;
    case Command::kSendmsg: add_fd(cmd.sendmsg().sock_fd_idx()); if (cmd.sendmsg().send_rights()) add_fd(cmd.sendmsg().rights_fd_idx()); break;
    case Command::kRecvmsg: add_fd(cmd.recvmsg().sock_fd_idx()); break;
    default: break;
    }
    break;
  case Command::kLioListio:
    for (int i = 0; i < cmd.lio_listio().entries_size(); ++i)
      add_fd(cmd.lio_listio().entries(i).fd_idx());
    break;
  case Command::kMunmap:
    add_map(cmd.munmap().map_idx());
    break;
  case Command::kMsync:
    add_map(cmd.msync().map_idx());
    break;
  case Command::kMprotect:
    add_map(cmd.mprotect().map_idx());
    break;
  case Command::kRename:
    add_path(cmd.rename().old_path_idx());
    if (cmd.rename().has_new_path_idx())
      add_path(cmd.rename().new_path_idx());
    break;
  case Command::kRenameAt:
    if (cmd.rename_at().has_olddirfd_idx())
      add_dirfd(static_cast<uint32_t>(std::max(cmd.rename_at().olddirfd_idx(), 0)));
    if (cmd.rename_at().has_newdirfd_idx())
      add_dirfd(static_cast<uint32_t>(std::max(cmd.rename_at().newdirfd_idx(), 0)));
    break;
  case Command::kRenameAt2:
    if (cmd.rename_at2().has_olddirfd_idx())
      add_dirfd(static_cast<uint32_t>(std::max(cmd.rename_at2().olddirfd_idx(), 0)));
    if (cmd.rename_at2().has_newdirfd_idx())
      add_dirfd(static_cast<uint32_t>(std::max(cmd.rename_at2().newdirfd_idx(), 0)));
    break;
  case Command::kFstatAt:
    if (cmd.fstat_at().has_dirfd_idx())
      add_dirfd(static_cast<uint32_t>(std::max(cmd.fstat_at().dirfd_idx(), 0)));
    break;
  case Command::kFchmodAt:
    if (cmd.fchmod_at().has_dirfd_idx())
      add_dirfd(static_cast<uint32_t>(std::max(cmd.fchmod_at().dirfd_idx(), 0)));
    break;
  case Command::kFchownAt:
    if (cmd.fchown_at().has_dirfd_idx())
      add_dirfd(static_cast<uint32_t>(std::max(cmd.fchown_at().dirfd_idx(), 0)));
    break;
  case Command::kFaccessAt:
    if (cmd.faccess_at().has_dirfd_idx())
      add_dirfd(static_cast<uint32_t>(std::max(cmd.faccess_at().dirfd_idx(), 0)));
    break;
  case Command::kMknodAt:
    if (cmd.mknod_at().has_dirfd_idx())
      add_dirfd(static_cast<uint32_t>(std::max(cmd.mknod_at().dirfd_idx(), 0)));
    break;
  case Command::kMkfifoAt:
    if (cmd.mkfifo_at().has_dirfd_idx())
      add_dirfd(static_cast<uint32_t>(std::max(cmd.mkfifo_at().dirfd_idx(), 0)));
    break;
  case Command::kLseek:
    add_fd(cmd.lseek().fd_idx());
    break;
  case Command::COMMAND_NOT_SET:
    break;
  default:
    break;
  }
}

static bool tracker_has_hot_objects(const std::shared_ptr<Pools::InteractionTracker> &tracker) {
  if (!tracker)
    return false;
  std::lock_guard<std::mutex> lock(tracker->mu);
  return !tracker->hot_object_scores.empty();
}

static bool tracker_object_is_hot(const std::shared_ptr<Pools::InteractionTracker> &tracker,
                                  uint64_t object_key) {
  if (!tracker)
    return false;
  std::lock_guard<std::mutex> lock(tracker->mu);
  auto it = tracker->hot_object_scores.find(object_key);
  return it != tracker->hot_object_scores.end() && it->second > 0;
}

static void track_command_interaction(const Command &cmd, const WorkerPlan &plan,
                                      const std::shared_ptr<Pools::InteractionTracker> &tracker) {
  if (!tracker)
    return;
  std::vector<uint64_t> objects;
  append_interaction_objects(cmd, objects);
  if (objects.empty())
    return;

  const InteractionAccess current{plan.role, command_op_class(cmd)};
  std::lock_guard<std::mutex> lock(tracker->mu);
  for (uint64_t object_key : objects) {
    auto prev = tracker->last_access.find(object_key);
    if (prev != tracker->last_access.end() &&
        prev->second.role != current.role &&
        prev->second.op_class != current.op_class) {
      const uint64_t pair_key =
          object_key ^ (static_cast<uint64_t>(prev->second.role) << 40) ^
          (static_cast<uint64_t>(current.role) << 32) ^
          (static_cast<uint64_t>(prev->second.op_class) << 24) ^
          (static_cast<uint64_t>(current.op_class) << 16);
      if (tracker->seen_pairs.insert(pair_key).second) {
        libfuzzer_coverage[pair_key % sizeof(libfuzzer_coverage)]++;
      }
      tracker->hot_object_scores[object_key]++;
      if (tracker->log_suspicious) {
        std::fprintf(stderr,
                     "suspicious interaction: obj=0x%llx %s/%d -> %s/%d via %s\n",
                     static_cast<unsigned long long>(object_key),
                     worker_role_name(prev->second.role),
                     static_cast<int>(prev->second.op_class),
                     worker_role_name(current.role),
                     static_cast<int>(current.op_class),
                     command_message_name(cmd).c_str());
      }
    }
    tracker->last_access[object_key] = current;
  }
}

static uint32_t default_delay_seed(const Session &sess) {
  uint32_t seed = 0x9e3779b9u;
  if (sess.has_data_provider()) {
    for (unsigned char byte : sess.data_provider())
      seed = (seed * 16777619u) ^ static_cast<uint32_t>(byte);
  }
  seed ^= static_cast<uint32_t>(sess.commands_size() * 1315423911u);
  return seed;
}

static void maybe_inject_delay(const Session &sess, const Command &cmd,
                               int command_index, const WorkerPlan &plan,
                               const RuntimeSettings &settings) {
  if (!settings.enable_delay_injection || !is_hot_command(cmd))
    return;
  uint32_t seed = sess.has_delay_seed() ? sess.delay_seed() : default_delay_seed(sess);
  seed ^= static_cast<uint32_t>(command_index * 0x45d9f3bu);
  seed ^= static_cast<uint32_t>(plan.worker_index * 0x27d4eb2du);
  seed ^= static_cast<uint32_t>(worker_role_to_hint(plan.role) * 0x85ebca6bu);
  seed ^= static_cast<uint32_t>(cmd.command_case() * 0xc2b2ae35u);
  const uint32_t yields = seed & 0x7u;
  for (uint32_t i = 0; i < yields; ++i)
    std::this_thread::yield();
}

static RuntimeSettings runtime_settings_for_session(const Session &sess) {
  RuntimeSettings settings;
  settings.mode = RuntimeMode::Race;
  settings.worker_count = 3;
  settings.hot_repeats = 2;
  settings.enable_delay_injection = true;
  settings.enable_object_replay = true;
  settings.enable_interaction_tracking = true;

  if (sess.has_concurrency_mode() &&
      sess.concurrency_mode() == CONCURRENCY_MODE_FAST) {
    settings.mode = RuntimeMode::Off;
    settings.worker_count = 1;
    settings.hot_repeats = 0;
    settings.enable_delay_injection = false;
    settings.enable_object_replay = false;
    settings.enable_interaction_tracking = false;
  }

  const char *env = std::getenv("FSFUZZ_CONCURRENCY_MODE");
  if (env && std::strcmp(env, "off") == 0) {
    settings.mode = RuntimeMode::Off;
    settings.worker_count = 1;
    settings.hot_repeats = 0;
    settings.enable_delay_injection = false;
    settings.enable_object_replay = false;
    settings.enable_interaction_tracking = false;
  } else if (env && std::strcmp(env, "race") == 0) {
    settings.mode = RuntimeMode::Race;
    settings.worker_count = 3;
    settings.hot_repeats = 2;
    settings.enable_delay_injection = true;
    settings.enable_object_replay = true;
    settings.enable_interaction_tracking = true;
  }
  settings.enable_suspicious_log = env_flag_enabled("FSFUZZ_LOG_SUSPICIOUS");
  return settings;
}

static const ThreadCommandList *select_thread_stream(const Session &sess,
                                                     WorkerSemanticRole role,
                                                     int fallback_index) {
  for (int i = 0; i < sess.thread_streams_size(); ++i) {
    if (worker_role_from_hint(sess.thread_streams(i).worker_role()) == role)
      return &sess.thread_streams(i);
  }
  if (fallback_index >= 0 && fallback_index < sess.thread_streams_size())
    return &sess.thread_streams(fallback_index);
  return nullptr;
}

static bool worker_owns_command(const WorkerPlan &plan, const Command &cmd) {
  if (plan.thread_stream || plan.consume_all_commands)
    return true;
  return command_matches_role(cmd, plan.role);
}

static bool should_replay_command(const Command &cmd,
                                  const RuntimeSettings &settings,
                                  const std::shared_ptr<Pools::InteractionTracker> &tracker) {
  if (!is_hot_command(cmd))
    return false;
  if (!settings.enable_object_replay || !tracker)
    return true;
  std::vector<uint64_t> objects;
  append_interaction_objects(cmd, objects);
  if (objects.empty())
    return !tracker_has_hot_objects(tracker);
  for (uint64_t object_key : objects) {
    if (tracker_object_is_hot(tracker, object_key))
      return true;
  }
  return !tracker_has_hot_objects(tracker);
}

static void run_worker_once(const Session &sess, const uint8_t *dp, size_t dlen,
                            const std::string *shared_root_path = nullptr,
                            int shared_root_fd = -1,
                            WorkerPlan plan = WorkerPlan{},
                            DeterministicPhaseBarrier *phase_barrier = nullptr,
                            std::shared_ptr<Pools::SharedState> shared_state =
                                nullptr,
                            RuntimeSettings settings = RuntimeSettings{}) {
  ScopedProcessState process_state;
  Pools P; // per-thread pools
  if (shared_root_path && shared_root_fd >= 0)
    attach_workspace(P, *shared_root_path, shared_root_fd,
                     std::move(shared_state));
  else
    seed_workspace(P);
  FuzzedDataProvider fdp(dp, dlen);

  if (phase_barrier)
    phase_barrier->ArriveAndWait();

  auto execute_command = [&](const Command &command, int command_index) {
    if (!worker_owns_command(plan, command))
      return;
    maybe_inject_delay(sess, command, command_index, plan, settings);
    if (settings.enable_interaction_tracking && P.shared_state &&
        P.shared_state->interaction_tracker) {
      track_command_interaction(command, plan, P.shared_state->interaction_tracker);
    }
    do_command(command, P, fdp);
  };

  if (plan.thread_stream) {
    for (int i = 0; i < plan.thread_stream->commands_size(); ++i)
      execute_command(plan.thread_stream->commands(i), i);
  } else {
    for (int i = 0; i < sess.commands_size(); ++i)
      execute_command(sess.commands(i), i);
  }

  if (phase_barrier)
    phase_barrier->ArriveAndWait();

  for (int repeat = 0; repeat < plan.hot_repeats; ++repeat) {
    if (plan.thread_stream) {
      for (int i = 0; i < plan.thread_stream->commands_size(); ++i) {
        const auto &command = plan.thread_stream->commands(i);
        if (!should_replay_command(command, settings,
                                   P.shared_state ? P.shared_state->interaction_tracker : nullptr))
          continue;
        execute_command(command, i);
      }
    } else {
      for (int i = 0; i < sess.commands_size(); ++i) {
        const auto &command = sess.commands(i);
        if (!worker_owns_command(plan, command))
          continue;
        if (!should_replay_command(command, settings,
                                   P.shared_state ? P.shared_state->interaction_tracker : nullptr))
          continue;
        execute_command(command, i);
      }
    }
    if (phase_barrier)
      phase_barrier->ArriveAndWait();
  }

  cleanup_session(P);
}

static void absolutize_input_paths(int *argc, char ***argv) {
  if (!argc || !argv || !*argv)
    return;
  std::error_code ec;
  for (int i = 1; i < *argc; ++i) {
    char *arg = (*argv)[i];
    if (!arg || !*arg || arg[0] == '-')
      continue;
    fs::path abs = fs::absolute(fs::path(arg), ec);
    if (ec)
      continue;
    std::string value = abs.string();
    char *copy = strdup(value.c_str());
    if (copy)
      (*argv)[i] = copy;
  }
}

static void run_fs_session(const Session &sess) {
  const RuntimeSettings settings = runtime_settings_for_session(sess);
  const uint8_t *dp =
      sess.has_data_provider()
          ? reinterpret_cast<const uint8_t *>(sess.data_provider().data())
          : nullptr;
  const size_t dlen =
      sess.has_data_provider() ? sess.data_provider().size() : 0;

  if (settings.mode == RuntimeMode::Off) {
    WorkerPlan plan;
    plan.consume_all_commands = true;
    plan.hot_repeats = settings.hot_repeats;
    run_worker_once(sess, dp, dlen, nullptr, -1, plan, nullptr, nullptr, settings);
    return;
  }

  constexpr int kWorkerCount = 3;
  Pools shared;
  shared.shared_state = std::make_shared<Pools::SharedState>();
  shared.shared_state->interaction_tracker =
      std::make_shared<Pools::InteractionTracker>();
  shared.shared_state->interaction_tracker->log_suspicious =
      settings.enable_suspicious_log;
  seed_workspace(shared);
  DeterministicPhaseBarrier phase_barrier(kWorkerCount);
  const std::array<WorkerPlan, kWorkerCount> plans = {{
      {WorkerSemanticRole::SetupWatcher, settings.hot_repeats, 0, false,
       select_thread_stream(sess, WorkerSemanticRole::SetupWatcher, 0)},
      {WorkerSemanticRole::IoAioMmap, settings.hot_repeats, 1, false,
       select_thread_stream(sess, WorkerSemanticRole::IoAioMmap, 1)},
      {WorkerSemanticRole::PathMetadata, settings.hot_repeats, 2, false,
       select_thread_stream(sess, WorkerSemanticRole::PathMetadata, 2)},
  }};

  std::thread t0([&] {
    run_worker_once(sess, dp, dlen, &shared.root_path, shared.root_dirfd,
                    plans[0], &phase_barrier, shared.shared_state, settings);
  });
  std::thread t1([&] {
    run_worker_once(sess, dp, dlen, &shared.root_path, shared.root_dirfd,
                    plans[1], &phase_barrier, shared.shared_state, settings);
  });
  run_worker_once(sess, dp, dlen, &shared.root_path, shared.root_dirfd,
                  plans[2], &phase_barrier, shared.shared_state, settings);
  t0.join();
  t1.join();

  cleanup_session(shared);
}

static bool full_write(int fd, const void *buf, size_t len) {
  const char *p = static_cast<const char *>(buf);
  while (len > 0) {
    ssize_t n = write(fd, p, len);
    if (n < 0) {
      if (errno == EINTR)
        continue;
      return false;
    }
    if (n == 0)
      return false;
    p += n;
    len -= static_cast<size_t>(n);
  }
  return true;
}


// Atomic, durable PoC writer. mkstemp's a sibling of `final_path` in the
// same directory so rename(2) is guaranteed atomic, fsyncs the file's data,
// renames into place, then fsyncs the directory so the new dirent itself is
// durable. Returns false on any I/O failure (the tmp file is unlinked).
static bool atomic_write_file(const std::string &dir,
                              const std::string &final_path,
                              const uint8_t *data, size_t size) {
  std::string tmpl = dir + "/.rec_XXXXXX";
  std::vector<char> buf(tmpl.begin(), tmpl.end());
  buf.push_back('\0');

  int fd = mkstemp(buf.data());
  if (fd < 0)
    return false;
  std::string tmp_path(buf.data());

  bool ok = full_write(fd, data, size);
  if (ok)
    ok = fsync(fd) == 0;
  close(fd);

  if (!ok || rename(tmp_path.c_str(), final_path.c_str()) != 0) {
    unlink(tmp_path.c_str());
    return false;
  }

  // Make the new directory entry itself durable.
  int dir_fd = open(dir.c_str(), O_RDONLY | O_DIRECTORY);
  if (dir_fd >= 0) {
    (void)fsync(dir_fd);
    close(dir_fd);
  }
  return true;
}

// Rolling-buffer PoC writer. Each call gets a fresh, monotonically-increasing
// sequence number; we keep the last kSlots files on disk and unlink the rest.
// atomic_write_file is invoked twice on the same path — the first call makes
// the input visible, the second call re-fsyncs everything so the data hits
// disk *before* the harness starts mutating the filesystem under it.
static void save_input_for_recovery(const uint8_t *data, size_t size) {
  static std::atomic<uint64_t> seq{0};
  static const std::string dir = "/home/mfirouz/testfuzz/poc_generated";
  constexpr uint64_t kSlots = 100;

  std::error_code ec;
  if (!fs::create_directories(dir, ec) && ec)
    return;

  const uint64_t cur = seq.fetch_add(1, std::memory_order_relaxed);
  const std::string path =
      dir + "/last_input_" + std::to_string(cur) + ".pb";

  (void)atomic_write_file(dir, path, data, size);
  (void)atomic_write_file(dir, path, data, size);

  if (cur >= kSlots) {
    const std::string old =
        dir + "/last_input_" + std::to_string(cur - kSlots) + ".pb";
    (void)unlink(old.c_str());
  }
}

static void save_input_for_recovery(const Session &sess) {
  std::string data;
  if (!sess.SerializeToString(&data))
    return;
  save_input_for_recovery(reinterpret_cast<const uint8_t *>(data.data()),
                          data.size());
}

static int get_child_timeout_ms() {
  return 200;
}

[[noreturn]] static void run_one_input_in_child(const Session &sess);

// ===============================================================
// kcov coverage collector interface
// ===============================================================
//
// kcov is per-task: only the task that called KCOV_ENABLE on a given fd can
// write to that fd's buffer, and the buffer is only readable by the same task
// (we cannot mmap it in the parent and read child coverage from there, the way
// the previous Pishi setup did). So the child opens kcov, arms it, runs the
// testcase, then folds the captured PCs into a MAP_SHARED|MAP_ANONYMOUS region
// allocated in the parent before fork(). After waitpid(), the parent merges
// that shared region into libfuzzer_coverage so libFuzzer can see it.

#define KCOV_COVER_SIZE (256 << 10)
#define KCOV_TRACE_PC 0
#define KCOV_INIT_TRACE64 _IOR('c', 1, uint64_t)
#define KCOV_ENABLE _IO('c', 100)
#define KCOV_DISABLE _IO('c', 101)

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif

static uint64_t *kcov_data = nullptr;
static unsigned char *g_kcov_shared = nullptr;
static const size_t g_kcov_shared_size = sizeof(libfuzzer_coverage);

// DEBUG_KCOV=1: ship the raw PC list from child to parent so the parent can
// log every newly-hit basic block. The buffer layout is identical to the
// kcov(2) buffer (slot 0 = count, slots [1..count] = PCs), which makes the
// child-side memcpy a one-liner.
static bool g_debug_kcov = false;
static uint64_t *g_kcov_pcbuf = nullptr;  // [0]=count, [1..]=PCs
static constexpr size_t kKcovPCBufEntries = KCOV_COVER_SIZE;

static void kcov_fail(const char *msg) {
  int e = errno;
  fprintf(stderr, "%s (errno %d)\n", msg, e);
  _exit(1);
}

// Parent: allocate the cross-process coverage buffer once, before any fork().
static void kcov_setup_shared() {
  void *p = mmap(nullptr, g_kcov_shared_size, PROT_READ | PROT_WRITE,
                 MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (p == MAP_FAILED) {
    fprintf(stderr, "kcov shared mmap failed (errno %d)\n", errno);
    exit(1);
  }
  g_kcov_shared = (unsigned char *)p;

  if (const char *env = std::getenv("DEBUG_KCOV"); env && *env && *env != '0') {
    g_debug_kcov = true;
    const size_t bytes = kKcovPCBufEntries * sizeof(uint64_t);
    void *pc = mmap(nullptr, bytes, PROT_READ | PROT_WRITE,
                    MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (pc == MAP_FAILED) {
      fprintf(stderr, "kcov pc-buf mmap failed (errno %d)\n", errno);
      exit(1);
    }
    g_kcov_pcbuf = (uint64_t *)pc;
    g_kcov_pcbuf[0] = 0;
    fprintf(stderr, "[kcov] DEBUG_KCOV=1: logging new basic blocks to stderr\n");
  }
}

// Child: open /sys/kernel/debug/kcov and mmap the per-task PC buffer.
static void kcov_init() {
  kcov_fd = open("/sys/kernel/debug/kcov", O_RDWR);
  if (kcov_fd == -1)
    kcov_fail("open kcov failed");
  if (ioctl(kcov_fd, KCOV_INIT_TRACE64, KCOV_COVER_SIZE))
    kcov_fail("KCOV_INIT failed");
  kcov_data = (uint64_t *)mmap(nullptr, KCOV_COVER_SIZE * sizeof(uint64_t),
                               PROT_READ | PROT_WRITE, MAP_SHARED, kcov_fd, 0);
  if (kcov_data == MAP_FAILED)
    kcov_fail("kcov mmap failed");
}

// Child: zero counter and arm coverage on this task.
static void kcov_start() {
  __atomic_store_n(&kcov_data[0], 0, __ATOMIC_RELAXED);
  if (ioctl(kcov_fd, KCOV_ENABLE, KCOV_TRACE_PC))
    kcov_fail("KCOV_ENABLE failed");
}

// Child: disable kcov, then fold collected PCs into the shared buffer that
// the parent will merge into libfuzzer_coverage.
static void kcov_stop() {
  uint64_t n = __atomic_load_n(&kcov_data[0], __ATOMIC_RELAXED);
  if (ioctl(kcov_fd, KCOV_DISABLE, 0))
    kcov_fail("KCOV_DISABLE failed");
  if (n > KCOV_COVER_SIZE - 1)
    n = KCOV_COVER_SIZE - 1;
  for (uint64_t i = 0; i < n; i++) {
    uint64_t pc = kcov_data[i + 1];
    size_t idx = (size_t)(pc % g_kcov_shared_size);
    unsigned char cur =
        __atomic_load_n(&g_kcov_shared[idx], __ATOMIC_RELAXED);
    if (cur < 255)
      __atomic_fetch_add(&g_kcov_shared[idx], 1, __ATOMIC_RELAXED);
  }
  // Debug mode: copy raw PCs to the parent-visible buffer so kcov_merge() can
  // diff against the running "seen" set and log new BBs.
  if (g_debug_kcov && g_kcov_pcbuf) {
    const uint64_t cap = kKcovPCBufEntries - 1;
    const uint64_t take = n > cap ? cap : n;
    for (uint64_t i = 0; i < take; i++)
      g_kcov_pcbuf[i + 1] = kcov_data[i + 1];
    __atomic_store_n(&g_kcov_pcbuf[0], take, __ATOMIC_RELEASE);
  }
}

// Parent: merge the child's coverage out of the shared buffer into
// libfuzzer_coverage and clear it for the next iteration.
static void kcov_merge() {
  if (!g_kcov_shared)
    return;
  for (size_t i = 0; i < g_kcov_shared_size; i++) {
    unsigned char v = g_kcov_shared[i];
    if (v) {
      int sum = (int)libfuzzer_coverage[i] + (int)v;
      if (sum > 255)
        sum = 255;
      libfuzzer_coverage[i] = (unsigned char)sum;
      g_kcov_shared[i] = 0;
    }
  }

  if (g_debug_kcov && g_kcov_pcbuf) {
    static std::unordered_set<uint64_t> seen;
    static std::atomic<uint64_t> g_total_new{0};
    const uint64_t n =
        __atomic_load_n(&g_kcov_pcbuf[0], __ATOMIC_ACQUIRE);
    uint64_t new_in_iter = 0;
    for (uint64_t i = 0; i < n; i++) {
      uint64_t pc = g_kcov_pcbuf[i + 1];
      if (seen.insert(pc).second) {
        ++new_in_iter;
        fprintf(stderr, "[kcov] new BB: 0x%016llx\n",
                static_cast<unsigned long long>(pc));
      }
    }
    if (new_in_iter) {
      const uint64_t total =
          g_total_new.fetch_add(new_in_iter, std::memory_order_relaxed) +
          new_in_iter;
      fprintf(stderr,
              "[kcov] iter: %llu PCs total, %llu new, %llu unique BBs seen\n",
              static_cast<unsigned long long>(n),
              static_cast<unsigned long long>(new_in_iter),
              static_cast<unsigned long long>(total));
    }
    __atomic_store_n(&g_kcov_pcbuf[0], 0, __ATOMIC_RELAXED);
  }
}

[[noreturn]] static void run_one_input_in_child(const Session &sess) {
  // The child executes the fuzz input in isolation so the parent can enforce
  // a hard timeout, and arms kcov on itself for the duration of the input so
  // the captured PCs cover only this testcase.
  ignore_all_child_signals();
  run_fs_session(sess);
  kcov_stop();
  _exit(0);
}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
  absolutize_input_paths(argc, argv);
  initialize_sandbox_tmp_root();
  g_initial_cwd_fd = open(sandbox_tmp_root().c_str(), O_RDONLY | O_DIRECTORY);
  if (g_initial_cwd_fd < 0) {
    fprintf(stderr, "fsfuzz: open sandbox tmp root '%s' failed: %s\n",
            sandbox_tmp_root().c_str(), strerror(errno));
    exit(1);
  }
  set_cloexec(g_initial_cwd_fd);
  g_initial_umask = ::umask(022);
  (void)::umask(g_initial_umask);
  ignore_sigxfsz();
  ignore_sigpipe();
  ignore_async_aio_signals();
  set_rlimits();
  kcov_setup_shared();
  return 0;
}



DEFINE_BINARY_PROTO_FUZZER(const Session &s) {
  save_input_for_recovery(s);
  
  #ifdef LOG_COMMAND
  for (int i = 0; i < s.commands_size(); ++i) {
    std::string name = command_message_name(s.commands(i));
    std::fprintf(stderr, "command[%d]: %s\n", i, name.c_str());
  }
  #endif

  // Parent/child synchronization pipe:
  // the child blocks on read() until the parent releases it, then the child
  // arms kcov for itself before running the testcase.
  int sync_pipe[2] = {-1, -1};
  if (pipe(sync_pipe) != 0) {
    perror("pipe");
    return;
  }

  pid_t pid = fork();
  if (pid == 0) {
    // Child process:
    // wait for release, arm coverage for this child task, then run exactly
    // one fuzz input and exit without returning to libFuzzer's loop.
    close(sync_pipe[1]);
    char ready = 0;
    if (read(sync_pipe[0], &ready, 1) != 1)
      _exit(1);
    close(sync_pipe[0]);

    kcov_init();
    kcov_start();
    run_one_input_in_child(s);
  }
  if (pid < 0) {
    // Fork failed, so there is no child to execute this input.
    close(sync_pipe[0]);
    close(sync_pipe[1]);
    perror("fork");
    return;
  }

  // Parent process:
  // release the child once setup is complete; the child arms kcov on itself
  // immediately before executing the input and dumps coverage into the shared
  // buffer before _exit().
  close(sync_pipe[0]);
  const char ready = 1;
  if (write(sync_pipe[1], &ready, 1) != 1) {
    // If we cannot release the child, terminate it so we do not leave a stuck
    // subprocess behind, then merge whatever coverage is in the shared buffer.
    close(sync_pipe[1]);
    kill(pid, SIGKILL);
    (void)waitpid(pid, nullptr, 0);
    perror("write");
    kcov_merge();
    return;
  }
  close(sync_pipe[1]);

  int status = 0;
  int waited_ms = 0;
  const int sleep_us = 1000;
  const int timeout_ms = get_child_timeout_ms();

  // Poll for child completion with 1ms granularity. If the input runs longer
  // than 2 seconds, the parent kills it to keep the fuzzer responsive.
  bool child_timed_out = false;
  for (;;) {
    pid_t rv = waitpid(pid, &status, WNOHANG);
    if (rv == pid)
      break;
    if (rv == -1) {
      if (errno == EINTR)
        continue; // interrupted — retry without advancing the timeout
      // Unexpected error: kill child to guarantee it does not outlive us.
      perror("waitpid");
      kill(pid, SIGKILL);
      (void)waitpid(pid, nullptr, 0);
      kcov_merge();
      return;
    }
    if (waited_ms >= timeout_ms) {
      child_timed_out = true;
      kill(pid, SIGKILL);
      (void)waitpid(pid, &status, 0); // blocking — child is dead after this
      break;
    }
    usleep(sleep_us);
    waited_ms += 1;
  }

  // Merge child kcov coverage from the shared buffer only after the child is
  // confirmed dead, so we capture everything it executed for this input.
  kcov_merge();

  if (WIFSIGNALED(status)) {
    if (child_timed_out) {
      std::fprintf(stderr,
                   "fork_base: child timed out after %d ms, killed with SIGKILL\n",
                   timeout_ms);
    } else {
      std::fprintf(stderr, "fork_base: child terminated with signal %d\n",
                   WTERMSIG(status));
    }
    return;
  }

  if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
    std::fprintf(stderr, "fork_base: child exited with status %d\n",
                 WEXITSTATUS(status));
  }
}
