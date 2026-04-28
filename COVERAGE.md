# Fork Architecture & Coverage Collection

This document describes how `fork_base.cc` runs each fuzz input in an isolated
child process, how kernel coverage is collected via `kcov`, and how that
coverage is fed back to libFuzzer's mutator on Linux.

---

## Why a fork-per-iteration model?

The harness fuzzes Linux kernel filesystem code (e.g. `ntfs3`). A bad input
can leave userspace state in arbitrary shape — locked file descriptors,
poisoned memory mappings, AIO requests still in flight, dangling temp
directories, blocked threads. We need every fuzz iteration to start from a
clean slate without restarting the libFuzzer process (which would discard the
mutator's accumulated corpus state).

The answer is a parent/child split:

| Role | Process | Responsibility |
|---|---|---|
| **Parent** | libFuzzer host | Owns the corpus, the mutator, the protobuf-mutator, and the `libfuzzer_coverage` array. Forks one child per input, enforces a hard timeout, collects coverage. |
| **Child** | one per iteration | Opens kcov, arms it, runs exactly one fuzz session, dumps kcov PCs into shared memory, exits. |

Each child gets its own fd table, signal handlers, working directory, mmap
layout — anything the input mutates is gone the moment the child `_exit()`s.

---

## Per-iteration timeline

```
        Parent                          Child
           │
           │  save_input_for_recovery(s)
           │  (atomic write × 2 to /home/mfirouz/testfuzz/poc_generated/)
           │
           │  pipe(sync_pipe)
           │  fork() ──────────────────► (child created with full COW state)
           │                              │
           │                              │  read(sync_pipe[0])  // blocks
           │  write(sync_pipe[1], 1)      │
           │  ─────────────────────────►  │
           │                              │  kcov_init()        // open /sys/kernel/debug/kcov, mmap
           │                              │  kcov_start()       // KCOV_ENABLE on this task
           │                              │  run_fs_session(s)  // spawns 3 worker threads (see below)
           │                              │  kcov_stop()        // KCOV_DISABLE + dump PCs
           │                              │  _exit(0)
           │  waitpid()  ◄────────────────┘
           │  kcov_merge()
           │  (drains shared buffer into libfuzzer_coverage)
           ▼
        next iteration
```

The sync pipe exists because the child's `KCOV_ENABLE` must come **after**
the parent has finished forking and any pending parent work. Otherwise kcov
might capture parent-side PCs that fired between `fork()` and the child's
first instruction.

---

## Threading model inside the child

The child does **not** execute commands serially. Once `kcov_start()` returns,
`run_fs_session()` (in `fork_base.cc`) spawns three concurrent worker threads
that race on the same shared filesystem state. This is what gives the harness
its ability to find race conditions, not just sequential bugs.

### Two execution modes

`run_fs_session()` chooses one of two paths based on the proto's
`concurrency_mode` field (parsed by `runtime_settings_for_session`):

| Mode | Threads | When |
|---|---|---|
| `RuntimeMode::Off` | 1 (caller only) | Set when the input requests fully serial execution. Used for simple replay / debugging. |
| Race mode (default) | **3** — two `std::thread`s + the calling thread | Default for normal fuzzing. |

### The three workers

In race mode each worker is assigned a `WorkerSemanticRole` and only executes
commands whose op-class matches that role:

| Worker | `WorkerSemanticRole` | Command op-classes it runs |
|---|---|---|
| `t0` | `SetupWatcher` | `kOpen`, `kOpenAt`, `kMkdir`, `kRmdir`, `kPoll`, `kReadlink`, `kGetdents`, links/unlinks |
| `t1` | `IoAioMmap` | `kRead`, `kWrite`, `kPread`, `kPwrite`, `kReadv`, `kWritev`, AIO suite, `kMmap`/`kMsync`/`kMprotect`, `kSendmsg`/`kRecvmsg`, `kFsync`, `kFlock`, `kFtruncate`, `kSendfile`, `kCopyFileRange`, `kSplice`/`kTee`/`kVmsplice`, … |
| `t2` (main thread) | `PathMetadata` | `kRename`/`kRenameAt2`, `kStat`, `kChmod`, `kChown`, xattrs, `kMknod`, `kMkfifo`, `kUtimes`/`kUtimensat`, `kStatx`, `kFallocate`, … |

The op-class table lives in `command_op_class()` and the role filter in
`command_matches_role()` (around `fork_base.cc:2747`). A command whose role
doesn't match the worker that picks it up is silently skipped, so each thread
only ever issues syscalls within its own bucket. That gives consistent
contention shapes (e.g. "open vs. write vs. rename" rather than "all three
threads doing identical opens").

### How they share state

All three workers operate on a single `Pools` instance:

```cpp
Pools shared;
shared.shared_state = std::make_shared<Pools::SharedState>();
shared.shared_state->interaction_tracker =
    std::make_shared<Pools::InteractionTracker>();
seed_workspace(shared);
```

`Pools::SharedState` (`fork_base.cc:530-548`) holds three
`SharedHandleTable`s — `fds`, `dirfds`, and `kqfds` — each protected by its
own `std::mutex`. So when worker `t0` opens a file, the resulting fd lands in
`shared_state->fds`, and workers `t1` and `t2` can immediately use that same
fd index in subsequent commands. Concurrent `read`s and `unlink`s on the same
file *do* race at the kernel level — that's the point.

The `Pools::InteractionTracker` exists to log "suspicious" cross-role
accesses to the same kernel object (e.g. metadata thread is renaming the file
that the IO thread just wrote to). When `FSFUZZ_LOG_SUSPICIOUS=1` is set the
tracker prints those interleavings to stderr, useful for triaging which
exact commands raced when a bug fires.

### Determinism: why a barrier is needed

Three threads racing freely on the same fd table would mean "the same
proto-mutator input never replays the same way," which would defeat
libFuzzer's mutation feedback (a crashing input wouldn't reproduce). To get
both real concurrency *and* reproducibility, the workers walk through
synchronized phases:

```cpp
DeterministicPhaseBarrier phase_barrier(kWorkerCount);
```

Each worker calls into the barrier at well-defined points (between command
chunks). Inside a phase the three threads run freely; between phases they all
wait at the barrier. The result is bounded nondeterminism — kernel-level
ordering inside a phase varies, but the harness re-enters each phase with all
three threads at the same logical position, which is enough for replay.

### Where to look in the code

| Function | Purpose | Approx line |
|---|---|---|
| `run_fs_session(sess)` | Decides between `Off` and race mode, spawns the threads | `fork_base.cc:3368` |
| `run_worker_once(...)` | Per-thread main loop; obeys role filter and the phase barrier | `fork_base.cc:3281` |
| `command_op_class(cmd)` | Maps a command to one of `Watch`/`Setup`/`Io`/`Aio`/`Mapping`/`PathMutation`/`Metadata`/`FdTransfer`/`Other` | `fork_base.cc:~2670` |
| `command_matches_role(cmd, role)` | Decides whether *this* worker handles *this* command | `fork_base.cc:~2747` |
| `Pools::SharedState`, `SharedHandleTable` | The mutex-protected fd / dirfd tables shared across the three threads | `fork_base.cc:530` |
| `DeterministicPhaseBarrier` | Lock-step phase boundaries | search the file |

### Updated per-iteration picture

```
libFuzzer                 parent                child
   │                        │                     │
   │  TestOneInput() ──────►│                     │
   │                        │  save_input(...)    │
   │                        │  fork() ───────────►│
   │                        │                     │  kcov_init / kcov_start
   │                        │                     │  run_fs_session()
   │                        │                     │       │
   │                        │                     │       ├──► t0 (SetupWatcher)
   │                        │                     │       ├──► t1 (IoAioMmap)
   │                        │                     │       └──► t2 (PathMetadata, this thread)
   │                        │                     │            ↑↑↑ all three race on shared fd table,
   │                        │                     │                synchronized via DeterministicPhaseBarrier
   │                        │                     │       │
   │                        │                     │       ▼ join + cleanup_session
   │                        │                     │  kcov_stop  (folds PCs into g_kcov_shared)
   │                        │                     │  _exit
   │                        │  waitpid ◄──────────┘
   │                        │  kcov_merge        (g_kcov_shared → libfuzzer_coverage)
   │  ◄───── return ────────│
```

So inside one libFuzzer iteration, ntfs3 is being hit by **three contending
kernel tasks** with shared fds — that's the structure that makes this harness
useful for finding races, not just sequential bugs.

---

## Shared memory bridges

kcov's buffer is **per-task**: only the task that called `KCOV_ENABLE` on a
given fd can read meaningful data from that fd's mmap. The parent has no
direct access to the child's coverage. So we need bridges that survive the
process boundary.

Both bridges are `MAP_SHARED | MAP_ANONYMOUS` mappings allocated by the parent
**before** `fork()`. That makes them visible (same physical pages) in both
processes.

### 1. `g_kcov_shared` — the libFuzzer feedback table

Allocated in `kcov_setup_shared()`:

```cpp
g_kcov_shared = mmap(nullptr, sizeof(libfuzzer_coverage),
                     PROT_READ | PROT_WRITE,
                     MAP_SHARED | MAP_ANONYMOUS, -1, 0);
```

Size matches `sizeof(libfuzzer_coverage)` (32 KiB by default). Each byte is a
saturating counter for the bucket whose hash matches that index.

- **Child** writes into it from `kcov_stop()` — for every PC the kernel
  recorded, it bumps `g_kcov_shared[pc % size]` (saturating at 255).
- **Parent** drains it from `kcov_merge()` after `waitpid()` — folds the
  bucket counts into `libfuzzer_coverage[]` and zeros the bridge so the
  next iteration starts clean.

### 2. `g_kcov_pcbuf` — debug-mode raw PCs

Allocated only when `DEBUG_KCOV=1` is set in the environment. Same shape as
the kernel kcov buffer: slot 0 is the count of valid entries, slots 1..N are
raw PC values. The child copies its kcov PCs verbatim into this buffer at the
end of `kcov_stop()`. The parent reads them in `kcov_merge()`, diffs against a
process-lifetime `std::unordered_set<uint64_t>`, and prints any newly-seen
PC to stderr.

---

## Linux libFuzzer extra counters: the `__libfuzzer_extra_counters` section

On Linux, libFuzzer (in compiler-rt's `FuzzerExtraCounters.cpp`) automatically
scans the ELF section named `__libfuzzer_extra_counters`. The linker
synthesizes two symbols for any section with that name:

- `__start___libfuzzer_extra_counters`
- `__stop___libfuzzer_extra_counters`

libFuzzer iterates `[__start, __stop)` once per iteration after the user's
`LLVMFuzzerTestOneInput` returns and treats every nonzero byte as an extra
coverage feature. There's **no registration call** needed — neither
`__sanitizer_cov_8bit_counters_init` nor any other API. Putting an array in
the right section is sufficient.

The harness declares its array at the top of `fork_base.cc`:

```cpp
extern "C" __attribute__((section("__libfuzzer_extra_counters")))
unsigned char libfuzzer_coverage[32 << 10];
```

The legacy macOS workflow used a custom-patched libFuzzer that looked up the
symbol `_pishi_libfuzzer_coverage` by name (because the macOS toolchain
doesn't honor `__libfuzzer_extra_counters` the same way). On Linux that's
unnecessary — the section attribute is enough.

---

## Coverage flow end-to-end

```
ntfs3 (or any kernel code) hits a basic block
        │  __sanitizer_cov_trace_pc instrumentation
        ▼
kernel kcov per-task buffer
        │  [child reads via mmap of /sys/kernel/debug/kcov]
        ▼
kcov_stop():  for each PC, ++g_kcov_shared[pc % size]
        │  [shared mmap; visible to parent]
        ▼
parent: waitpid()
        │
        ▼
kcov_merge():  libfuzzer_coverage[i] += g_kcov_shared[i]; clear g_kcov_shared
        │  [array lives in section __libfuzzer_extra_counters]
        ▼
libFuzzer scans the section after LLVMFuzzerTestOneInput returns
        │
        ▼
mutator decides whether the input is "interesting" (=adds new features)
and either keeps it in the corpus or drops it
```

The key file/line references:

| Step | Location |
|---|---|
| `libfuzzer_coverage[]` declaration | `fork_base.cc:66-72` |
| `kcov_setup_shared()` (allocates bridges) | `fork_base.cc:3540` |
| `kcov_init()` (child opens kcov) | `fork_base.cc:3551` |
| `kcov_start()` (child arms kcov) | `fork_base.cc:3564` |
| `kcov_stop()` (child dumps PCs to bridge) | `fork_base.cc:3572` |
| `kcov_merge()` (parent → libfuzzer_coverage) | `fork_base.cc:3590` |
| Fork lifecycle (`DEFINE_BINARY_PROTO_FUZZER`) | `fork_base.cc:3637` |

---

## Why hash-and-saturate (not raw PCs)

The kernel kcov buffer can hold up to `KCOV_COVER_SIZE = 256 * 1024` PCs per
iteration. Shipping all of them across the process boundary every time would
be expensive. More importantly, libFuzzer's extra-counter table is a fixed
32 KiB — it isn't designed to hold arbitrary PC values, just per-bucket
counters. So `kcov_stop()` does the standard hash-table fold:

```cpp
size_t idx = pc % g_kcov_shared_size;
if (g_kcov_shared[idx] < 255) ++g_kcov_shared[idx];
```

This loses raw PC information (you can't go from a bucket back to a function
name), but it's exactly the shape libFuzzer's mutator wants: "this iteration
visited buckets {a, b, c} with frequencies {3, 1, 8}." Buckets that flip from
0→nonzero or that change frequency category are reported as new features and
the input is preserved.

If you need raw PC information, run with `DEBUG_KCOV=1` (next section).

---

## DEBUG_KCOV: log newly-hit basic blocks

Set `DEBUG_KCOV=1` at startup to log every previously-unseen kernel PC to
stderr.

```bash
DEBUG_KCOV=1 ./fork_base /home/mfirouz/testfuzz \
    -artifact_prefix=/home/mfirouz/testfuzz/ -timeout=5
```

What changes:

1. `kcov_setup_shared()` allocates the second bridge (`g_kcov_pcbuf`) — also
   `MAP_SHARED | MAP_ANONYMOUS`, sized like the kcov buffer.
2. `kcov_stop()` (child) copies its raw PC list into `g_kcov_pcbuf` after the
   normal hash-fold pass. `g_kcov_pcbuf[0]` is set with a release store; the
   parent uses an acquire load on the same slot to read consistent data.
3. `kcov_merge()` (parent) iterates `g_kcov_pcbuf[1..n]`, dedups against a
   `static std::unordered_set<uint64_t>` that lives for the whole fuzzing
   run, and prints each new entry:
   ```
   [kcov] new BB: 0xffffffff8123abcd
   [kcov] iter: 4123 PCs total, 17 new, 4123 unique BBs seen
   ```

The seen-set is process-lifetime (parent only). Memory grows ~16 bytes per
unique kernel BB visited — for typical kernel coverage budgets that's a few
hundred KB. Without `DEBUG_KCOV` set, neither the second mmap nor the dedup
pass exists, so the fast path has zero added overhead.

To get symbols, pipe the addresses to `addr2line`:

```bash
DEBUG_KCOV=1 ./fork_base ... 2>&1 \
  | grep '\[kcov\] new BB:' \
  | awk '{print $4}' \
  | addr2line -e /path/to/vmlinux -f -i -p
```

---

## Failure modes & what to check

| Symptom | Likely cause |
|---|---|
| `open kcov failed (errno 13)` | Run as root or with `CAP_SYS_ADMIN`; debugfs must be mounted. |
| `KCOV_INIT failed (errno 22)` | Kernel built without `CONFIG_KCOV=y`, or the requested cover size exceeds the kernel cap. |
| `KCOV_ENABLE failed (errno 16)` (EBUSY) | Another task already armed kcov on this fd. Means a stale child holds the fd; investigate signal handling / cleanup. |
| libFuzzer reports "exec/sec: 0" or never marks new corpus entries | The `__libfuzzer_extra_counters` section isn't being honored. Confirm with `objdump -h ./fork_base \| grep extra_counters`; the section should appear with a nonzero size. |
| New BBs printed in DEBUG mode but libFuzzer corpus doesn't grow | Coverage is reaching the bridge but libFuzzer isn't consuming it. Check that the binary was actually linked with `-fsanitize=fuzzer` and not just `-fsanitize=fuzzer-no-link`. |

---

## Pre-fork ordering invariant

Anything the parent and child both need access to via `MAP_SHARED` must be
allocated **before** `fork()`. Specifically `kcov_setup_shared()` is called
from `LLVMFuzzerInitialize` — guaranteed to run once, before libFuzzer enters
its mutation loop, hence before any iteration's `fork()`.

If you add a new shared bridge, allocate it in `LLVMFuzzerInitialize` (or its
helpers). Allocating after `fork()` in the child won't propagate to the
parent; allocating after `fork()` in the parent would race with whatever the
child is doing.

---

## Output paths summary

| What | Path | Why |
|---|---|---|
| Per-worker filesystem workspaces | `/tmp/ntfs/fsfuzz.<wid>.XXXXXX/` | The mounted ntfs3 image — every fuzz syscall hits this filesystem. |
| Recovered PoC inputs (rolling 100) | `/home/mfirouz/testfuzz/poc_generated/last_input_<seq>.pb` | 9p-shared with the host so a guest panic still leaves the input visible from outside the VM. |
| libFuzzer corpus / artifact dir | `/home/mfirouz/testfuzz/` (passed on the command line) | Same 9p mount; libFuzzer-managed. |

These are hardcoded constants in `fork_base.cc`; there are no environment
variables to override them. If you need a different layout, edit the
constants and rebuild.
