Missing Surface

The schema never models fsctl, ffsctl, fhopen, sendfile, preadv, pwritev, kevent_qos, kevent_id, or the statfs64 family. They are absent from the Command oneof in fuzz_filesys.proto (line 17), but XNU exposes them in syscalls.master (line 242), syscalls.master (line 337), syscalls.master (line 345), syscalls.master (line 374), and syscalls.master (line 540). fsctl and ffsctl are probably the highest-value missing entries because they fan out into per-filesystem control paths.

There is no path to raw-syscall-only “extended” filesystem calls like open_extended, umask_extended, stat_extended, lstat_extended, fstat_extended, chmod_extended, fchmod_extended, access_extended, mkfifo_extended, and mkdir_extended in syscalls.master (line 277). If you ever add raw syscall shims, that opens more MAC/xsecurity plumbing than the libc-style wrappers do.

The harness does not expose file-backed VM calls like madvise, mincore, minherit, mlock, munlock, mlockall, and munlockall, even though XNU provides them in mman.h (line 264). For filesystem fuzzing, these are useful because they touch vnode pager and mapped-file state, not just generic VM.

Present In Proto But Disabled

A large Darwin-only bucket is already in the proto but currently no-ops in the executor: umask, aio_suspend, sync, acct, revoke, chroot, setattrlist, fsetattrlist, exchangedata, searchfs, copyfile, clonefileat, fclonefileat, openbyid, fs_snapshot, fmount, and pivot_root in fuzz_filesys.proto (line 120) and fuzz_filesys.cc (line 1441), fuzz_filesys.cc (line 1780), fuzz_filesys.cc (line 1997), and fuzz_filesys.cc (line 2084). If the goal is maximum kernel coverage, this is the easiest “already wired in schema” bucket to reclaim.

openbyid_np exists in XNU in syscalls.master (line 479), but the executor explicitly skips OpenById in fuzz_filesys.cc (line 2205). That leaves object-id based vnode lookup uncovered.

Narrow Modeling

Open flag coverage is much narrower than XNU’s real surface. The proto only enumerates RDWR/WRONLY/CREAT/TRUNC/EXCL/APPEND/CLOEXEC/DIRECTORY in fuzz_filesys.proto (line 570), and flags_from_mask() only maps those plus forced O_NONBLOCK|O_NOFOLLOW in fuzz_filesys.cc (line 277). Missing useful bits include O_SHLOCK, O_EXLOCK, O_ASYNC, O_EVTONLY, O_SYMLINK, O_EXEC, O_SEARCH, O_RESOLVE_BENEATH, O_UNIQUE, and O_NOFOLLOW_ANY from fcntl.h (line 121).

fcntl is heavily sandboxed by the harness. safe_fcntl_cmd() only allows six commands in fuzz_filesys.cc (line 359), so you miss high-value file controls like F_PREALLOCATE, F_SETSIZE, F_RDADVISE, F_NOCACHE, F_LOG2PHYS, F_FULLFSYNC, F_GETPATH, F_FREEZE_FS, F_THAW_FS, F_GET/SETPROTECTIONCLASS, F_SET/GETNOSIGPIPE, F_BARRIERFSYNC, F_OFD_*, F_PUNCHHOLE, F_TRANSFEREXTENTS, and F_ATTRIBUTION_TAG in fcntl.h (line 295). This is one of the biggest missed APFS/HFS coverage areas.

mmap and msync flags are also too narrow. The harness only maps MAP_PRIVATE|MAP_SHARED and maybe MAP_NOCACHE in fuzz_filesys.cc (line 238), plus MS_ASYNC/MS_INVALIDATE in fuzz_filesys.cc (line 247). XNU has additional interesting flags like MAP_FIXED, MAP_ANON, MAP_NORESERVE, MAP_HASSEMAPHORE, MAP_JIT, MAP_RESILIENT_CODESIGN, MAP_RESILIENT_MEDIA, MAP_32BIT, MAP_TRANSLATED_ALLOW_EXECUTE, MAP_TPRO, MS_SYNC, MS_KILLPAGES, and MS_DEACTIVATE in mman.h (line 119).

Xattr modeling misses the position argument completely. The proto only carries name/value/options in fuzz_filesys.proto (line 296), and the executor hardcodes position = 0 for all get/set xattr calls in fuzz_filesys.cc (line 1463). XNU’s xattr ABI includes position for getxattr/setxattr in xattr.h (line 92), which matters for resource-fork style paths.

Xattr buffer sizing is fixed and small. getxattr, fgetxattr, listxattr, and flistxattr all use a 1024-byte local buffer in fuzz_filesys.cc (line 1468), which limits large EA and name-list paths.

Already Reachable But Worth Biasing

renameatx_np is already passed through raw in fuzz_filesys.cc (line 1321), so the interesting missing piece is better use of flags like RENAME_SECLUDE, RENAME_SWAP, RENAME_EXCL, RENAME_NOFOLLOW_ANY, and RENAME_RESOLVE_BENEATH from stdio.h (line 35).

The attrlist schema is flexible enough to probe deep volume features already in fuzz_filesys.proto (line 456). If you want more coverage without new commands, bias options toward FSOPT_* bits in attr.h (line 46) and request capability-rich volume attrs like VOL_CAP_INT_SEARCHFS, VOL_CAP_INT_EXCHANGEDATA, VOL_CAP_INT_COPYFILE, VOL_CAP_INT_CLONE, VOL_CAP_INT_SNAPSHOT, VOL_CAP_INT_RENAME_*, VOL_CAP_INT_PUNCHHOLE, and VOL_CAP_INT_BARRIERFSYNC in attr.h (line 380).

The kevent path is less of a blocker than it looks: the harness forwards raw filter, flags, and fflags into EV_SET in fuzz_filesys.cc (line 1120), so EVFILT_VNODE plus NOTE_DELETE|NOTE_WRITE|NOTE_EXTEND|NOTE_ATTRIB|NOTE_LINK|NOTE_RENAME|NOTE_REVOKE from event.h (line 242) are already reachable.