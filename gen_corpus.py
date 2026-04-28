#!/usr/bin/env python3
"""Linux filesystem fuzzer corpus generator.

Emits seed inputs for the proto-mutator harness in fuzz_filesys.cc /
fork_base.cc. Each seed is written as a binary protobuf and (optionally) a
text-format prototxt for inspection.

Usage:
    ./gen_corpus.py                            # default: 64 seeds in ./corpus_binary
    ./gen_corpus.py --count 256 --out corpus
    ./gen_corpus.py --decode corpus_binary/seed_000.pb
"""
import argparse
import random
import sys
from pathlib import Path

try:
    from google.protobuf import text_format
    import fuzz_filesys_pb2
except ModuleNotFoundError:
    print("error: run `protoc --python_out=. fuzz_filesys.proto` first "
          "(or run `./build.sh`)", file=sys.stderr)
    raise

# -------- OpenFlag enum bit positions (matches fuzz_filesys.proto) ----------
OF = {
    "WRONLY":    1,
    "RDWR":      2,
    "CREAT":     3,
    "TRUNC":     4,
    "EXCL":      5,
    "APPEND":    6,
    "CLOEXEC":   7,
    "DIRECTORY": 8,
    "NOFOLLOW":  9,
    "NONBLOCK":  10,
    # 11..13 (SYNC/DSYNC/RSYNC) are deliberately not exposed by the harness
    "DIRECT":    14,
    "NOATIME":   15,
    "PATH":      16,
    "TMPFILE":   17,
    "LARGEFILE": 18,
    "ASYNC":     19,
    "NOCTTY":    20,
}

def of_mask(*names: str) -> int:
    m = 0
    for n in names:
        m |= 1 << OF[n]
    return m

REG_RW    = of_mask("RDWR", "CREAT")
REG_TRUNC = of_mask("RDWR", "CREAT", "TRUNC")
REG_APP   = of_mask("RDWR", "CREAT", "APPEND")
DIR_OPEN  = of_mask("DIRECTORY")
TMPFILE   = of_mask("RDWR", "TMPFILE")
PATH_OPEN = of_mask("PATH")


# ============================================================================
# Text-format emission helpers
# ============================================================================

def qbs(data: bytes) -> str:
    out = []
    for b in data:
        if 32 <= b <= 126 and b not in (34, 92):
            out.append(chr(b))
        else:
            out.append(f"\\{b:03o}")
    return '"' + "".join(out) + '"'


def emit_value(key: str, value, indent: int = 4) -> str:
    pad = " " * indent
    if isinstance(value, bool):
        return f"{pad}{key}: {'true' if value else 'false'}"
    if isinstance(value, int):
        return f"{pad}{key}: {value}"
    if isinstance(value, str):
        return f'{pad}{key}: "{value}"'
    if isinstance(value, bytes):
        return f"{pad}{key}: {qbs(value)}"
    raise TypeError(f"unsupported value type for {key}: {type(value)}")


def emit_message(name: str, fields: dict, indent: int = 2) -> str:
    pad = " " * indent
    lines = [f"{pad}{name} {{"]
    for k, v in fields.items():
        if isinstance(v, list):
            for elem in v:
                lines.append(emit_value(k, elem, indent + 2))
        else:
            lines.append(emit_value(k, v, indent + 2))
    lines.append(f"{pad}}}")
    return "\n".join(lines)


def cmd(name: str, fields: dict | None = None) -> str:
    """Emit `commands { <name> { ... } }`."""
    inner = emit_message(name, fields or {}, indent=4)
    return "commands {\n" + inner + "\n}"


def emit_session_text(commands: list[str], data_provider: bytes) -> str:
    parts = list(commands)
    parts.append(f"data_provider: {qbs(data_provider)}")
    return "\n".join(parts) + "\n"


# ============================================================================
# Random helpers
# ============================================================================

def rand_bytes(r: random.Random, lo: int = 8, hi: int = 128) -> bytes:
    n = r.randint(lo, hi)
    return bytes(r.getrandbits(8) for _ in range(n))


def rand_mode(r: random.Random) -> int:
    return r.choice([0o644, 0o600, 0o664, 0o755, 0o777, 0o400])


def rand_xattr_name(r: random.Random) -> str:
    suffix = "".join(r.choice("abcdefghijklmnopqrstuvwxyz")
                     for _ in range(r.randint(3, 8)))
    return r.choice(["user.", "user.fuzz."]) + suffix


def rand_short_name(r: random.Random, prefix: str) -> str:
    return f"{prefix}_{r.getrandbits(24):06x}"


def rand_oflags(r: random.Random, want_dir: bool = False) -> int:
    if want_dir:
        return DIR_OPEN | (of_mask("CLOEXEC") if r.random() < 0.5 else 0)
    base = r.choice([REG_RW, REG_TRUNC, REG_APP])
    if r.random() < 0.30: base |= of_mask("CLOEXEC")
    if r.random() < 0.10: base |= of_mask("NOATIME")
    if r.random() < 0.05: base |= of_mask("DIRECT")
    return base


# ============================================================================
# Per-scenario command builders. Each returns a list[str] of "commands { ... }"
# blocks. Indices into the harness pools (fd_idx / dirfd_idx / path_idx /
# req_idx / map_idx) wrap modulo the pool size at dispatch time, so out-of-
# range values are safe — the harness will round them off.
# ============================================================================

def setup_seq(r: random.Random) -> list[str]:
    return [
        cmd("open", {"path_idx": 0, "flags": REG_RW, "mode": 0o644}),
        cmd("open", {"path_idx": 1, "flags": DIR_OPEN}),
        cmd("open_at", {"dirfd_idx": -1, "flags": REG_RW | of_mask("EXCL"),
                        "mode": rand_mode(r),
                        "name_hint": rand_short_name(r, "f")}),
    ]


def io_seq(r: random.Random) -> list[str]:
    return [
        cmd("write",  {"fd_idx": 0, "data": rand_bytes(r, 32, 256)}),
        cmd("pwrite", {"fd_idx": 0, "off": r.randint(0, 4096),
                       "data": rand_bytes(r, 16, 1024)}),
        cmd("read",   {"fd_idx": 0, "maxlen": r.choice([64, 256, 4096])}),
        cmd("pread",  {"fd_idx": 0, "off": 0, "maxlen": 256}),
        cmd("lseek",  {"fd_idx": 0, "off": 0, "whence": 0}),
        cmd("ftruncate", {"fd_idx": 0, "len": r.randint(0, 65536)}),
    ]


def vec_io_seq(r: random.Random) -> list[str]:
    return [
        cmd("writev", {"fd_idx": 0,
                       "data": [rand_bytes(r, 8, 64) for _ in range(r.randint(2, 5))]}),
        cmd("readv",  {"fd_idx": 0, "iovcnt": r.choice([2, 4, 8]), "maxlen": 4096}),
        cmd("pwritev", {"fd_idx": 0, "offset": r.randint(0, 4096),
                        "data": [rand_bytes(r, 8, 64) for _ in range(3)]}),
        cmd("preadv",  {"fd_idx": 0, "offset": 0, "iovcnt": 4, "maxlen": 4096}),
    ]


def xattr_seq(r: random.Random) -> list[str]:
    name = rand_xattr_name(r)
    return [
        cmd("setxattr", {"path_idx": 0, "name": name,
                         "value": rand_bytes(r, 8, 128), "flags": 0,
                         "follow_symlink": r.random() < 0.7}),
        cmd("getxattr", {"path_idx": 0, "name": name, "buf_size": 256,
                         "follow_symlink": True}),
        cmd("listxattr", {"path_idx": 0, "buf_size": 1024,
                          "follow_symlink": r.random() < 0.7}),
        cmd("fsetxattr", {"fd_idx": 0, "name": name + ".fd",
                          "value": rand_bytes(r, 8, 64)}),
        cmd("fgetxattr", {"fd_idx": 0, "name": name + ".fd", "buf_size": 128}),
        cmd("removexattr", {"path_idx": 0, "name": name,
                            "follow_symlink": r.random() < 0.7}),
    ]


def link_unlink_seq(r: random.Random) -> list[str]:
    new_name = rand_short_name(r, "l")
    return [
        cmd("link",   {"existing_path_idx": 0, "new_path_idx": 999}),
        cmd("link_at", {"olddirfd_idx": -1, "newdirfd_idx": -1,
                        "oldname": "seed_file", "newname": new_name,
                        "follow_symlink": True}),
        cmd("symlink", {"target_path_idx": 0, "link_path_idx": 998}),
        cmd("symlink_at", {"newdirfd_idx": -1,
                           "target": "seed_file",
                           "linkname": rand_short_name(r, "s")}),
        cmd("readlink", {"path_idx": 998}),
        cmd("unlink_at", {"dirfd_idx": -1, "name": new_name}),
        cmd("unlink",   {"path_idx": 998}),
    ]


def rename_seq(r: random.Random) -> list[str]:
    a, b = rand_short_name(r, "a"), rand_short_name(r, "b")
    return [
        cmd("open_at", {"dirfd_idx": -1, "flags": REG_RW | of_mask("CREAT"),
                        "mode": 0o644, "name_hint": a}),
        cmd("open_at", {"dirfd_idx": -1, "flags": REG_RW | of_mask("CREAT"),
                        "mode": 0o644, "name_hint": b}),
        cmd("rename_at", {"olddirfd_idx": -1, "oldname": a,
                          "newdirfd_idx": -1, "newname": b}),
        # rename_at2 flags: 1=NOREPLACE, 2=EXCHANGE, 4=WHITEOUT
        cmd("rename_at2", {"olddirfd_idx": -1, "oldname": b,
                           "newdirfd_idx": -1, "newname": a,
                           "flags": r.choice([0, 1, 2])}),
    ]


def stat_seq(r: random.Random) -> list[str]:
    # STATX_BASIC_STATS=0x7ff, STATX_BTIME=0x800, STATX_MNT_ID=0x1000,
    # STATX_DIOALIGN=0x2000, STATX_ALL=0xfff
    statx_mask = r.choice([0x7ff, 0xfff, 0x800, 0x1000, 0x2000])
    return [
        cmd("stat",  {"path_idx": 0}),
        cmd("lstat", {"path_idx": 0}),
        cmd("fstat", {"fd_idx": 0}),
        cmd("fstat_at", {"dirfd_idx": -1, "name": "seed_file",
                         "flags": r.choice([0, 0x100, 0x1000])}),  # AT_SYMLINK_NOFOLLOW / AT_NO_AUTOMOUNT
        cmd("statx", {"dirfd_idx": -1, "name": "seed_file",
                      "flags": 0, "mask": statx_mask}),
        cmd("statfs",  {"path_idx": 0}),
        cmd("fstatfs", {"fd_idx": 0}),
        cmd("access",  {"path_idx": 0, "mode": r.choice([0, 1, 2, 4, 7])}),
        cmd("faccess_at", {"dirfd_idx": -1, "name": "seed_file",
                           "mode": r.choice([0, 1, 2, 4])}),
    ]


def metadata_seq(r: random.Random) -> list[str]:
    return [
        cmd("chmod",   {"path_idx": 0, "mode": rand_mode(r)}),
        cmd("fchmod",  {"fd_idx": 0,   "mode": 0o660}),
        cmd("chown",   {"path_idx": 0, "uid": r.choice([0, 1000]),
                        "gid": r.choice([0, 1000])}),
        cmd("utimes",  {"path_idx": 0, "atime_sec": 1000, "atime_usec": 0,
                        "mtime_sec": 2000, "mtime_usec": 0}),
        cmd("utimensat", {"dirfd_idx": -1, "name": "seed_file",
                          "atime_sec": 0, "atime_nsec": 0,
                          "mtime_sec": 1700000000, "mtime_nsec": 0,
                          "flags": 0}),
    ]


def aio_seq(r: random.Random) -> list[str]:
    req = r.randint(0, 7)
    return [
        cmd("aio_write", {"fd_idx": 0, "off": r.randint(0, 4096),
                          "data": rand_bytes(r, 32, 256), "req_idx": req}),
        cmd("aio_read",  {"fd_idx": 0, "off": 0, "maxlen": 256, "req_idx": req}),
        cmd("aio_error",  {"req_idx": req}),
        cmd("aio_return", {"req_idx": req}),
        cmd("aio_cancel", {"fd_idx": 0, "req_idx": req}),
    ]


def lio_seq(r: random.Random) -> list[str]:
    entries = []
    for i in range(r.randint(2, 4)):
        op = r.choice([1, 2])  # 1=READ 2=WRITE
        e = {"fd_idx": 0, "off": r.randint(0, 4096), "opcode": op,
             "req_idx": i}
        if op == 2:
            e["data"] = rand_bytes(r, 16, 128)
        else:
            e["maxlen"] = 128
        entries.append(emit_message("entries", e, indent=4))
    return ["commands {\n  lio_listio {\n" + "\n".join(entries) +
            "\n    mode: 0\n  }\n}"]


def mmap_seq(r: random.Random) -> list[str]:
    return [
        cmd("mmap", {"fd_idx": 0, "len": 4096, "prot": 3, "flags": 1, "off": 0}),
        cmd("msync", {"map_idx": 0, "flags": 0}),
        cmd("madvise", {"map_idx": 0, "advice": r.choice([0, 1, 2, 3, 4])}),
        cmd("mprotect", {"map_idx": 0, "prot": 1}),
        cmd("munmap", {"map_idx": 0}),
    ]


def fallocate_seq(r: random.Random) -> list[str]:
    # FALLOC_FL_*: 1=KEEP_SIZE, 2=PUNCH_HOLE (needs KEEP_SIZE), 4=COLLAPSE_RANGE,
    # 8=ZERO_RANGE, 16=INSERT_RANGE, 32=UNSHARE_RANGE
    base_off = r.choice([0, 4096, 8192, 65536])
    return [
        cmd("fallocate", {"fd_idx": 0, "mode": 0,
                          "offset": 0,
                          "len": r.choice([1024, 4096, 65536])}),
        cmd("fallocate", {"fd_idx": 0, "mode": 1 | 2,
                          "offset": base_off,
                          "len": r.choice([1024, 4096])}),
        cmd("fallocate", {"fd_idx": 0, "mode": r.choice([1, 8, 1 | 8, 16]),
                          "offset": 0,
                          "len": 1024}),
    ]


def copy_seq(r: random.Random) -> list[str]:
    return [
        cmd("open_at", {"dirfd_idx": -1, "flags": REG_RW | of_mask("CREAT"),
                        "mode": 0o644, "name_hint": rand_short_name(r, "src")}),
        cmd("open_at", {"dirfd_idx": -1, "flags": REG_RW | of_mask("CREAT"),
                        "mode": 0o644, "name_hint": rand_short_name(r, "dst")}),
        cmd("write", {"fd_idx": 1, "data": rand_bytes(r, 256, 1024)}),
        cmd("copy_file_range", {"in_fd_idx": 1, "out_fd_idx": 2,
                                "in_off": 0, "out_off": 0,
                                "len": 256, "flags": 0,
                                "use_in_off": True, "use_out_off": True}),
        cmd("sendfile", {"out_fd_idx": 2, "in_fd_idx": 1,
                         "offset": 0, "len": 256, "use_offset": True}),
    ]


def splice_seq(r: random.Random) -> list[str]:
    return [
        cmd("pipe", {"nonblock": True, "cloexec": True}),
        cmd("write", {"fd_idx": 0, "data": rand_bytes(r, 64, 256)}),
        cmd("splice", {"fd_in_idx": 0, "fd_out_idx": 2,
                       "len": 128, "flags": 0,
                       "use_off_in": False, "use_off_out": False}),
        cmd("tee", {"fd_in_idx": 1, "fd_out_idx": 2, "len": 64, "flags": 0}),
        cmd("vmsplice", {"fd_idx": 2,
                         "data": [rand_bytes(r, 16, 96)], "flags": 0}),
    ]


def fadvise_seq(r: random.Random) -> list[str]:
    return [
        cmd("fadvise",   {"fd_idx": 0, "offset": 0, "len": 4096,
                          "advice": r.choice([0, 1, 2, 3, 4, 5])}),
        cmd("readahead", {"fd_idx": 0, "offset": 0, "count": 4096}),
    ]


def sync_seq(r: random.Random) -> list[str]:
    # SYNC_FILE_RANGE_*: 1=WAIT_BEFORE, 2=WRITE, 4=WAIT_AFTER. The harness
    # masks all of them down to WRITE-only, so we exercise the full
    # combinatorial input space here.
    return [
        cmd("fsync",     {"fd_idx": 0}),
        cmd("fdatasync", {"fd_idx": 0}),
        cmd("sync_file_range", {"fd_idx": 0,
                                "offset": r.choice([0, 4096, 65536]),
                                "nbytes": r.choice([0, 4096, 65536, 1 << 20]),
                                "flags": r.choice([0, 1, 2, 4, 7])}),
        cmd("syncfs",    {"fd_idx": 0}),
    ]


def memfd_seq(r: random.Random) -> list[str]:
    return [
        cmd("memfd_create", {"name": rand_short_name(r, "mem"), "flags": 0}),
        cmd("ftruncate",    {"fd_idx": 0, "len": 4096}),
        cmd("write",        {"fd_idx": 0, "data": rand_bytes(r, 64, 256)}),
        cmd("dup3",         {"old_fd_idx": 0, "new_fd_idx": 1, "flags": 0}),
    ]


def dir_enum_seq(r: random.Random) -> list[str]:
    return [
        cmd("mkdir_at", {"dirfd_idx": -1, "name": rand_short_name(r, "d"),
                         "mode": 0o755}),
        cmd("getdents", {"fd_idx": 0, "count": 4096}),
    ]


def fcntl_seq(r: random.Random) -> list[str]:
    return [
        cmd("fcntl", {"fd_idx": 0, "cmd": r.randint(0, 12),
                      "arg":  r.randint(0, 31)}),
        cmd("flock", {"fd_idx": 0, "op": r.choice([1, 2, 4])}),
    ]


def mknod_mkfifo_seq(r: random.Random) -> list[str]:
    return [
        cmd("mknod_at", {"dirfd_idx": -1, "name": rand_short_name(r, "n"),
                         "mode": 0o644 | 0o010000, "dev": 0}),  # S_IFIFO bit
        cmd("mkfifo_at", {"dirfd_idx": -1, "name": rand_short_name(r, "p"),
                          "mode": 0o644}),
    ]


def uds_seq(r: random.Random) -> list[str]:
    return [
        cmd("socketpair", {"domain": 0, "type": 0, "proto": 0}),
        cmd("sendmsg", {"sock_fd_idx": 0, "data": rand_bytes(r, 32, 128),
                        "send_rights": True, "rights_fd_idx": 1}),
        cmd("recvmsg", {"sock_fd_idx": 1, "maxlen": 128,
                        "accept_rights": True}),
    ]


SCENARIOS = [
    setup_seq, io_seq, vec_io_seq, xattr_seq, link_unlink_seq, rename_seq,
    stat_seq, metadata_seq, aio_seq, lio_seq, mmap_seq, fallocate_seq,
    copy_seq, splice_seq, fadvise_seq, sync_seq, memfd_seq, dir_enum_seq,
    fcntl_seq, mknod_mkfifo_seq, uds_seq,
]


# ============================================================================
# Seed assembly
# ============================================================================

def build_seed_text(r: random.Random, target_cmd_count: int) -> str:
    cmds: list[str] = []
    cmds.extend(setup_seq(r))  # always seed the fd pool first
    while len(cmds) < target_cmd_count:
        cmds.extend(r.choice(SCENARIOS)(r))
    cmds = cmds[:target_cmd_count]
    return emit_session_text(cmds, rand_bytes(r, 64, 256))


def build_seed_binary(r: random.Random, target_cmd_count: int) -> bytes:
    text = build_seed_text(r, target_cmd_count)
    msg = fuzz_filesys_pb2.Session()
    text_format.Parse(text, msg)
    return msg.SerializeToString()


# ============================================================================
# Decode helper (so corpus entries can be inspected as text)
# ============================================================================

def decode_inputs_to_text(paths: list[str], out_dir: str | None) -> None:
    out = Path(out_dir) if out_dir else None
    if out:
        out.mkdir(parents=True, exist_ok=True)
    for path in paths:
        msg = fuzz_filesys_pb2.Session()
        msg.ParseFromString(Path(path).read_bytes())
        text = text_format.MessageToString(msg)
        if out is None:
            print(f"### {path}")
            print(text)
        else:
            (out / (Path(path).stem + ".prototxt")).write_text(text)


# ============================================================================
# CLI
# ============================================================================

def main():
    p = argparse.ArgumentParser(description="Linux fs-fuzz corpus generator")
    p.add_argument("--count", type=int, default=64,
                   help="number of seeds to generate (default: 64)")
    p.add_argument("--out", default="corpus_binary",
                   help="output directory for .pb seeds")
    p.add_argument("--cmds", type=int, default=24,
                   help="approx commands per seed (default: 24)")
    p.add_argument("--seed", type=int, default=None,
                   help="RNG seed (default: nondeterministic)")
    p.add_argument("--text-out", default=None,
                   help="if set, also write prototxt copies here")
    p.add_argument("--decode", nargs="+",
                   help="instead of generating, decode these .pb files to "
                        "prototxt on stdout (or to --text-out)")
    args = p.parse_args()

    if args.decode:
        decode_inputs_to_text(args.decode, args.text_out)
        return

    r = random.Random(args.seed)
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    text_dir = Path(args.text_out) if args.text_out else None
    if text_dir:
        text_dir.mkdir(parents=True, exist_ok=True)

    for i in range(args.count):
        n_cmds = max(4, args.cmds + r.randint(-4, 8))
        data = build_seed_binary(r, n_cmds)
        (out_dir / f"seed_{i:03d}.pb").write_bytes(data)
        if text_dir:
            (text_dir / f"seed_{i:03d}.prototxt").write_text(
                build_seed_text(r, n_cmds))

    print(f"wrote {args.count} seeds to {out_dir}")


if __name__ == "__main__":
    main()
