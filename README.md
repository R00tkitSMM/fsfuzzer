# Filesystem Fuzzer

This directory contains a filesystem fuzzing harness built around protobuf-based
inputs.

The current setup uses binary protobuf inputs end to end:

- `gen_corpus.py` generates binary protobuf seeds
- the harness saves recovery inputs as binary protobuf files
- `fuzz_filesys` accepts binary protobuf inputs
- `fork_base` accepts binary protobuf inputs

## Python Setup

Create and activate a Python virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install the protobuf Python runtime:

```bash
python3 -m pip install --upgrade pip
python3 -m pip install protobuf
```

Verify the protobuf runtime is available:

```bash
python3 -c "from google.protobuf import text_format; print('protobuf ok')"
```

## Build

The build script uses Homebrew LLVM/Clang and also generates both C++ and Python
protobuf bindings.

Run:

```bash
./build.sh
```

This generates:

- `fuzz_filesys.pb.cc`
- `fuzz_filesys.pb.h`
- `fuzz_filesys_pb2.py`
- `fuzz_filesys`
- `fork_base`

## Generate Binary Seeds

Generate a corpus of binary protobuf seeds:

```bash
python3 gen_corpus.py --count 100
```

By default this writes binary `.pb` files into:

```text
corpus_binary/
```

These are binary protobuf files, not textproto files.

## Run The Harness

Run the main harness on the generated corpus:

```bash
./fuzz_filesys corpus_binary
```

Run the fork-based harness:

```bash
./fork_base corpus_binary
```

Both harnesses use `DEFINE_BINARY_PROTO_FUZZER`, so they expect binary protobuf
inputs.

## Replay A Saved Input

You can replay a saved input directly:

```bash
./fuzz_filesys ~/fuzz_save/last_input_0.pb
./fork_base ~/fuzz_save/last_input_0.pb
```

Since the harness is binary-protobuf based, saved `.pb` files can be replayed
directly.

## Saved Recovery Inputs

Before executing an input, the harness saves the testcase to:

```text
~/fuzz_save/
```

It rotates between:

- `last_input_0.pb`
- `last_input_1.pb`

These files are written as binary protobuf and flushed for durability so they
can still be available after a crash or panic.

If the system panics, test both files.

## Notes

- Old textproto corpus files are not compatible with the current binary harness.
- If you still have older text-based seeds, they need to be converted before
  replaying with the current setup.
- The command logging printed by the harness comes from decoding the binary
  protobuf input and printing each `Command` oneof name before execution.
