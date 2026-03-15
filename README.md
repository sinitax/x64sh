# x64sh

An interactive x86-64 assembly shell. Type assembly instructions at a
prompt and they are assembled, executed in a child process via `ptrace`,
and the resulting register state is displayed.

## Building

Requires a C compiler, Python 3, and `make`. Git submodules are fetched
automatically.

```
make
```

The result is a statically linked binary at `build/x64sh`.

Install to `/usr/local/bin`:

```
make install
```

## Usage

```
Usage: x64sh [-h] [-i] [-p PID] [-m SIZE]
  -h        Show help
  -i        In-place mode: reset RIP after each instruction
  -p PID    Attach to an existing process instead of forking
  -m SIZE   Shared memory region size (default 0x1000)
  -q        Quiet (errors only)
  -v / -vv  Increase verbosity
```

Run `x64sh` with no arguments to get an interactive prompt. Enter x86-64
assembly in Intel syntax. Press Enter on an empty line to re-execute the
last instruction. Ctrl-D to exit.

## Example

```
$ ./build/x64sh -q
$ mov rax, 0xdeadbeef
MEM: 48b8efbeadde00000000000000000000
ASM: mov rax, 0xdeadbeef
stepping..done
RIP: 00007f0a1234000a
RAX: 00000000deadbeef    R8:  00000000ffffffff
RBX: 0000000000200000    R9:  0000000000000000
RCX: 0000000000700000    R10: 0000000000000000
RDX: 0000000000000013    R11: 0000000000000246
RDI: 0000000000200000    R12: 00007ffd00000008
RSI: 0000000000200000    R13: 00007ffd00000018
RBP: 00007ffd00000000    R14: 0000000000000013
RSP: 00007ffd00000000    R15: 0000000000900000
EFLAGS: 0000000000000246 [ PF ZF IF ]
$ bswap eax
MEM: 0fc80000000000000000000000000000
ASM: bswap eax
stepping..done
RIP: 00007f0a1234000c
RAX: 00000000efbeadde    R8:  00000000ffffffff
...
EFLAGS: 0000000000000246 [ PF ZF IF ]
$ xor ecx, ecx
MEM: 31c90000000000000000000000000000
ASM: xor ecx, ecx
stepping..done
RIP: 00007f0a1234000e
RAX: 00000000efbeadde    R8:  00000000ffffffff
...
RCX: 0000000000000000    R10: 0000000000000000
...
EFLAGS: 0000000000000246 [ PF ZF IF ]
$ crc32 ecx, eax
MEM: f20f38f1c80000000000000000000000
ASM: crc32 ecx, eax
stepping..done
RIP: 00007f0a12340013
...
RCX: 00000000b2ddc10c    R10: 0000000000000000
...
EFLAGS: 0000000000000246 [ PF ZF IF ]
```

Each instruction shows:
- **MEM**: the raw encoded bytes poked into the child process
- **ASM**: disassembly of the encoded instruction (via XED decoder)
- **Registers**: full GPR state after single-stepping
- **EFLAGS**: decoded flag bits (CF, PF, AF, ZF, SF, TF, IF, DF, OF)

## In-place mode

With `-i`, RIP is reset to its initial position after each instruction.
This is useful for repeatedly testing the same instruction with different
register states, since the instruction is always written to the same
address.

## Testing

```
make && sh test/run.sh
```

The test suite covers various obscure x86-64 instructions including
`bswap`, `cpuid`, `rdtsc`, `crc32`, `popcnt`, `bsf`/`bsr`, `xadd`,
`aesimc`, and SSE packed operations.

## How it works

1. Forks a child process (or attaches to an existing PID with `-p`)
2. Maps a shared RWX memory region
3. Presents an interactive prompt using [bestline](https://github.com/jart/bestline)
4. Parses the assembly input and encodes it to machine code via
   [Intel XED](https://github.com/intelxed/xed)
5. Pokes the bytes into the child via `PTRACE_POKETEXT`
6. Single-steps the child with `PTRACE_SINGLESTEP`
7. Reads back and displays all registers and flags

## Dependencies

Fetched automatically as git submodules:

- [Intel XED](https://github.com/intelxed/xed) -- x86 encoder/decoder
- [bestline](https://github.com/jart/bestline) -- line editing library
- [mbuild](https://github.com/intelxed/mbuild) -- XED's build system

## License

Apache 2.0
