# elfbrk

ELF32/ELF64 file format fuzzer, analyzer, and steganography research tool.

```
gcc -Wall -Wextra -o elfbrk elfbrk.c
```

No dependencies beyond libc.

---

## Usage

```
elfbrk <elf_file> [options ...]
```

Multiple flags can be combined in a single invocation. Analysis flags are read-only and safe on any file. Write flags modify the file in place — work on a copy.

---

## Analysis

### `--phdr`
Walk and print all program headers (segments). Shows type, file offset, virtual/physical address, file size, memory size, flags, and alignment. Supports ELF32 and ELF64.

```
elfbrk ./binary --phdr
```

### `--shdr`
Walk and print all section headers. Resolves section names from `.shstrtab`. Shows index, name, type, address, file offset, size, flags, and alignment.

```
elfbrk ./binary --shdr
```

### `--slack-count`
Enumerate every location in the file where data can be hidden without affecting execution. Shows the hex content of each region, then prints a category summary at the end.

| Tag | Source |
|-----|--------|
| `[ehdr]` | `EI_OSABI`, `EI_ABIVERSION`, `EI_PAD` (9 bytes in `e_ident`), `e_version` (4 bytes), `e_flags` if zero |
| `[phdr]` | `p_paddr` per segment — physical address field, ignored by the kernel on all virtual-memory OSes |
| `[phdr]` | `PT_NOTE` segment content — kernel maps but never validates |
| `[shdr]` | `sh_link`, `sh_info`, `sh_entsize` on sections where the loader does not use those fields |
| `[gap]`  | Alignment padding between sections in the file |
| `[over]` | Bytes past the last section / table (EOF overlay) |

```
elfbrk ./binary --slack-count
```

---

## Steganography — `p_paddr` fields

`p_paddr` (physical address) is ignored by the kernel on any OS with virtual memory. Because the program header table is mapped by `PT_PHDR`, bytes written to these fields are present in process memory at runtime without touching the file again.

Total capacity: `e_phnum × 4` bytes (ELF32) or `e_phnum × 8` bytes (ELF64).

### `--paddr-read`
Hex dump every `p_paddr` field from all program headers to stdout.

```
elfbrk ./binary --paddr-read
```

### `--paddr-read-file <file>`
Extract all `p_paddr` bytes — concatenated in segment order — and write them raw to `<file>`. Symmetric with `--paddr-write-file`.

```
elfbrk ./binary --paddr-read-file recovered.bin
```

### `--paddr-write <hexstring>`
Pack bytes from a hex string across the `p_paddr` fields in order. Bytes are packed left-to-right; the last partially-filled field is zero-padded. Accepts bare pairs or colon/dash/space-separated bytes.

```
elfbrk ./binary --paddr-write deadbeefcafebabe
elfbrk ./binary --paddr-write "de:ad:be:ef:ca:fe:ba:be"
elfbrk ./binary --paddr-write "de ad be ef"
```

### `--paddr-write-file <file>`
Same as `--paddr-write` but reads the payload from a file. Use for binary payloads (shellcode, keys, compressed data).

```
elfbrk ./binary --paddr-write-file payload.bin
```

---

## Steganography — slack regions

`--slack-write-file` and `--slack-read-file` operate on the same regions in the same order (sorted by file offset). A write followed by a read recovers the payload exactly.

### `--slack-read-file <file>`
Collect every slack region, read their bytes in file-offset order, and write the concatenated result to `<file>`. Always produces the same number of bytes as the total slack capacity regardless of what was previously written there.

```
elfbrk ./binary --slack-read-file recovered.bin
```

### `--slack-write-file <file>`
Write the contents of `<file>` into the binary's slack regions in file-offset order, scattering bytes across as many regions as needed.

Reports:
- Payload size
- Total slack capacity and region count
- Bytes written
- **Overflow**: bytes that did not fit (if payload > capacity)
- **Unused**: slack bytes remaining (if payload < capacity)

```
elfbrk ./binary --slack-write-file payload.bin
```

---

## Section and note manipulation

### `--shdr-strip`
Zeros `e_shoff`, `e_shnum`, and `e_shstrndx` in the ELF header. The binary continues to execute normally — the kernel only uses the program header table at load time. Tools that depend on section headers (`readelf -S`, `objdump`, `gdb`) lose all section visibility.

```
elfbrk ./binary --shdr-strip
```

### `--note-inject <file>`
Write the contents of `<file>` into the first `PT_NOTE` segment, bounded by that segment's `p_filesz`. The segment header and surrounding structure are untouched. The binary continues to execute normally — the kernel maps PT_NOTE segments R-- but never validates their content.

Reports bytes written and remaining capacity in the segment.

```
elfbrk ./binary --note-inject payload.bin
```

---

## Debug section manipulation

### `--debuglink-corrupt`
Flips all bits in the CRC32 field of `.gnu_debuglink`. GDB validates this CRC before loading a separate `.debug` file — a corrupted CRC causes it to silently refuse symbol loading. Prints the old and new CRC values.

```
elfbrk ./binary --debuglink-corrupt
```

### `--debuglink-path <path>`
Replaces the filename string in `.gnu_debuglink` with `<path>`. The new path must fit within the existing section (at most `section_size - 5` bytes). The existing CRC is preserved at the new aligned offset. Use to redirect debuggers to a nonexistent or poisoned debug file.

```
elfbrk ./binary --debuglink-path /tmp/fake.debug
```

### `--build-id-patch <hexstring>`
Overwrites the build ID descriptor bytes in `.note.gnu.build-id` with the supplied hex bytes. Build IDs are used by GDB, `eu-debuginfod`, and crash reporters to fetch matching debug info — a wrong ID breaks that chain. Prints old and new ID bytes.

```
elfbrk ./binary --build-id-patch deadbeefcafebabedeadbeefcafebabedeadbeef
```

### `--debug-inject <section> <file>`
Writes the contents of `<file>` into the named section, bounded by that section's size. Remainder is zero-padded. Works on any section by name — intended for injecting malformed or misleading DWARF into `.debug_info`, `.debug_line`, etc. The binary continues to execute normally.

```
elfbrk ./binary --debug-inject .debug_info payload.bin
```

### `--debug-zero`
Zeroes the content of every section whose name starts with `.debug_`. Section headers are left intact so the binary still appears to have debug sections, but their content is gone. Confuses tools (Valgrind, perf, sanitizers) that consume DWARF directly rather than through GDB.

```
elfbrk ./binary --debug-zero
```

---

## Magic patch flags

Overwrite the first 4 bytes of the ELF header (`e_ident[0..3]`) with an alternate signature. Useful for bypassing naive file-type detection. Use `--magic-patch-reset` to restore the ELF magic.

| Flag | Value | Description |
|------|-------|-------------|
| `--magic-patch` | `0xBADC0DE0` | elfbrk signature |
| `--magic-patch-reset` | `0x7F454C46` | restore ELF magic |
| `--magic-patch-slack` | `0x90909090` | NOP sled pattern |
| `--magic-patch-pk1` | `0x504B0304` | ZIP local file header |
| `--magic-patch-pk2` | `0x504B0506` | ZIP end of central directory |
| `--magic-patch-pk3` | `0x504B0708` | ZIP data descriptor |
| `--magic-patch-zb1` | `0x4D530304` | zipbrk variant 1 |
| `--magic-patch-zb2` | `0x4D530506` | zipbrk variant 2 |
| `--magic-patch-zb3` | `0x4D530708` | zipbrk variant 3 |
| `--magic-patch-dos` | `0x4D5A4CCC` | DOS MZ header |

```
elfbrk ./binary --magic-patch-pk1    # disguise as ZIP
elfbrk ./binary --magic-patch-reset  # restore
```

---

## Output format

All output uses a pipe-bordered style (`|  ...`). The ELF header dump is always printed at the end of every run reflecting the current on-disk state. A slack summary block is appended when `--slack-count` is passed.

---

## Notes

- ELF32 and ELF64 are both supported. Class is auto-detected from `EI_CLASS`.
- All offset and size arithmetic uses `uint64_t` internally to avoid overflow.
- Bounds checking is applied to every structure access before dereferencing.
- The section header table is not used by the kernel at load time. `--shdr-strip` and the `[shdr]` entries in `--slack-count` exploit this.
- `p_paddr` fields are inside the mapped `PT_PHDR` segment — payload written there is present in process memory at runtime without touching the file again.
- `--slack-read-file` and `--slack-write-file` use a fixed region ordering (sorted by file offset) so they are always symmetric regardless of what has been written.
