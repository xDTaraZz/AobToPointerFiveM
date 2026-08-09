<div align="center">

```
 █████   ██████  ██████      ██████      ██████  ████████ ██████
██   ██ ██    ██ ██   ██          ██     ██   ██    ██    ██   ██
███████ ██    ██ ██████       █████      ██████     ██    ██████
██   ██ ██    ██ ██   ██     ██          ██         ██    ██   ██
██   ██  ██████  ██████      ███████     ██         ██    ██   ██
```

### Change AOB to Pointer

![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)
![Arch](https://img.shields.io/badge/Arch-x64-7C3AED?style=for-the-badge)
![Dependencies](https://img.shields.io/badge/Dependencies-none-22C55E?style=for-the-badge)

<br>

**English** · [ไทย](README.th.md)

</div>

<br>

Absolute addresses die on every restart, and offsets move on every gamebuild. Signatures survive
both. This tool walks between the two — paste bytes, get `Module.exe+OFFSET`; paste an address,
get the bytes back. One file, no dependencies, read-only.

It finds **FiveM** and **RedM** by itself on **any gamebuild**, and waits if the game isn't running yet.

<br>

## Preview

```
        +- TARGET ---------------------------------------------------------+
        |  FiveM_b3095_GTAProcess.exe   build 3095                         |
        |  pid 14820   x64   0x7FF64C120000   100 MB                       |
        +------------------------------------------------------------------+

        > 48 8B 8B 88 01 00 00 F3 0F 10 40 2C

        100 MB   0.48s

        +- MATCH ----------------------------------------------------------+
        |  > FiveM_b3095_GTAProcess.exe+1A4F3C6                            |
        |  0x7FF64DB6F3C6    0x188[rbx]  0x2C[rax]                         |
        +------------------------------------------------------------------+
```

Every result is copied to your clipboard automatically.

<br>

## Run

Needs Windows and **64-bit Python 3.8+**. Nothing to install.

```bash
py main.py
```

Pass a process name to target something else:

```bash
py main.py FiveM_GTAProcess.exe
```

> [!TIP]
> If it can't open the process, run your terminal as Administrator.

<br>

## Usage

One prompt, both directions — it decides from what you type.

**Bytes in, address out.** Spaces, commas, `0x` prefixes and `??` wildcards all work.

```
> 48 8B 8B 88 01 00 00 F3 0F 10 40 2C
> 48,8B,8B,88,01,00,00
> 48 8B 8B ?? ?? 00 00
```

**Address in, bytes out.** It grows the signature until it matches exactly one place in the module,
masking only the bytes that move between builds.

```
> FiveM_b3095_GTAProcess.exe+1A4F3C6
> +1A4F3C6
> 0x7FF64DB6F3C6
```

<br>

## Options

Add them after the bytes, on the same line. Optional.

| Option | Does |
|:--|:--|
| `+2C` | Shift the result by a hex offset |
| `rip 3:7` | Follow a `[rip+disp32]` operand to what it points at |
| `chain 0x188 0x2C` | Walk a pointer chain and show the live value |
| `all` | Scan the whole process instead of the main module |

```
> 48 8B 05 ?? ?? ?? ??  rip 3:7
> 48 8B 8B 88 01 00 00  chain 0x188 0x2C
```

<br>

## About the offsets

`48 8B 8B 88 01 00 00` is `mov rcx,[rbx+0x188]`, so `0x188` is a real field offset you can drop
straight into a pointer chain. Offsets based on `rsp` or `rbp` are hidden — those are stack slots,
not struct fields.

<br>

## Notes

Read-only. It opens the process with `PROCESS_VM_READ` and never writes, injects or hooks anything.
Built for reverse engineering and modding — how you use it on a given server is between you and
that server's rules.

<br>

---

<div align="center">

**Made by [xDTaraZz](https://github.com/xDTaraZz)** · MIT License

</div>