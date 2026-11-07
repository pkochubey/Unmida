# Unmida

Unmida is a Windows command-line unpacker for x86 and x64 executables and DLLs protected with Themida.

Unmida runs the target under a debugger and waits for the protector to unpack it in memory. For native targets it locates the original entry point (OEP), reconstructs the import address table (IAT), and writes a new Portable Executable (PE) file. Use it on binaries you are authorized to analyze. Run untrusted targets in an isolated Windows VM.

## Build from source

Install [Go 1.25.4 or newer](https://go.dev/doc/install) and run the following from the project root in PowerShell.

```powershell
.\build.ps1
```

The script produces `Unmida32.exe` (`windows/386`) and `Unmida64.exe` (`windows/amd64`) in the project root with CGO disabled. The instruction decoder comes from `golang.org/x/arch`, pinned in `go.mod`.

## ScyllaHide setup

ScyllaHide helps the debugger handle Themida's anti-debugging checks. Keep the supplied [`scylla_hide.ini`](scylla_hide.ini) beside the Unmida executable.

For **x64**, download the compatible ScyllaHide bundle from the upstream release asset.

```powershell
curl.exe --fail --location --header 'Accept: application/octet-stream' `
  --output scyllahide-x64.zip https://api.github.com/repositories/441734472/releases/assets/420483178
```

Extract `InjectorCLIx64.exe` and `HookLibraryx64.dll` from the archive and place them next to `Unmida64.exe`. This injector meets the minimum PE timestamp of `0x6484FEF9`.

For **x86**, Unmida has built-in anti-debugging workarounds. To use ScyllaHide, copy `InjectorCLIx86.exe` and `HookLibraryx86.dll` from the [ScyllaHide releases](https://github.com/x64dbg/ScyllaHide/releases) next to `Unmida32.exe`.

## Unpack a file

Choose the Unmida executable that matches the target's architecture. Pass the target path directly or prefix it with `/unpack`.

```powershell
.\Unmida32.exe 'C:\samples\target32.exe'
.\Unmida64.exe /unpack 'C:\samples\target64.dll'
.\Unmida32.exe 'C:\samples\target32.exe' --no-data --parameters '--mode demo'
.\Unmida64.exe --help
```

- `--parameters <command line>` passes one string of arguments to the target EXE.
- `--no-data` skips the automatic `.rdata` and `.data` reconstruction attempted for eligible native PE32 dumps.

The dump normally goes beside the input with `U` inserted before the extension, for example `target.exe` becomes `targetU.exe` and `target.dll` becomes `targetU.dll`. If the output path is denied, Unmida tries the current working directory. An existing file at the chosen output path can be overwritten.

Exit codes are `0` for success or requested help, `1` for an operation failure, and `2` for invalid arguments or an invocation without arguments. Progress goes to standard output and errors go to standard error.

## Post-processing PE32 dumps

| Command | Effect |
| --- | --- |
| `/mkdata <file>` | Reconstructs `.rdata` and `.data` for eligible PE32 images, including certain MSVC builds. Updates the file in place. |
| `/shrink <file>` | Removes sections that the shrink heuristics consider unused. Updates the file in place. Use a copy because the operation can break non-MSVC images or code that still relies on virtualized sections. |
| `/dump <PID> <file>` | Copies the code region of a running process's main module into a copy of the supplied PE32 dump. The process must match the supplied image. For `targetU.exe`, the output is `targetU.novm.exe`. |

```powershell
.\Unmida32.exe /mkdata 'C:\samples\targetU.exe'
.\Unmida32.exe /dump 1234 'C:\samples\targetU.exe'
.\Unmida32.exe /shrink 'C:\samples\targetU.exe'
```

## Limitations

- Results depend on the Themida version, protection settings, target compiler, and Windows environment. Verify the dump against your target.
- Virtualized code and VM anti-dump protections can leave a dump unable to run.
- DLL dumps may lack relocation information and fail to load if their preferred base address is unavailable.
- Windows compatibility shims can interfere with tracing. Turn off compatibility mode for Unmida and the target.

## License

Unmida is distributed under the [GNU General Public License, version 3](LICENSE).
