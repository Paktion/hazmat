"""Extract the airlock's fixed vocabularies from the capa ruleset in the sandbox image.

    docker run --rm --platform linux/amd64 -v "$PWD":/repo hazmat-sandbox \
        python3 /repo/scripts/build_vocab.py /repo/hazmat/vocab

Writes capa_rules.txt (rule names), attack.txt (ATT&CK technique IDs) and
apis.txt (API names referenced by any rule, plus A/W variants and common libc).
These are the only strings, besides the driver's own choices, that may cross
the airlock as labels.
"""
import os
import re
import sys
from pathlib import Path

rules_dir = Path(os.environ.get("CAPA_RULES", "/opt/capa-rules"))
out = Path(sys.argv[1])

names, attack, apis = set(), set(), set()
for f in rules_dir.rglob("*.yml"):
    if ".github" in f.parts or "nursery" in f.parts:
        continue
    text = f.read_text(errors="ignore")
    m = re.search(r"^\s+name:\s*(.+?)\s*$", text, re.M)
    if m:
        names.add(m.group(1).strip("'\""))
    attack.update(re.findall(r"\[(T\d{4}(?:\.\d{3})?)\]", text))
    for api in re.findall(r"^\s*-?\s*api:\s*([A-Za-z0-9_.:@?$]+)", text, re.M):
        api = api.split(".")[-1].split("::")[-1]
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{1,63}", api):
            apis.add(api)
            if not api.endswith(("A", "W")):
                apis.update({api + "A", api + "W"})

LIBC = """printf fprintf sprintf snprintf vsnprintf puts fputs fgets fgetc fputc fopen fclose fread fwrite fseek ftell
malloc calloc realloc free memcpy memmove memset memcmp strlen strcpy strncpy strcat strcmp strncmp strchr strrchr strstr
exit _exit abort atexit getenv setenv system popen pclose fork execve execl execvp waitpid kill signal raise sleep usleep
open close read write lseek unlink stat fstat mmap munmap mprotect ptrace socket connect bind listen accept send recv
getpid getppid getuid geteuid dlopen dlsym isspace isalpha isdigit tolower toupper perror __libc_start_main
__cxa_finalize __stack_chk_fail __main __getmainargs __set_app_type _initterm _cexit _amsg_exit _onexit __C_specific_handler
__iob_func __acrt_iob_func __stdio_common_vfprintf __stdio_common_vsprintf _errno""".split()
# Common Windows APIs capa leaves out on purpose (compiler-inserted, too noisy for a rule)
WIN_EXTRA = """IsDebuggerPresent GetTickCount QueryPerformanceCounter GetCurrentProcessId GetCurrentThreadId
GetSystemTimeAsFileTime GetStartupInfoA GetStartupInfoW GetModuleHandleA GetModuleHandleW GetProcAddress
LoadLibraryA LoadLibraryW LoadLibraryExA LoadLibraryExW ExitProcess TerminateProcess GetLastError SetLastError
Sleep EnterCriticalSection LeaveCriticalSection InitializeCriticalSection DeleteCriticalSection
SetUnhandledExceptionFilter UnhandledExceptionFilter RtlCaptureContext RtlLookupFunctionEntry RtlVirtualUnwind
TlsGetValue TlsSetValue TlsAlloc TlsFree VirtualProtect VirtualQuery VirtualAlloc VirtualFree
GetCommandLineA GetCommandLineW HeapAlloc HeapFree GetProcessHeap""".split()
apis.update(LIBC + WIN_EXTRA)

out.mkdir(parents=True, exist_ok=True)
for fname, values in (("capa_rules.txt", names), ("attack.txt", attack), ("apis.txt", apis)):
    (out / fname).write_text("\n".join(sorted(values)) + "\n")
    print(f"{fname}: {len(values)}")
