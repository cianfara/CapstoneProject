#!/usr/bin/env python3
import os
import re
import json
import subprocess
from collections import defaultdict

import pefile
from PackedAnalyzer import analyze_pe

# ---------- Import analysis ----------

def summarize_imports(path):
    """
    Return a dict: {dll_name: [func1, func2, ...]}.
    If no import table, returns {}.
    """
    try:
        pe = pefile.PE(path, fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
        )
    except Exception:
        return {}

    imports = defaultdict(list)

    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        return {}

    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll = entry.dll.decode(errors="ignore") if entry.dll else "UNKNOWN"
        for imp in entry.imports:
            if imp.name:
                name = imp.name.decode(errors="ignore")
                imports[dll].append(name)

    summary = {
        dll: sorted(funcs)
        for dll, funcs in sorted(imports.items())
    }
    return summary


def summarize_capabilities(imports_dict):
    """
    Small heuristic summary of what the binary *could* do based on imports.
    imports_dict: {dll: [funcs]}
    """
    dlls_lower = {dll.lower() for dll in imports_dict.keys()}
    funcs_lower = {fn.lower() for funcs in imports_dict.values() for fn in funcs}

    uses_registry = (
        "advapi32.dll" in dlls_lower and
        any(fn.startswith("reg") for fn in funcs_lower)
    )

    uses_network = any(
        d in dlls_lower
        for d in ("ws2_32.dll", "wininet.dll", "winhttp.dll", "iphlpapi.dll")
    )

    uses_crypto = any(
        d in dlls_lower
        for d in ("crypt32.dll", "bcrypt.dll", "ncrypt.dll", "rsaenh.dll")
    )

    process_injection = any(
        fn in funcs_lower
        for fn in (
            "writeprocessmemory",
            "createremotethread",
            "virtualallocex",
            "openprocess",
            "setthreadcontext",
            "queueuserapc",
        )
    )

    service_persistence = any(
        fn in funcs_lower
        for fn in (
            "createservicea",
            "createservicew",
            "changeserviceconfiga",
            "changeserviceconfigw",
            "startservicea",
            "startservicew",
        )
    )

    interesting_api_tokens = {
        "virtualalloc", "virtualallocex", "virtualprotect",
        "loadlibrarya", "loadlibraryw", "getprocaddress",
        "writeprocessmemory", "createremotethread",
        "mapviewoffile", "unmapviewoffile",
        "internetopen", "internetconnect", "httpsendrequest",
        "connect", "send", "recv",
    }

    interesting_apis = sorted(
        {fn for fn in funcs_lower for token in interesting_api_tokens if token in fn}
    )

    return {
        "uses_registry": uses_registry,
        "uses_network": uses_network,
        "uses_crypto": uses_crypto,
        "can_inject_into_other_processes": process_injection,
        "can_persist_via_services": service_persistence,
        "interesting_apis": interesting_apis,
    }


# ---------- Strings analysis ----------

def _extract_ascii_strings(path, min_len=4, max_strings=5000):
    strings = []
    current = []

    with open(path, "rb") as f:
        data = f.read()

    for b in data:
        if 32 <= b <= 126:
            current.append(chr(b))
        else:
            if len(current) >= min_len:
                strings.append("".join(current))
                if len(strings) >= max_strings:
                    break
            current = []
    if len(current) >= min_len and len(strings) < max_strings:
        strings.append("".join(current))

    return strings


def summarize_strings(path, max_sample_strings=20):
    strings = _extract_ascii_strings(path)

    domain_re = re.compile(
        r"\b[a-zA-Z0-9.-]+\.(com|net|org|info|io|co|ru|cn|de|uk|gov|edu|biz|xyz|top|club|jp|br|pl|fr|it|au|es|nl|se|no)\b"
    )
    ip_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

    suspicious_proc_names = [
        "svchost.exe", "lsass.exe", "services.exe", "winlogon.exe",
        "explorer.exe", "rundll32.exe", "smss.exe", "csrss.exe", "taskmgr.exe",
    ]

    keyword_terms = [
        "keylog", "inject", "shell", "backdoor", "rat ",
        "miner", "steal", "password", "credential",
        "hook", "persist", "autorun", "runonce", "startup",
        "update server", "botnet",
    ]

    domains = set()
    ips = set()
    suspicious_procs = set()
    keywords = set()

    for s in strings:
        for m in domain_re.finditer(s):
            domains.add(m.group(0).lower())

        for m in ip_re.finditer(s):
            ip = m.group(0)
            octets = ip.split(".")
            try:
                if all(0 <= int(o) <= 255 for o in octets):
                    ips.add(ip)
            except ValueError:
                pass

        lower_s = s.lower()

        for p in suspicious_proc_names:
            if p in lower_s:
                suspicious_procs.add(p)

        for kw in keyword_terms:
            if kw in lower_s:
                keywords.add(kw.strip())

    sample_strings = strings[:max_sample_strings]

    return {
        "num_strings": len(strings),
        "sample_strings": sample_strings,
        "domains": sorted(domains),
        "ips": sorted(ips),
        "suspicious_process_names": sorted(suspicious_procs),
        "keywords": sorted(keywords),
    }


# ---------- Code summary (Capstone) ----------

def summarize_code(path, max_instructions=64):
    """
    Use Capstone (if available) to take a small window of instructions at EP
    and summarise basic instruction mix.
    """
    try:
        import capstone
    except ImportError:
        return {"note": "capstone not installed; code summary unavailable"}

    try:
        pe = pefile.PE(path, fast_load=False)
    except Exception as e:
        return {"error": f"failed_to_parse_pe: {e!s}"}

    try:
        is_64 = pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_AMD64"]
    except Exception:
        is_64 = False

    arch = capstone.CS_ARCH_X86
    mode = capstone.CS_MODE_64 if is_64 else capstone.CS_MODE_32

    ep_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    ep_offset = pe.get_offset_from_rva(ep_rva)

    # Small window of bytes at EP
    data = pe.__data__[ep_offset:ep_offset + max_instructions * 16]

    md = capstone.Cs(arch, mode)
    md.detail = False

    total = 0
    call_count = 0
    jump_count = 0
    push_count = 0
    xor_count = 0
    mnemonic_counts = defaultdict(int)

    for insn in md.disasm(data, pe.OPTIONAL_HEADER.ImageBase + ep_rva):
        total += 1
        m = insn.mnemonic.lower()
        mnemonic_counts[m] += 1

        if m == "call":
            call_count += 1
        elif m.startswith("j"):  # jmp, jz, jne, etc.
            jump_count += 1
        elif m == "push":
            push_count += 1
        elif m == "xor":
            xor_count += 1

        if total >= max_instructions:
            break

    top_mnemonics = sorted(
        mnemonic_counts.items(), key=lambda kv: kv[1], reverse=True
    )[:10]

    return {
        "ep_offset": ep_offset,
        "instructions_analyzed": total,
        "num_calls": call_count,
        "num_jumps": jump_count,
        "num_push": push_count,
        "num_xor": xor_count,
        "top_mnemonics": top_mnemonics,
    }


# ---------- Utility helpers ----------

def changeDir(newTargetDir):
    os.chdir(newTargetDir)
    fworking_directory = os.getcwd()
    print(f"[+] Working Directory is: {fworking_directory}")
    return None


def clearOldLogs(file_to_delete):
    if os.path.exists(file_to_delete):
        try:
            os.remove(file_to_delete)
            print(f"[+] Removed old log file: {file_to_delete}")
        except OSError:
            pass


def getFilesToScan():
    # Read complete Loki log file
    with open("lokiOut.txt", "r", encoding="utf-8", errors="ignore") as handle:
        log_text = handle.read()

    pattern = re.compile(r"FILE:\s*(.*?)\s+SCORE:")
    filepaths = pattern.findall(log_text)
    return filepaths


def runLoki(sdirectoryToScan=r"C:\\", sWorkingDir=r"C:\\"):
    lokiDir = os.path.join(sWorkingDir, "Loki")
    print(lokiDir)
    os.chdir(lokiDir)
    # Run Loki on Sample Folder, save Output as lokiOut.txt
    subprocess.run(
        ["loki.exe", "-p", sdirectoryToScan, "-l", "lokiOut.txt"],
        shell=True,
        check=False,
    )
    # Move Output one folder up because that is where this file is running
    subprocess.run("powershell cp lokiOut.txt ..", shell=True, check=False)
    os.chdir(sWorkingDir)
    print(f"[+] Ran Loki on directory {sdirectoryToScan}")
    return None


# ---------- Main ----------

if __name__ == "__main__":
    directoryToScan = r"C:\Users\Adam\Desktop\Dev\sample"   # Folder to scan
    logDir = "summary.json"                                 # Output file

    workingDirectory = os.path.dirname(os.path.abspath(__file__))
    changeDir(workingDirectory)
    clearOldLogs(logDir)

    # 1) Run Loki and parse the hit list
    runLoki(sdirectoryToScan=directoryToScan, sWorkingDir=workingDirectory)
    listofBinaries = getFilesToScan()

    samples = []

    # 2) For each binary Loki flagged, run analyses
    for binaryToAnalyze in listofBinaries:
        clean = os.path.normpath(binaryToAnalyze)
        print(f"[+] Analyzing {clean}")

        importsResult = summarize_imports(clean)
        packedResult = analyze_pe(clean)
        capabilities = summarize_capabilities(importsResult)
        strings_summary = summarize_strings(clean)
        code_summary = summarize_code(clean)

        file_path = packedResult.get("file", clean)
        pe_analysis = {k: v for k, v in packedResult.items() if k != "file"}

        samples.append({
            "file": file_path,
            "imports": importsResult,
            "capabilities": capabilities,
            "strings_summary": strings_summary,
            "code_summary": code_summary,
            "pe_analysis": pe_analysis,
        })

    # 3) Write single valid JSON document
    with open(logDir, "w", encoding="utf-8") as f:
        json.dump({"samples": samples}, f, indent=2)

    print(f"[+] Saved analysis to {logDir}")
    print("Enter any key to exit")
    input()
