#!/usr/bin/env python3
import pefile
from collections import defaultdict
import json
import os
from PackedAnalyzer import analyze_pe
from GPTAnalysis import sendLogsToGPT
import re
import subprocess

directoryToScan =   r"C:\Users\Adam\Desktop\Dev\sample"       #Update to change the scanning target
logDir = r"summary.json"                                      #Update to change the name of the Output File
dllConfigPath = "import_config.json"                          #Update to change what DLLs are considered suspicious or benign. 
                                                              #This is used to summarize and reduce bloat in the summary.json file
                                                              #You can also specify the max number of functions per DLL


DEFAULT_IMPORT_CONFIG = {                                     #Do not modify, only used in the case where DLL config is not found
    "noisy_gui_dlls": [],
    "interesting_dlls": [],
    "suspicious_apis": [],
    "suspicious_keywords": [],
    "max_funcs_per_dll": 20,
}



def summarize_imports(path):
    pe = pefile.PE(path)

    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        return {
            "num_imports": 0,
            "imports_by_dll": {},
            "sample_imports": {},
            "suspicious_apis": [],
            "note": "No import table found (possibly packed).",
        }

    imports = defaultdict(list)

    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll_raw = entry.dll or b""
        dll = dll_raw.decode(errors="ignore").lower()
        for imp in entry.imports:
            if imp.name:
                func_name = imp.name.decode(errors="ignore")
            else:
                # fall back to ordinal if no name
                func_name = f"ord_{imp.ordinal}"
            imports[dll].append(func_name)

    # Basic counts
    total_imports = sum(len(funcs) for funcs in imports.values())
    imports_by_dll = {dll: len(funcs) for dll, funcs in imports.items()}

    sample_imports = {}
    suspicious_apis = set()

    for dll, funcs in imports.items():
        # Decide if this DLL is considered "noisy"
        dll_is_noisy = dll in NOISY_GUI_DLLS and dll not in INTERESTING_DLLS

        # Only keep a small sample of functions per DLL, or all if DLL is small
        if dll_is_noisy and len(funcs) > MAX_FUNCS_PER_DLL:
            # For noisy GUI DLLs with tons of imports, just skip listing them
            # They still show up in imports_by_dll as a count.
            sampled = []
        else:
            sampled = funcs[:MAX_FUNCS_PER_DLL]

        # Save sample imports (maybe empty list)
        if sampled:
            sample_imports[dll] = sorted(set(sampled))

        # Check for suspicious APIs
        for f in funcs:
            base_name = f.split("@", 1)[0]  # strip stdcall decorations if any
            if base_name in SUSPICIOUS_APIS:
                suspicious_apis.add(f"{dll}!{base_name}")
                continue

            lower_name = base_name.lower()
            if any(keyword in lower_name for keyword in SUSPICIOUS_KEYWORDS):
                suspicious_apis.add(f"{dll}!{base_name}")

    return {
        "num_imports": total_imports,
        "imports_by_dll": imports_by_dll,   # DLL -> count
        "sample_imports": sample_imports,   # DLL -> small list of names
        "suspicious_apis": sorted(suspicious_apis),
    }


def parse_loki_results(log_path="lokiOut.txt"):
    """
    Parse lokiOut.txt and return a dict:
        { "C:\\path\\file.exe": { ...loki_metadata... }, ... }
    """
    loki_by_file = {}

    if not os.path.exists(log_path):
        print(f"[!] Loki output not found at {log_path}")
        return loki_by_file

    with open(log_path, "r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            # Only care about per-file hits
            if "MODULE: FileScan" not in line or "FILE:" not in line:
                continue

            # File path
            file_match = re.search(r"FILE:\s*(.*?)\s+SCORE:", line)
            if not file_match:
                continue
            path = file_match.group(1).strip()

            # Basic numeric / text fields
            score_match = re.search(r"SCORE:\s*(\d+)", line)
            file_type_match = re.search(r"TYPE:\s*(\S+)", line)
            size_match = re.search(r"SIZE:\s*(\d+)", line)

            md5_match = re.search(r"MD5:\s*([0-9a-fA-F]+)", line)
            sha1_match = re.search(r"SHA1:\s*([0-9a-fA-F]+)", line)
            sha256_match = re.search(r"SHA256:\s*([0-9a-fA-F]+)", line)

            reason_match = re.search(r"REASON_1:\s*(.*?)\s+MATCH:", line)
            rule_match = re.search(r"MATCH:\s*(\S+)", line)
            subscore_match = re.search(r"SUBSCORE:\s*(\d+)", line)
            desc_match = re.search(r"DESCRIPTION:\s*(.*?)\s+REF:", line)

            # MATCHES: $a3: 'Hello', $a5: '\Adam\'
            matches_match = re.search(r"MATCHES:\s*(.*)$", line)
            matched_strings = []
            if matches_match:
                matches_raw = matches_match.group(1).strip()
                # grab all the quoted strings
                matched_strings = re.findall(r"'([^']*)'", matches_raw)

            loki_by_file[path] = {
                "score": int(score_match.group(1)) if score_match else None,
                "type": file_type_match.group(1) if file_type_match else None,
                "size": int(size_match.group(1)) if size_match else None,
                "hashes": {
                    "md5": md5_match.group(1) if md5_match else None,
                    "sha1": sha1_match.group(1) if sha1_match else None,
                    "sha256": sha256_match.group(1) if sha256_match else None,
                },
                "reason": reason_match.group(1).strip() if reason_match else None,
                "rule": rule_match.group(1) if rule_match else None,
                "subscore": int(subscore_match.group(1)) if subscore_match else None,
                "description": desc_match.group(1).strip() if desc_match else None,
                "matched_strings": matched_strings,
                # Optional raw line for debugging:
                # "raw": line.strip(),
            }

    return loki_by_file

def changeDir(newTargetDir): #No Default as system gets file path before this
    os.chdir(newTargetDir)
    fworking_directory = os.getcwd()
    print(f"[+] Working Directory is: {fworking_directory}") #Verify we Moved to folder where ScanDir will be found
    return None

def clearOldLogs(file_to_delete):
    if os.path.exists(file_to_delete):
        try:
            os.remove(file_to_delete)
            print(f"[+] Removed old log file: {file_to_delete}")
        except OSError as e:
            pass
    else:
        pass




def load_import_config(path="import_config.json"):
    cfg = DEFAULT_IMPORT_CONFIG.copy()

    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                file_cfg = json.load(f)
            # Only override known keys
            for key, value in file_cfg.items():
                if key in cfg:
                    cfg[key] = value
        except Exception as e:
            print(f"[!] Failed to load {path}: {e}")
            print("[!] Using built-in defaults for import config.")

    return cfg





def load_import_config(path="import_config.json"):
    cfg = DEFAULT_IMPORT_CONFIG.copy()

    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                file_cfg = json.load(f)
            # Only override known keys
            for key, value in file_cfg.items():
                if key in cfg:
                    cfg[key] = value
        except Exception as e:
            print(f"[!] Failed to load {path}: {e}")
            print("[!] Using built-in defaults for import config.")

    return cfg

def getFilesToScan():
    handle = open(r"lokiOut.txt","r")
    log_text = str(handle.readlines())
    pattern = re.compile(r"FILE:\s*(.*?)\s+SCORE:")
    filepaths = pattern.findall(log_text)
    #print("paths")
    #print(filepaths)
    return filepaths


def runLoki(sdirectoryToScan=r"C:\\", sWorkingDir=r"C:\\"): #Safe Default Dir to Scan and save Log
    lokiDir = sWorkingDir + r"\Loki"
    print(lokiDir)
    os.chdir(lokiDir)                                                                       #Change to lokiDir to run Loki
    subprocess.run(["loki.exe", "-p", sdirectoryToScan, "-l", "lokiOut.txt"], shell=True)   #Run Loki on Sample Folder, save Output as lokiOut
    subprocess.run("powershell cp lokiOut.txt ..", shell=True)                              #Move Output one folder up because that is where this file is running
    os.chdir(sWorkingDir)
    print(f"[+] Ran Loki on directory {sdirectoryToScan}")                                                                   #Return to old working directory
    return None

print(f"[+] Attempting to Load dll suspicious Configuration from {dllConfigPath}")
IMPORT_CONFIG = load_import_config(dllConfigPath)
NOISY_GUI_DLLS = set(IMPORT_CONFIG["noisy_gui_dlls"])
INTERESTING_DLLS = set(IMPORT_CONFIG["interesting_dlls"])
SUSPICIOUS_APIS = set(IMPORT_CONFIG["suspicious_apis"])
SUSPICIOUS_KEYWORDS = list(IMPORT_CONFIG["suspicious_keywords"])
MAX_FUNCS_PER_DLL = int(IMPORT_CONFIG["max_funcs_per_dll"])


if __name__ == "__main__":

    workingDirectory = os.path.dirname(os.path.abspath(__file__)) #Find where this script is running from
    changeDir(workingDirectory) 
    clearOldLogs(logDir)                                          #Clear existing Output Logs

    runLoki(sdirectoryToScan=directoryToScan, sWorkingDir=workingDirectory)                            
    loki_results = parse_loki_results("lokiOut.txt")

    # Files to analyze come from Loki hits
    listofBinaries = list(loki_results.keys())                     #Returns a list of Binaries detected by Loki by running Regex on the Output log
    results = []

    for binaryToAnalyze in listofBinaries:
        clean = os.path.normpath(binaryToAnalyze)
        print(f"[+] Analyzing {clean}")
        importsResult = summarize_imports(binaryToAnalyze)
        packedresult = analyze_pe(binaryToAnalyze)
        loki_info = loki_results.get(binaryToAnalyze, {})
        # Build a combined object per file
        results.append({
            "path": clean,
            "loki": loki_info,          # <-- Loki score, hashes, rule, matched strings
            "imports": importsResult,   # existing pefile summary
            "packing": packedresult,    # your PackedAnalyzer output
            # ToDo: capstone, strings, etc. can hang off here later
        })

    # Now that loop is done we write as a single structure
    with open(logDir, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print(f"[+] Saved analysis to {logDir}")
    print(f"[+] Sending Logs to GPT")
    print("Hold")
    input()
    GPTResult = sendLogsToGPT()
    if GPTResult==None:
        print(f"[+] GPT Response not Recieved")
    else:
        print(f"[+] GPT Response Recieved")

    print ("Enter any key to exit")
    input()