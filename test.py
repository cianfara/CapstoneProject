#!/usr/bin/env python3
import pefile
from collections import defaultdict
import json
import os
from PackedAnalyzer import analyze_pe
import re
import subprocess


def summarize_imports(path):
    pe = pefile.PE(path)

    imports = defaultdict(list)

    if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        # keep your old behaviour, but this is now per-file data
        return {"imports": {}, "note": "No import table found (possibly packed)."}

    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll = entry.dll.decode(errors="ignore")
        for imp in entry.imports:
            name = imp.name.decode(errors="ignore") if imp.name else None
            imports[dll].append(name)

    summary = {
        dll: sorted(func for func in funcs if func)
        for dll, funcs in sorted(imports.items())
    }

    return summary


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
            # if we can't delete it, just carry on
            pass


def getFilesToScan():
    # Read complete log file as a single string
    with open(r"lokiOut.txt", "r", encoding="utf-8", errors="ignore") as handle:
        log_text = handle.read()

    pattern = re.compile(r"FILE:\s*(.*?)\s+SCORE:")
    filepaths = pattern.findall(log_text)
    return filepaths


def runLoki(sdirectoryToScan=r"C:\\", sWorkingDir=r"C:\\"):
    lokiDir = sWorkingDir + r"\Loki"
    print(lokiDir)
    os.chdir(lokiDir)
    # Run Loki on Sample Folder, save Output as lokiOut
    subprocess.run(
        ["loki.exe", "-p", sdirectoryToScan, "-l", "lokiOut.txt"],
        shell=True
    )
    # Move Output one folder up because that is where this file is running
    subprocess.run("powershell cp lokiOut.txt ..", shell=True)
    os.chdir(sWorkingDir)
    print(f"[+] Ran Loki on directory {sdirectoryToScan}")
    return None


if __name__ == "__main__":
    directoryToScan = r"C:\Users\Adam\Desktop\Dev\sample"  # ToDo Update
    logDir = r"summary.json"                               # Output file name

    workingDirectory = os.path.dirname(os.path.abspath(__file__))
    changeDir(workingDirectory)
    clearOldLogs(logDir)

    # 1) Run Loki and parse the hit list
    runLoki(sdirectoryToScan=directoryToScan, sWorkingDir=workingDirectory)
    listofBinaries = getFilesToScan()

    samples = []  # we'll collect per-file records here

    # 2) For each binary Loki flagged, run your analyses
    for binaryToAnalyze in listofBinaries:
        clean = os.path.normpath(binaryToAnalyze)
        print(f"[+] Analyzing {clean}")

        importsResult = summarize_imports(clean)
        packedResult = analyze_pe(clean)

        # Prefer the path from analyze_pe if present
        file_path = packedResult.get("file", clean)

        # Strip the top-level 'file' key out of pe_analysis payload
        pe_analysis = {k: v for k, v in packedResult.items() if k != "file"}

        samples.append({
            "file": file_path,
            "imports": importsResult,
            "pe_analysis": pe_analysis
        })

    # 3) Write ONE valid JSON document:
    # {
    #   "samples": [ {...}, {...}, ... ]
    # }
    with open(logDir, "w", encoding="utf-8") as f:
        json.dump({"samples": samples}, f, indent=2)

    print(f"[+] Saved analysis to {logDir}")
    print("Enter any key to exit")
    input()
