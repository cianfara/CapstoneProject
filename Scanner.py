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

def summarize_imports(path):
    pe = pefile.PE(path)

    imports = defaultdict(list)

    if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
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


if __name__ == "__main__":
    workingDirectory = os.path.dirname(os.path.abspath(__file__)) #Find where this script is running from
    changeDir(workingDirectory)                                 
    clearOldLogs(logDir)                                          #Clear existing Output Logs

    runLoki(sdirectoryToScan=directoryToScan, sWorkingDir=workingDirectory)
    listofBinaries = getFilesToScan()                             #Returns a list of Binaries detected by Loki by running Regex on the Output log

    results = []

    for binaryToAnalyze in listofBinaries:
        clean = os.path.normpath(binaryToAnalyze)
        print(f"[+] Analyzing {clean}")
        importsResult = summarize_imports(binaryToAnalyze)
        packedresult = analyze_pe(binaryToAnalyze)

        # Build a combined object per file
        results.append({
            "path": clean,
            "imports": importsResult,
            "packing": packedresult,
            # ToDo: add capstone, strings, etc. here
        })

    # Now that loop is done we write as a single structure
    with open(logDir, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print(f"[+] Saved analysis to {logDir}")
    print(f"[+] Sending Logs to GPT")
    GPTResult = sendLogsToGPT()
    if GPTResult==None:
        print(f"[+] GPT Response not Recieved")
    else:
        print(f"[+] GPT Response Recieved")

    print ("Enter any key to exit")
    input()