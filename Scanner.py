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
    directoryToScan =   r"C:\Users\Adam\Desktop\Dev\sample"      #ToDo Update
    logDir = r"summary.json"                                     #Update to change the name of the Output File
    workingDirectory = os.path.dirname(os.path.abspath(__file__))
    changeDir(workingDirectory)                                 
    clearOldLogs(logDir)                                            #Clear existing Output Logs

    runLoki(sdirectoryToScan=directoryToScan, sWorkingDir=workingDirectory)
    listofBinaries = getFilesToScan()                            #Returns a list of Binaries detected by Loiki
    
    for binaryToAnalyze in listofBinaries:
        clean = os.path.normpath(binaryToAnalyze)
        print(f"[+] Analyzing {clean}")
        importsResult = summarize_imports(binaryToAnalyze)  #Uses PEHeader to get list of imports used by binary
        packedresult = analyze_pe(binaryToAnalyze)          #Runs stastical analysis and checks for indicators of a packed binary

        with open(logDir, "a", encoding="utf-8") as f:      #Writes files to disk in JSON
            json.dump(importsResult, f, indent=2)
            json.dump(packedresult, f, indent=2)

    print(f"[+] Saved analysis to {logDir}")

    print ("Enter any key to exit")
    input()