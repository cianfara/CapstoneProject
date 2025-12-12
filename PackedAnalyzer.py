#!/usr/bin/env python3
import argparse
import json
import os
import sys
from pathlib import Path

import pefile

SUSPICIOUS_SECTION_NAMES = {
    "UPX0", "UPX1", "UPX2",
    ".aspack", ".petite", ".themida",
    ".packed", ".upx"
}

# APIs commonly used in unpacking / injection stubs
SUSPICIOUS_APIS = {
    "virtualalloc", "virtualallocex", "virtualprotect",
    "loadlibrarya", "loadlibraryw", "getprocaddress",
    "writeprocessmemory", "createremotethread",
    "mapviewoffile", "ntunmapviewofsection"
}

IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_FILE_RELOCS_STRIPPED = 0x0001


def get_ep_section(pe):
    ep_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    ep_va = ep_rva + pe.OPTIONAL_HEADER.ImageBase
    for s in pe.sections:
        start = s.VirtualAddress + pe.OPTIONAL_HEADER.ImageBase
        end = start + s.Misc_VirtualSize
        if start <= ep_va < end:
            name = s.Name.rstrip(b"\x00").decode(errors="ignore") or "<unnamed>"
            return name
    return None

def doNothing():
    pass

def analyze_pe(path):
    pe = pefile.PE(path, fast_load=False)
    filesize = os.path.getsize(path)

    result = {
        "file": str(Path(path).resolve()),
        "size_bytes": filesize,
        "num_sections": pe.FILE_HEADER.NumberOfSections,
        "packed_score": 0,
        "sections": [],
        "high_entropy_sections": [],
        "suspicious_section_names": [],
        "entry_point_section": None,
        "num_imports": 0,
        "imports_by_dll": {},  #Used only for Calculations, Removed before return
        "suspicious_apis": [], #Used only for Calculations, Removed before Return
        "overlay_size": 0,
        "relocations_stripped": False,
        "entropy_mean": None,
        "entropy_max": None,
    }

    # ---- Sections / entropy ----
    entropies = []
    high_entropy_sections = []
    suspicious_section_names = []

    for s in pe.sections:
        name = s.Name.rstrip(b"\x00").decode(errors="ignore") or "<unnamed>"
        entropy = s.get_entropy()
        is_executable = bool(s.Characteristics & IMAGE_SCN_MEM_EXECUTE)

        section_info = {
            "name": name,
            "entropy": entropy,
            "size_raw": int(s.SizeOfRawData),
            "size_virtual": int(s.Misc_VirtualSize),
            "is_executable": is_executable,
        }
        result["sections"].append(section_info)

        if entropy is not None:
            entropies.append(entropy)
            if entropy > 7.2 and s.SizeOfRawData > 1024:
                high_entropy_sections.append(name)
                # Executable high-entropy section is a big hint
                result["packed_score"] += 15 if is_executable else 8

        if name in SUSPICIOUS_SECTION_NAMES:
            suspicious_section_names.append(name)
            result["packed_score"] += 20

    result["high_entropy_sections"] = high_entropy_sections
    result["suspicious_section_names"] = suspicious_section_names

    if entropies:
        result["entropy_mean"] = sum(entropies) / len(entropies)
        result["entropy_max"] = max(entropies)

    # ---- Entry point section ----
    ep_section = get_ep_section(pe)
    result["entry_point_section"] = ep_section
    if ep_section is not None and ep_section not in (".text", "CODE"):
        result["packed_score"] += 15

    # ---- Imports + suspicious APIs ----
    suspicious_apis_found = []
    imports_by_dll = {}
    total_imports = 0

    try:
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
        )

        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = (
                    entry.dll.decode(errors="ignore").lower()
                    if entry.dll else ""
                )
                for imp in entry.imports:
                    if imp.name:
                        api_name = imp.name.decode(errors="ignore")
                        total_imports += 1
                        imports_by_dll[dll_name] = imports_by_dll.get(dll_name, 0) + 1

                        lower_api = api_name.lower()
                        for token in SUSPICIOUS_APIS:
                            if token in lower_api:
                                suspicious_apis_found.append(api_name)
                                break
    except Exception:
        # don't crash analysis on broken import tables
        pass

    result["num_imports"] = total_imports
    result["imports_by_dll"] = imports_by_dll
    result["suspicious_apis"] = sorted(set(suspicious_apis_found))

    # Few imports on a big file is suspicious
    if filesize > 200 * 1024 and total_imports <= 5:
        result["packed_score"] += 20

    if result["suspicious_apis"]:
        result["packed_score"] += 10

    # ---- Overlay (data after last section) ----
    overlay_size = 0
    if pe.sections:
        last = max(
            pe.sections,
            key=lambda s: s.PointerToRawData + s.SizeOfRawData
        )
        last_end = last.PointerToRawData + last.SizeOfRawData
        if last_end < filesize:
            overlay_size = filesize - last_end
            result["packed_score"] += 10

    result["overlay_size"] = overlay_size

    # ---- Relocations stripped ----
    reloc_stripped = bool(pe.FILE_HEADER.Characteristics & IMAGE_FILE_RELOCS_STRIPPED)
    result["relocations_stripped"] = reloc_stripped
    if reloc_stripped:
        result["packed_score"] += 5

    # ---- Final verdict ----
    score = max(0, min(result["packed_score"], 100))
    result["packed_score"] = score

    if score >= 70:
        verdict = "likely_packed"
    elif score >= 40:
        verdict = "possibly_packed"
    else:
        verdict = "unlikely_packed"

    result.pop("suspicious_apis")           #This data using customised filters for detecting packed stubs 
    result.pop("imports_by_dll")            #The info for GPT is added in the main scanner
    result.pop("num_imports")               #This will be steamlined in the future
 
    result["packed_verdict"] = verdict      
                                            



    pe.close()
    return result


def main():
    parser = argparse.ArgumentParser(
        description="Heuristic packed-file analysis for PE files (for LOKI follow-up)."
    )
    parser.add_argument("file", help="Path to a PE file (exe/dll/sys, etc.)")
    args = parser.parse_args()

    path = args.file
    if not os.path.isfile(path):
        print(f"Error: '{path}' is not a file", file=sys.stderr)
        sys.exit(1)

    try:
        res = analyze_pe(path)
    except pefile.PEFormatError as e:
        print(json.dumps({
            "file": str(Path(path).resolve()),
            "error": "not_a_pe",
            "details": str(e),
        }, indent=2))
        sys.exit(0)

    print(json.dumps(res, indent=2))
    out = r"summary.json"  # output file

    # Write to JSON file
    with open(out, "a", encoding="utf-8") as f:
        json.dump(res, f, indent=2)


if __name__ == "__main__":
    main()
