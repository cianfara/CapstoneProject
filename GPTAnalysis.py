from openai import OpenAI
import json
import os
from typing import Any

SUMMARY_PATH = r"summary.json"




def load_scan_json(path: str = SUMMARY_PATH) -> str:
    """
    Load the JSON file and return it as a string.
    We send the raw text so the model sees exactly what you see.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"{path} not found. Did you run Scanner.py first?")

    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def ask_openai_for_triage(scan_json_text: str) -> str:
    """
    Send the Loki/PEfile results to OpenAI and get a triage summary back.
    """
    client = OpenAI()

    # System / dev instructions: what you want the model to do
    instructions = """
You are a DFIR malware triage assistant.

You will receive JSON output from a scanner that includes:
- file path
- PE import table summary
- basic packing indicators (entropy, section anomalies, etc.)

Your job:
1. Group findings by file path.
2. For each file, estimate a priority: "high", "medium", or "low" investigation priority.
3. Explain briefly WHY (e.g., suspicious imports, packing indicators, Loki score if present).
4. Flag any strong indicators of malware vs likely false positives.

Respond ONLY in JSON with this exact shape:

{
  "summary": "Short overview of the scan result",
  "files": [
    {
      "path": "string",
      "priority": "high" | "medium" | "low",
      "risk_score": 0-100,
      "suspicious_indicators": [
        "short description 1",
        "short description 2"
      ],
      "comment": "one or two sentence explanation"
    }
  ]
}
"""

    # We use the Responses API, which is the recommended interface now. :contentReference[oaicite:2]{index=2}
    response = client.responses.create(
        model="gpt-5.1", 
        # enforce JSON output format
        text={
            "format": {
                "type": "json_object"
            }
        },
        instructions=instructions,
        temperature=0,
        input=[
            {
                "role": "user",
                "content": (
                    "Here is the scan JSON to analyze:\n\n"
                    "```json\n"
                    f"{scan_json_text}\n"
                    "```"
                ),
            }
        ],
    )

    # For simple text responses, SDK exposes output_text helper. :contentReference[oaicite:3]{index=3}
    return response.output_text

def changeDir(newTargetDir): #No Default as system gets file path before this
    os.chdir(newTargetDir)
    return os.getcwd()


def sendLogsToGPT(sPath=SUMMARY_PATH):
    workingDirectory = os.path.dirname(os.path.abspath(__file__)) #Find where this script is running from
    changeDir(workingDirectory)
    scan_json_text = load_scan_json(sPath)
    print(f"[+] Please wait for GPT Response")
    result_json_str = ask_openai_for_triage(scan_json_text)

    print("\n=== OpenAI triage result (JSON) ===\n")

    # Optional: save the model's triage to disk
    with open("triage_result.json", "w", encoding="utf-8") as f:
        f.write(result_json_str)
    return result_json_str

if __name__ == "__main__":
    sendLogsToGPT()
