# CapstoneProject
1. Takes Loki Output and filters for yara matches
2. Butchers with PEHeader checking Imports, Entropy, Signs of Packing
3. Combines report with Loki
4. Compiles to condensed JSON report
5. Send to ChatGPT. Request structured JSON reply
6. Parse Json Reply
7. (ToDo) Allow GPT to request actions with Capstone




***Install***
1. pip install pefile
2. pip install capstone
3. pip install openai
4. git clone https://github.com/cianfara/CapstoneProject
5. Download and extract Loki to Capstone Folder
https://github.com/Neo23x0/Loki/releases/tag/v0.51.0

*NB Loki may generate a false positive detection when downloading in Chrome








