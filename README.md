# CapstoneProject
1. Takes Loki Output and filters for yara matches
2. Butchers with PEHeader checking Imports, Entropy, Signs of Packing
3. Combines report with Loki
4. (ToDo) Generates metadata with capstone
5. Compiles to condensed JSON report
6. Send to ChatGPT. Request structured JSON reply
7. Parse Json Reply
8. (ToDo) Allow GPT to request actions with Capstone




***Install***
1. pip3 install pefile
2. pip install capstone
3. git clone https://github.com/cianfara/CapstoneProject
4. Download and extract Loki to Capstone Folder
https://github.com/Neo23x0/Loki/releases/tag/v0.51.0

*NB Loki may generate a false positive detection when downloading in Chrome





