import json 
import os

if __name__ == "__main__":
    workingDirectory = os.path.dirname(os.path.abspath(__file__))
    os.chdir(workingDirectory)
    with open('summary.json', 'r') as file:
        data = json.load(file)
        print(data["imports"])