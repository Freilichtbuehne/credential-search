import os
import argparse
import re
from threading import Thread
import time

# api and token patterns are inspired by https://github.com/trufflesecurity/truffleHog
patterns = {
    "Keys" : {
        "RSA private key": "-----BEGIN RSA PRIVATE KEY-----",
        "SSH (OPENSSH) private key": "-----BEGIN OPENSSH PRIVATE KEY-----",
        "SSH (DSA) private key": "-----BEGIN DSA PRIVATE KEY-----",
        "SSH (EC) private key": "-----BEGIN EC PRIVATE KEY-----",
        "PGP private key block": "-----BEGIN PGP PRIVATE KEY BLOCK-----",
        "Generic private key": "-{2,7}BEGIN.{0,15}PRIVATE KEY.{0,15}-{2,7}",
    },
    "APIKeys": {
        "AWS API Key": "(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
        "Heroku API Key": "[h|H][e|E][r|R][o|O][k|K][u|U].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
        "Generic Secret": "[s|S][e|E][c|C][r|R][e|E][t|T].{0,30}['\"\\s][0-9a-zA-Z]{32,45}['\"\\s]",
        "Generic API Key": "[a|A][p|P][i|I][_]?[k|K][e|E][y|Y].{0,30}['\"\\s][0-9a-zA-Z]{32,45}['\"\\s]",
        "Twilio API Key": "SK[a-z0-9]{32}",
    },
    "Oauth": {
        "Facebook Oauth": "[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].{0,30}['\"\\s][0-9a-f]{32}['\"\\s]",
        "Twitter Oauth": "[t|T][w|W][i|I][t|T][t|T][e|E][r|R].{0,30}['\"\\s][0-9a-zA-Z]{35,44}['\"\\s]",
        "Google Oauth": "(\"client_secret\":\"[a-zA-Z0-9-_]{24}\")",
    },
    "Accounts": {
        "Slack Token": "(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})",
        "GitHub": "[g|G][i|I][t|T][h|H][u|U][b|B].{0,30}['\"\\s][0-9a-zA-Z]{35,40}['\"\\s]",
        "Generic Secret": "[s|S][e|E][c|C][r|R][e|E][t|T].{0,30}['\"\\s][0-9a-zA-Z]{32,45}['\"\\s]",
        "Slack Webhook": "https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
        "Google (GCP) Service-account": "\"type\": \"service_account\"",
    },
    #TODO: Add some more applications
    "ApplicationSpecific":{
        "FileZilla Export": '<Pass encoding="base64">|<FileZilla\d version=\"',
        "Putty Keyfile": "^PuTTY-User-Key-File-\d:",
        "Chrome/Edge Password Export": "^name,url,username,password\n",
        "WinSCP Export": "RandomSeedFile=.*winscp.rnd\n",
        "Ultra VNC": "\[ultravnc\]\npasswd=.+",
    },
    "DirectoryName":{
        "Password": "password",
        "Credential": "credential",
        "Passwort": "passwort",
        "Passwört": "passwört",
    },
    "FileName":{
        "Password": "password",
        "Credential": "credential",
        "Passwort": "passwort",
        "Passwört": "passwört",
        "Chrome Password Export": "chrome[- ]pass(wörter|words)\.csv",
        "Edge Password Export": "microsoft edge[- ](passwords|kennwörter)\.csv",
        "Filezilla Export": "filezilla.{0,20}\.xml",
        "WinSCP Export": "winscp.{0,20}\.ini",
        "etc_passwd": "etc_passwd",
        "etc_shadow": "etc_shadow",
        ".htpasswd": "\.htpasswd",
    }
}

class ConsoleColors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    ORANGE = "\033[93m"
    BLUE = "\033[94m"
    DEFAULT = "\033[0m"

class DetectionType:
    FILENAME = "FileName"
    FILECONTENT = "FileContent"
    DIRECTORY = "DirectoryName"

# https://stackoverflow.com/questions/6893968/how-to-get-the-return-value-from-a-thread-in-python
class ThreadWithReturnValue(Thread):
    def __init__(self, group=None, target=None, name=None, args=(), kwargs={}, Verbose=None):
        Thread.__init__(self, group, target, name, args, kwargs)
        self._return = None
    def run(self):
        if self._target is not None:
            self._return = self._target(*self._args, **self._kwargs)
    def join(self, *args):
        Thread.join(self, *args)
        return self._return

class SearchResult:
    def __init__(self, detectionType, name, context, pattern, patternType):
        self.detectionType = detectionType
        self.name = name
        self.context = context.replace("\n", "")
        self.pattern = pattern
        self.patternType = patternType

    def __getattribute__(self, name):
        return object.__getattribute__(self, name)

def get_dir_files(directory):
    dir_files = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            # check if file is not this script
            own_filename = os.path.basename(__file__)
            if file != own_filename:
                dir_files.append(os.path.join(root, file))
    return dir_files

def get_dirs(directory):
    # get all subdirectories names
    subdirs = [x[0] for x in os.walk(directory)]
    return subdirs

def check_files(files, patterns, threadname, extensionsToIgnore):
    results = []
    totalFileCount = len(files)
    fileCount = 0
    for file in files:
        fileCount += 1

        # print progress every 100 files
        if fileCount % 100 == 0:
            print(f"{ConsoleColors.GREEN}[Thread {threadname}]{ConsoleColors.DEFAULT} {fileCount}/{totalFileCount} files checked ({round(fileCount/totalFileCount*100, 2)} %)" )

        # check file name for patterns and convert to lowercase
        filename = os.path.basename(file).lower()

        # check if file ends with an extension to ignore
        if any(filename.endswith(extension) for extension in extensionsToIgnore): continue

        for pattern in patterns[DetectionType.FILENAME]:
            if re.search(patterns[DetectionType.FILENAME][pattern], filename):
                # create new search result and add it to results
                result = SearchResult(DetectionType.FILENAME, file, "", "", "")
                results.append(result)

        # check file content for patterns
        try :
            for line in open(file, errors='ignore'):
                # iterate over all pattern types
                for pattern_type in patterns:
                    # iterate over all patterns in a pattern type
                    for pattern in patterns[pattern_type]:
                        # exclude directory patterns and file name patterns
                        if pattern_type == DetectionType.DIRECTORY or pattern_type == DetectionType.FILENAME: continue
                        regexResult = re.search(patterns[pattern_type][pattern], line)
                        if not regexResult: continue

                        # get context n characters before and n characters after the match
                        context = ""
                        contextLenght = 20
                        contextBegin = regexResult.start() - contextLenght > 0 and regexResult.start() - contextLenght or 0
                        contextEnd = regexResult.end() + contextLenght < len(line) and regexResult.end() + contextLenght or len(line)
                        context = line[contextBegin:contextEnd]
                        # remove all whitespaces at the beginning
                        context = context.lstrip()

                        # create new search result and add it to results
                        result = SearchResult(DetectionType.FILECONTENT, file, context, pattern, pattern_type)
                        results.append(result)
                        print(f"{ConsoleColors.RED}[Hit]{ConsoleColors.DEFAULT} Found credentials in {file}")
        except:
            print(f"{ConsoleColors.ORANGE}[Warning]{ConsoleColors.DEFAULT} Error while reading file {file}")
            pass
    print(f"Thread {threadname} finished")
    return results

def check_dir(directory, patterns):
    results = []
    # check directory name for patterns
    for pattern in patterns[DetectionType.DIRECTORY]:
        if re.search(pattern, directory):
            # create new search result and add it to results
            result = SearchResult(DetectionType.DIRECTORY, directory, "", "", "")
            results.append(result)
    return results

def extract_list_args(arguments):
    args = []
    for arg in arguments:
        argAppend = ""
        for char in arg:
            argAppend += char
        args.append(argAppend)
    return args

def validate_ignore_extensions(list):
    # if extension does not start with a dot add it
    for i in range(len(list)):
        if not list[i].startswith("."):
            list[i] = "." + list[i]
    return list

def print_results(results):
    print(f"\n{ConsoleColors.GREEN}-{"="*14}[Results]{"="*14}-{ConsoleColors.DEFAULT}\n")
    # get all detection types
    detectionTypes = []
    for result in results:
        if result.detectionType not in detectionTypes:
            detectionTypes.append(result.detectionType)

    # iterate over all detection types
    for detectionType in detectionTypes:
        # get all results for this detection type
        resultsForType = [result for result in results 
            if result.detectionType == detectionType
        ]

        # print results for this detection type
        if detectionType == DetectionType.DIRECTORY:
            print(f"{ConsoleColors.RED}┌───[Directoryname]{ConsoleColors.DEFAULT}")
            for result in resultsForType:
                decoration = result == resultsForType[-1] and "└─" or "├─"
                print(f"{ConsoleColors.RED}{decoration}{ConsoleColors.DEFAULT} {result.name}")
            print("\n")
        elif detectionType == DetectionType.FILENAME:
            print(f"{ConsoleColors.RED}┌───[Filename]{ConsoleColors.DEFAULT}")
            for result in resultsForType:
                decoration = result == resultsForType[-1] and "└─" or "├─"
                print(f"{ConsoleColors.RED}{decoration}{ConsoleColors.DEFAULT} {result.name}")
            print("\n")
        elif detectionType == DetectionType.FILECONTENT:
            print(f"{ConsoleColors.RED}┌───[Filecontent]{ConsoleColors.DEFAULT}")
            print(f"{ConsoleColors.RED}│{ConsoleColors.DEFAULT}")
            for result in resultsForType:
                decorationTop = result == resultsForType[-1] and "└──" or "├──"
                decoration = result == resultsForType[-1] and " " or "│"
                print(f"{ConsoleColors.RED}{decorationTop}───[{result.patternType}]{ConsoleColors.DEFAULT}")
                print(f"{ConsoleColors.RED}{decoration}{ConsoleColors.DEFAULT}      Pattern: {result.pattern}")
                print(f"{ConsoleColors.RED}{decoration}{ConsoleColors.DEFAULT}      File:    {result.name}")
                print(f"{ConsoleColors.RED}{decoration}{ConsoleColors.DEFAULT}      Context: {result.context == '' and 'None' or result.context}")
                print(f"{ConsoleColors.RED}{decoration}{ConsoleColors.DEFAULT}")
    totalResults = len(results)
    print(f"\nTotal results: {totalResults}")

def main():
    output = []

    # parse arguments
    parser = argparse.ArgumentParser(description='Search for passwords and credentials in a directory structure')

    parser.add_argument('-d', '--directory', help='directory to search', required=False, default=os.getcwd())
    parser.add_argument('-t', '--threads', help='number of threads to use', required=False, default=1)
    parser.add_argument('-i', '--ignore', type=list, nargs='*', help='extensions to ignore', required=False, default=[])

    args = parser.parse_args()

    # extract all extensions to ignore
    ignoreExtensions = extract_list_args(args.ignore)

    # add dot to all extensions if not already done
    ignoreExtensions = validate_ignore_extensions(ignoreExtensions)

    # precompile regex pattern for faster search
    compiled_patterns = {}
    for key in patterns:
        compiled_patterns[key] = {}
        for pattern in patterns[key]:
            compiled_patterns[key][pattern] = re.compile(patterns[key][pattern])

    # search subdirectories
    print(f"{ConsoleColors.BLUE}[Info]{ConsoleColors.DEFAULT} Seaching subdirectories...")
    dirs = get_dirs(args.directory)
    print(f"{ConsoleColors.BLUE}[Info]{ConsoleColors.DEFAULT} Found {len(dirs)} subdirectories in directory {args.directory}")

    print(f"{ConsoleColors.BLUE}[Info]{ConsoleColors.DEFAULT} Start scanning directories")
    # check subdirectories
    for dir in dirs:
        res = check_dir(dir, compiled_patterns)
        output.extend(res)

    # get files in directory
    dir_files = get_dir_files(args.directory)
    print(f"{ConsoleColors.BLUE}[Info]{ConsoleColors.DEFAULT} Found {len(dir_files)} files in directory {args.directory}")

    # check files
    countTotal = len(dir_files)
    count = 0

    # distribute files to threads (e. g. 2 threads and 100 files -> 50 files per thread)
    filesPerThread = int(countTotal / int(args.threads))
    files = []
    for i in range(0, int(args.threads)):
        files.append(dir_files[i*filesPerThread:(i+1)*filesPerThread])

    threads = []

    for i in range(0, int(args.threads)):
        t = ThreadWithReturnValue(target=check_files, args=(files[i], compiled_patterns, i + 1, ignoreExtensions,))
        t.daemon = True
        threads.append(t)
        t.start()
        print(f"{ConsoleColors.BLUE}[Info]{ConsoleColors.DEFAULT} Started thread {i + 1}")

    # start threads
    while True:
        time.sleep(1)
        if len(threads) == 0:
            break
        for t in threads:
            if not t.is_alive():
                output.extend(t.join())
                threads.remove(t)

    print("Finished scanning files")

    print_results(output)

if __name__ == '__main__':
    main()