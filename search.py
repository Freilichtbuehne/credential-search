import os
import argparse
import re
import threading

class consoleColors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    ORANGE = "\033[93m"
    DEFAULT = "\033[0m"

# api and token patterns are inspired by https://github.com/trufflesecurity/truffleHog

patterns = {
    "Keys" : {
        "RSA private key": "-----BEGIN RSA PRIVATE KEY-----",
        "SSH (OPENSSH) private key": "-----BEGIN OPENSSH PRIVATE KEY-----",
        "SSH (DSA) private key": "-----BEGIN DSA PRIVATE KEY-----",
        "SSH (EC) private key": "-----BEGIN EC PRIVATE KEY-----",
        "PGP private key block": "-----BEGIN PGP PRIVATE KEY BLOCK-----",
        "Generic private key": "-{5}BEGIN.*PRIVATE KEY.*-{5}",
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
    "ApplicationSpecific":{
        "FileZilla Export": '<Pass encoding="base64">',
        "Putty Keyfile": "^PuTTY-User-Key-File-\\d:",
        "Chrome Password Export": "^name,url,username,password\n",
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
        "Chrome Password Export": "Chrome-Passwörter.csv|Chrome-Passwords.csv",
        "Filezilla Export": "Filezilla.xml",
        "etc_passwd": "etc_passwd",
        "etc_shadow": "etc_shadow",
        ".htpasswd": ".htpasswd",
    }
}

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

def check_files(files, patterns, threadname):
    totalFileCount = len(files)
    fileCount = 0
    for file in files:
        fileCount += 1

        # print progress every 100 files
        if fileCount % 100 == 0:
            print(f"{consoleColors.GREEN}[Thread {threadname}]{consoleColors.DEFAULT} {fileCount}/{totalFileCount} files checked ({round(fileCount/totalFileCount*100, 2)} %)" )

        # check file name for patterns
        for pattern in patterns["FileName"]:
            filename = os.path.basename(file)
            if re.search(pattern, filename):
                print("{}[Filename]{} detected {}".format(consoleColors.RED, consoleColors.DEFAULT, file))

        # check file content for patterns
        # avoid errors with encoding
        for line in open(file, errors='ignore'):
            # iterate over all pattern types
            for pattern_type in patterns:
                # iterate over all patterns in a pattern type
                for pattern in patterns[pattern_type]:
                    # exclude directory patterns and file name patterns
                    if pattern_type != "DirectoryName" and pattern_type != "FileName":
                        regexResult = re.search(patterns[pattern_type][pattern], line)
                        if regexResult:
                            # get context n characters before and n characters after the match
                            context = ""
                            contextLenght = 20
                            contextBegin = regexResult.start() - contextLenght > 0 and regexResult.start() - contextLenght or 0
                            contextEnd = regexResult.end() + contextLenght < len(line) and regexResult.end() + contextLenght or len(line)
                            context = line[contextBegin:contextEnd]
                            # remove all whitespaces at the beginning
                            context = context.lstrip()

                            print(f"{consoleColors.RED}[Filecontent]{consoleColors.ORANGE} <{pattern_type}>{consoleColors.DEFAULT} detected {pattern} in {file}")
                            print("Context: {}".format(context == "" and "None" or context))
    print(f"Thread {threadname} finished")
    
def check_dir(directory, patterns):
    # check directory name for patterns
    for pattern in patterns["DirectoryName"]:
        if re.search(pattern, directory):
            print(f"{consoleColors.RED}[Directoryname]{consoleColors.DEFAULT} detected {directory}")

def main():
    # parse arguments
    parser = argparse.ArgumentParser(description='Search for passwords and credentials in a directory structure')

    parser.add_argument('-d', '--directory', help='directory to search', required=False, default=os.getcwd())

    # add number of threads
    parser.add_argument('-t', '--threads', help='number of threads to use', required=False, default=1)

    args = parser.parse_args()

    # compile patterns
    compiled_patterns = {}
    for key in patterns:
        compiled_patterns[key] = {}
        for pattern in patterns[key]:
            # precompile pattern for faster search
            compiled_patterns[key][pattern] = re.compile(patterns[key][pattern])

        # get subdirectories
    dirs = get_dirs(args.directory)
    print("Found {} subdirectories in directory {}".format(len(dirs), args.directory))

    # check subdirectories
    for dir in dirs:
        check_dir(dir, compiled_patterns)

    # get files in directory
    dir_files = get_dir_files(args.directory)
    print("Found {} files in directory {}".format(len(dir_files), args.directory))

    # check files
    countTotal = len(dir_files)
    count = 0

    # distribute files to threads (e. g. 2 threads and 100 files -> 50 files per thread)
    filesPerThread = int(countTotal / int(args.threads))
    files = []
    for i in range(0, int(args.threads)):
        files.append(dir_files[i*filesPerThread:(i+1)*filesPerThread])

    # create threads
    threads = []
    for i in range(0, int(args.threads)):
        t = threading.Thread(target=check_files, args=(files[i], compiled_patterns, i + 1))
        threads.append(t)

    # start threads
    threadCount = 0
    for thread in threads:
        threadCount += 1
        thread.start()
        print("Started thread {}".format(threadCount))

if __name__ == '__main__':
    main()