#!/usr/bin/python3

import sys
import os
import csv
import hashlib
import subprocess
import random

CHECKER_CONFIG='default.cfg'
CHECKER_TESTS='tests.csv'
CHECKER_COMMAND='./ursulalogchecktester'
CHECKER_RESULT='Result code:'
CHECKER_RESULT_CODE='Code string:'

CHECKER_SECRET_STRING='secret'
DELIMITER=':'

def run_checker(task, salt, logfile):
    result = None
    code = None
    with subprocess.Popen([CHECKER_COMMAND, CHECKER_CONFIG, task, str(salt), logfile],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE) as proc:
        outstr = ''
        for line in proc.stdout.readlines():
            line = str(line, 'utf-8').strip()
            outstr += line + '\n'
            if line.find(CHECKER_RESULT) == 0:
                result = int(line[len(CHECKER_RESULT):].strip())
            elif line.find(CHECKER_RESULT_CODE) == 0:
                code = line[len(CHECKER_RESULT_CODE):].strip()
        errstr = str(proc.stderr.read(), 'utf-8')
    return (result, code, outstr, errstr)

def generate_sha256(secret, task, salt, result):
    h = hashlib.new('sha256')
    h.update('{}:{}:{}:{}'.format(secret, task, salt, result).encode('utf-8'))
    return h.hexdigest()

def test_log(secret, task, result, logfile):
    salt = random.randint(1, 2147483647)

    print('Runnig checker {} {} with salt {}... '.format(task, logfile, salt), end='')
    res, code, outstr, errstr = run_checker(task, salt, logfile)
    if res != result:
        print("Wrong result {} (expected {}) while testing log {}".format(res, result, logfile))
        print("Errors:\n{}\n".format(errstr))
        print("Output:\n{}\n".format(outstr))
        sys.exit(1)
    if res != 0:
        sha = generate_sha256(secret, task, salt, result)
        if code != sha:
            print("Wrong result code '{}' (expected '{}') while testing log {}".format(code, sha, logfile))
            print("Errors:\n{}\n".format(errstr))
            print("Output:\n{}\n".format(outstr))
            sys.exit(1)   
    print('OK')
    
if __name__ == '__main__':

    # tasks to test - (task_uuid, result, path)
    Tasks = []
    Secret = None
    
    print('Current dir:', os.getcwd())

    reader = csv.reader(open(CHECKER_CONFIG), delimiter=DELIMITER)
    for row in reader:
        if len(row) != 2: continue
        if row[0] == CHECKER_SECRET_STRING:
            Secret = row[1].strip()

    if Secret is None:
        print('Bad config, cannot find the secret string')
        sys.exit(1)

    reader = csv.reader(open(CHECKER_TESTS), delimiter=DELIMITER)
    for row in reader:
        if len(row) != 3: continue
        Tasks.append((row[0], int(row[1]), row[2].strip())) # add the tests

    print('Testing (total {}):'.format(len(Tasks)))
    for t in Tasks:
        test_log(Secret, t[0], t[1], t[2])
    print('Done!')

    sys.exit(0)
