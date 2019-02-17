#!/usr/bin/python3
# -*- coding: utf-8 -*-
from __future__ import division, print_function, unicode_literals
from hashlib import sha1
from os import stat, access, R_OK
from argparse import ArgumentParser
from getpass import getpass
import sys
import signal
import csv

def handler(signum, frame):
    print('\nCtrl-C pressed')
    sys.exit(0)

def binary_search(hex_hash, list_file, file_size):
    def get_full_line(file, pos):
        file.seek(pos)
        while pos > 0 and file.read(1) != "\n":
            pos -= 1
            file.seek(pos)
        return file.readline(), pos

    def search_hash(file, my_hash, start, end):
        if start >= end:
            return 0
        new_pos = start + (end - start) // 2
        candidate_line, pivot = get_full_line(file, new_pos)
        # print("Trying line at pos {:11d}: \"{}\" (pivot position: {})".format(
        #     new_pos, candidate_line.strip(), pivot))
        pwned_hash, count = candidate_line.split(':')
        if pwned_hash == my_hash:
            if args.quiet == False:
                print("Password found at byte {:11d}: \"{}\"".format(pivot, candidate_line.strip()))
            else:
                print("Password found")
            return int(count.strip())
        if my_hash > pwned_hash:
            return search_hash(file, my_hash, file.tell(), end)
        else:
            return search_hash(file, my_hash, start, pivot)

    return search_hash(list_file, hex_hash, 0, file_size)

def check_pass(password, display_pass=True):
    if 'decode' in dir(str):
        password = password.decode('utf-8')
    encodings = ['utf-8', 'latin', 'iso8859-15', 'iso8859-1']
    hashes = []
    for encoding in encodings:
        try:
            hash_candidate = sha1(password.encode(encoding)).hexdigest().upper()
            if hash_candidate not in hashes:
                hashes.append(hash_candidate)
        except UnicodeEncodeError:
            continue
    count = 0
    for h in hashes:
        if  display_pass==True:
            if args.quiet == False:
                print("Searching for hash {} of password \"{}\".".format(h, password))
            count += binary_search(h, pwned_passwords_file, pwned_passwords_file_size)
            if count > 0:
                print("Your password \"{}\" was in {} leaks or hacked databases!".format(password, count) +
                      " Please change it immediately.")
            else:
                print("Your password \"{}\" is not in the dataset. You may relax.".format(password))
        else:
            if args.quiet == False:
                print("Searching for hash {} of password".format(h))
            count += binary_search(h, pwned_passwords_file, pwned_passwords_file_size)
            if count > 0:
                if args.quiet == False:
                    print("Your password was in {} leaks or hacked databases!".format(count) +
                          " Please change it immediately.")
            else:
                print("Your password is not in the dataset. You may relax.")


if __name__ == "__main__":
    parser = ArgumentParser(description='Test passwords locally.' +
                                        ' Each password you pass as an argument will be hashed and this script' +
                                        ' will search for the hash in the list.' +
                                        ' Alternative specify a CSV file.')
    parser.add_argument('passwords', nargs='*')
    parser.add_argument('-f', '--pwned-passwords-ordered-by-hash-filename', dest='password_file', required=False,
                        default="pwned-passwords-sha1-ordered-by-hash-v4.txt", help='use a different password file')
    parser.add_argument('-i', '--interactive', dest='interactive', action='store_true', required=False, help='ask for password(s) interactively.')
    parser.add_argument('-q', '--quiet', dest='quiet', action='store_true', required=False)
    parser.add_argument('-c', '--csv-file', required=False, default="")
    parser.add_argument('--csv-column-user', required=False, default="Username")
    parser.add_argument('--csv-column-group', required=False, default="Group")
    parser.add_argument('--csv-column-title', required=False, default="Title")
    parser.add_argument('--csv-column-password', required=False, default="Password")
    args = parser.parse_args()
    if not access(args.password_file, R_OK):
        raise SystemExit("***E*** Password hash file '%s' does not exist or is not readable!" % args.password_file)
    with open(args.password_file, 'r') as pwned_passwords_file:
        pwned_passwords_file_size = stat(args.password_file).st_size
        #print("File size: {} Bytes".format(pwned_passwords_file_size))
        if args.csv_file != "":
            print("Read passwords from CSV file: " + args.csv_file)
            if not access(args.csv_file, R_OK):
                raise SystemExit("***E*** Password hash file '%s' does not exist or is not readable!" % args.csv_file)
            with open(args.csv_file, 'rt') as csvfile:
                delimiter=','
                quotechar='"'
                if 'decode' in dir(str):
                    # workaround for python 2.x
                    delimiter= delimiter.encode('ascii')
                    quotechar= quotechar.encode('ascii')
                csvreader = csv.DictReader(csvfile, delimiter=delimiter, quotechar=quotechar)
                csvdata = [r for r in csvreader]
                print("Entries found in CSV file: " + str(len(csvdata)))
                for i in range(0, len(csvdata)):
                    csvdata_user = csvdata[i][args.csv_column_user]  if (args.csv_column_user  in  csvdata[i].keys()) else "(no_user)"
                    csvdata_group= csvdata[i][args.csv_column_group] if (args.csv_column_group in csvdata[i].keys()) else "(no_group)"
                    csvdata_title= csvdata[i][args.csv_column_title] if (args.csv_column_title in csvdata[i].keys()) else "(no_title)"
                    if not (args.csv_column_password in csvdata[i].keys()):
                        print("***W*** Entry for user %s does not contain password column '%s'!" % (csvdata_user, args.csv_column_password))
                    else:
                        print("Entry #" + str(i) + ": " + csvdata_group + " : " + csvdata_title + " : " + csvdata_user + " : ", end='')
                        if csvdata[i][args.csv_column_password].isdigit():
                            print("(only " + str(len(csvdata[i][args.csv_column_password])) + " digits, potentially a PIN)")
                        elif len(csvdata[i][args.csv_column_password]) > 0:
                            check_pass(csvdata[i][args.csv_column_password], False)
                        else:
                            print("(empty)")
            sys.exit(0)
        if (args.interactive==False) and (len(args.passwords) == 0):
            print ("No passwords given as argument.\n")
        for password in args.passwords:
            print("")
            check_pass(password)
        if args.interactive==True:
            print("\nNow running in interactive mode; passwords are not displayed\nEnter empty password or press Ctrl-C to exit.")
            signal.signal(signal.SIGINT, handler)
            while True:
                password=getpass('\nPassword: ')
                if(password==''):
                    sys.exit(0)
                check_pass(password, False)
