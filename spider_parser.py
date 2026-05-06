#!/usr/bin/env python3.9


import glob
import json
import os
import re
import shlex
import socket
import sys
import argparse

def main():
    parser = argparse.ArgumentParser(description='')
    parser.add_argument('-d','--dir', type=str, default=os.path.expanduser('~/.nxc/modules/nxc_spider_plus/'), help='Directory of nxc spider_plus output. Default is ~/.nxc/modules/nxc_spider_plus/')
    parser.add_argument('REGEX', type=str)

    parser.add_argument('-m','--mount',default=False, action=argparse.BooleanOptionalAction, help='Display commands necessary to create mount shares')
    parser.add_argument('-u','--username', help='Username for mount')
    parser.add_argument('-p','--password', help='password for mount')
    args = parser.parse_args()

    #list all files in directory
    files = glob.glob(args.dir+'*.json')

    #Compile regex pattern
    regex_pattern = re.compile(args.REGEX)

    for file_path in files:
        file = file_path.split('/')[-1:][0]
        hostname = '.'.join(file.split('.')[:-1])

        with open(file_path) as open_file:
            try:
                a = json.load(open_file)
            except json.decoder.JSONDecodeError:
                pass
            for key in a.keys():
                #If share is IPC$ we can skip it
                if key != 'IPC$':
                    #if share is not IPC$ then iterate through the items in the share.
                    for item in a[key]:
                        if re.search(regex_pattern, item):
                            print(f'{hostname},{key},{item}')
    if args.mount:
        for file_path in files:
            file = file_path.split('/')[-1:][0]         # split file path with name
            hostname = '.'.join(file.split('.')[:-1])   # pull hostname from filename
            try:
                ip = socket.gethostbyname(hostname)
            except socket.gaierror:
                print(f'# DNS lookup failed for {hostname}, skipping', file=sys.stderr)
                continue
            with open(file_path) as open_file:
                try:
                    a = json.load(open_file)
                except json.decoder.JSONDecodeError:
                    pass #in case of a corupt file
                for key in a.keys():
                    if key != 'IPC$':
                        unc = f'//{ip}/{key}'
                        mount_point = f'/mnt/{hostname}/{key}'
                        opts = f'username={args.username},password={args.password}'
                        print(f'mkdir -p {shlex.quote(mount_point)}')
                        print(f'mount -t cifs {shlex.quote(unc)} {shlex.quote(mount_point)} -o {shlex.quote(opts)}')


if __name__ == '__main__':
    main()
