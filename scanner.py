import os
import hashlib
import argparse



# Grab command line arguments for directory and signature file
parser = argparse.ArgumentParser()
parser.add_argument('--directory', '-d', help="The directory to scan for viruses in", required=True)
parser.add_argument('--signatures', '-s', help="The signature file", required=True)
args = parser.parse_args()

print("[*] Scanning directory: %s"%args.directory)
print("[*] Using signature file: %s"%args.signatures)


blocksize=65536

for root, subFolders, files in os.walk(args.directory):
    # Take MD5 Of the file
    
    for fi in files:
        with open(os.path.join(root, fi), 'rb') as fin:
            hash_md5 = hashlib.md5()
            for block in iter(lambda: fin.read(blocksize), b""):
                hash_md5.update(block)
            digest = hash_md5.hexdigest()
            with open(args.signatures) as signatures_file:
                for sig in signatures_file:
                    if sig.strip() == str(digest):
                        print("[!] File %s is a virus"%(os.path.join(root, fi)))
