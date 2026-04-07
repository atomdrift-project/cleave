#!/usr/bin/env python3
import os
import sys

def main():
    for path in sys.argv[1:]:
        if os.path.exists(path):
            print(f"Found: {path}")
        else:
            print(f"Missing: {path}")

if __name__ == "__main__":
    main()
