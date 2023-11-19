#pragma once
#define ok(msg, ...) printf("[+] " msg "\n", ##__VA_ARGS__)
#define err(msg, ...) printf("[-] " msg "\n", ##__VA_ARGS__)
#define info(msg, ...) printf("[!] " msg "\n", ##__VA_ARGS__)
#define MAX_SIZE 1024