#include <stdio.h>
#include <iostream>
#include <fstream>
#include <string>
#include <Windows.h>
#include <Wincrypt.h>
#include <stdlib.h>

void writeHashToFile(HCRYPTPROV prov,
    HCRYPTHASH* hash);

void readHashFromFile(byte* arr);

void bruteForce(byte* hash, DWORD hashLength);

void releaseContext(HCRYPTPROV prov,
    HCRYPTHASH hash);

int symbolTransform(char symbol);

void getHashValue(byte* data,
    DWORD* dataLen,
    byte* hash);

bool hashEquals(byte* hash1,
    byte* hash2,
    int len);

void printBytes(byte* arr,
    int len,
    int minus);
