#include <iostream>
#include "BruteForce.h"

//filepath E:\C\c++\vs2019\CryptoAPI\1.txt

#define MODE_BRUTEFORCE
//#define MODE_HASHWRITE
#define MD5_LEN 16

int main()
{
    setlocale(LC_ALL, "rus");

    HCRYPTPROV prov;
    HCRYPTHASH hash;


    CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);

#ifdef MODE_HASHWRITE

    writeHashToFile(prov, &hash);

#endif

#ifdef MODE_BRUTEFORCE

    DWORD hashLength = MD5_LEN;
    byte* hashData = (byte*)malloc(MD5_LEN);
    readHashFromFile(hashData);
    bruteForce(hashData, hashLength);

#endif

    CryptReleaseContext(prov, 0);
}