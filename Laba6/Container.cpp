#include <iostream>
#include <fstream>
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <wincrypt.h>
 
int main()
{
    HCRYPTPROV prov;
    HCRYPTKEY key;
    LPCWSTR container = TEXT("0");
    bool res;
    DWORD err;
 
    res = CryptAcquireContext(&prov, container, MS_DEF_PROV, PROV_RSA_FULL, CRYPT_NEWKEYSET);
    if (!res) {
        err = GetLastError();
        printf("CryptAcquireContext: %X\n", err);
        if (err == NTE_EXISTS) {
            res = CryptAcquireContext(&prov, container, MS_DEF_PROV, PROV_RSA_FULL, CRYPT_SILENT);
            if (!res) {
                err = GetLastError();
                printf("CryptAcquireContext: %X\n", err);
            }
        }
    }
    /*
    res = CryptGenKey(prov, AT_SIGNATURE, CRYPT_EXPORTABLE, &key);
    if (!res) {
        err = GetLastError();
        printf("CryptGenKey: %X\n", err);
    }*/
    
    res = CryptGetUserKey(prov, AT_SIGNATURE, &key);
    if (!res) {
        err = GetLastError();
        printf("CryptGetUserKey: %X\n", err);
    }
    else {
        printf("success");
    }
 
    CryptDestroyKey(key);
    CryptReleaseContext(prov, 0);
 
    NTE_BAD_KEY;
}