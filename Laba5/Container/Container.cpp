#define GEN_KEY

#ifndef GEN_KEY
#include <stdio.h>
#include <iostream>
#include <fstream>
#include <string>
#include <Windows.h>
#include <Wincrypt.h>
#include <stdlib.h>

typedef struct {
    char* provFullName;
    wchar_t* provPsevdonim;
    int provType;
} Provider;

void getProviders(Provider* providers, int* len);

void printProvider(Provider provider);

void menuCryptoProviders(Provider* providers, Provider* provider, int len);

int main()
{
    setlocale(LC_ALL, "rus");

    HCRYPTPROV prov;
    Provider provGet;
    Provider* providers;
    int lenProviders;
    byte* containerName = (byte*)malloc(1000);
    DWORD containerNameLength;

    providers = (Provider*)malloc(1000);

    getProviders(providers, &lenProviders);

    menuCryptoProviders(providers, &provGet, lenProviders);

    CryptAcquireContext(&prov, NULL, provGet.provPsevdonim, provGet.provType, CRYPT_VERIFYCONTEXT);

    int cnt = 0;
    bool res = CryptGetProvParam(prov, PP_ENUMCONTAINERS, containerName, &containerNameLength, CRYPT_FIRST);
    printf("res = %d, error: %X\n", res, GetLastError());
    while (CryptGetProvParam(prov, PP_ENUMCONTAINERS, containerName, &containerNameLength, CRYPT_NEXT)) {
        printf("\t%d). %s\n", cnt + 1, (wchar_t*)containerName);
        cnt++;
    }NTE_BAD_DATA;

}

void getProviders(Provider* providers, int* len) {
    DWORD index = 0;
    DWORD type;
    LPSTR fullName;
    LPWSTR psevdonim;
    DWORD fullNameLength;
    DWORD psevdonimLength;
    while (CryptEnumProvidersA(index, NULL, 0, &type, NULL, &fullNameLength) &&
        CryptEnumProvidersW(index, NULL, 0, &type, NULL, &psevdonimLength)) {

        fullName = (LPSTR)malloc(fullNameLength);
        psevdonim = (LPWSTR)malloc(psevdonimLength);

        CryptEnumProvidersA(index, NULL, 0, &type, fullName, &fullNameLength);
        CryptEnumProvidersW(index, NULL, 0, &type, psevdonim, &psevdonimLength);

        if (len != 0) {
            providers[index].provFullName = fullName;
            providers[index].provPsevdonim = psevdonim;
            providers[index].provType = type;
        }

        index++;
    }

    *len = index;
}

void printProvider(Provider provider) {
    printf("%s, %X, %d\n", provider.provFullName, provider.provPsevdonim, provider.provType);
}

void menuCryptoProviders(Provider* providers, Provider* provider, int len) {
    int choose;
    printf("Длина списка: %d\n", len);
    printf("Выберите криптопровайдера из списка: \n");
    for (int i = 0; i < len; i++) {
        printf("\t%d). %s\n", i + 1, providers[i].provFullName);
    }
    scanf("%d", &choose);
    if (choose < 0 || choose > len) {
        printf("Некорректный ввод, сделайте выбор заново!");
        menuCryptoProviders(providers, provider, len);
    }
    else {
        *provider = providers[choose - 1];
    }
}
#endif


#ifdef GEN_KEY
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
    LPCWSTR container = TEXT("laba5");
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
    res = CryptGenKey(prov, AT_KEYEXCHANGE, CRYPT_EXPORTABLE, &key);
    if (!res) {
        err = GetLastError();
        printf("CryptGenKey: %X\n", err);
    }
    */
    res = CryptGetUserKey(prov, AT_KEYEXCHANGE, &key);
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
#endif