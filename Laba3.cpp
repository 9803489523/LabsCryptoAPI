#define _CRT_SECURE_NO_WARNINGS 1
#include <stdio.h>
#include <iostream>
#include <fstream>
#include <string>
#include <Windows.h>
#include <Wincrypt.h>
#include <stdlib.h>

//#define DEBUG

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
    int err = GetLastError();

#ifdef DEBUG
    printf("res = %d, error: %X\n", res, err);
#endif // DEBUG

    if (err == 259) {
        printf("Список криптоконтейнеров пуст\n");
        goto exit;
    }

    while (CryptGetProvParam(prov, PP_ENUMCONTAINERS, containerName, &containerNameLength, CRYPT_NEXT)) {
        printf("\t%d). %s\n", cnt + 1, (wchar_t*)containerName);
        cnt++;
    }NTE_BAD_DATA;
exit:
    system("pause");

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