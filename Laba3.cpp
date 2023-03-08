#define _CRT_SECURE_NO_WARNINGS 1

#include <iostream>
#include <fstream>
#include <string>
#include <Windows.h>
#include <Wincrypt.h>
#include <stdlib.h> 

#define DEBUG

void funcDebug(bool func);

void containerFillIn(LPCWSTR* container);

int main()
{
    setlocale(LC_ALL, "rus");

    HCRYPTPROV prov;
    HCRYPTKEY key;
    LPCWSTR keyContainer;
    char* str;
    bool res;

    containerFillIn(&keyContainer);

    res = CryptAcquireContext(&prov, keyContainer, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET);

#ifdef DEBUG
    funcDebug(res);
#endif

    if (res) {
#ifdef DEBUG
        funcDebug(
#endif
            CryptGenKey(prov, AT_SIGNATURE, CRYPT_EXPORTABLE, &key)
#ifdef DEBUG
        )
#endif
            ;
        printf("Сгенерирован новый контейнер '%s' с ключом: %X\n", keyContainer, key);
    }
    else {
        if (GetLastError() == NTE_EXISTS) {
            CryptAcquireContext(&prov, keyContainer, NULL, PROV_RSA_FULL, CRYPT_SILENT);
#ifdef DEBUG
            funcDebug(
#endif
                CryptGetUserKey(prov, AT_SIGNATURE, &key)
#ifdef DEBUG
            )
#endif
                ;
            printf("Контейнер '%s' существует, извлечение ключа: %X\n", keyContainer, key);
        }
    }

    CryptDestroyKey(key);
    CryptReleaseContext(prov, 0);
    system("pause");
}

void funcDebug(bool func) {
    if (func) {
        printf("Success\n");
    }
    else {
        printf("Failed with error: %X\n", GetLastError());
    }
}

void containerFillIn(LPCWSTR* container) {
    const char* str = (char*)malloc(100);
    printf("Введите название контейнера: ");
    scanf("%s", str);
    *container = (LPCWSTR)str;
}