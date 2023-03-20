#include <iostream>
#include <fstream>
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <wincrypt.h>

//#define DEBUG
#define DEFAULT_CONTAINER  "laba5"


void printBytes(byte* arr, int len);

byte* getDataFromFile(DWORD* len, const char* str);

int main()
{
    setlocale(LC_ALL, "rus");

    HCRYPTKEY session;
    HCRYPTKEY publickey;
    HCRYPTPROV provider;
    DWORD decryptLen;
    byte* userData;
    byte* keyData;
    DWORD keyLen;
    bool res;

    userData = getDataFromFile(&decryptLen, "с зашифрованными данными");
    keyData = getDataFromFile(&keyLen, "с зашифрованным ключом");
#ifdef DEBUG
    printf("Зашифрованное сообщение: \n%s\n", userData);
    printf("Зашифрованный ключ: \n");
    printBytes(keyData, keyLen);
#endif
    res = CryptAcquireContext(&provider, TEXT(DEFAULT_CONTAINER), NULL, PROV_RSA_FULL, CRYPT_SILENT);
    if (!res)
        printf("CryptAcquireContext(): %X\n", GetLastError());
    res = CryptGetUserKey(provider, AT_KEYEXCHANGE, &publickey);
    if (!res)
        printf("CryptGetUserKey(): %X\n", GetLastError());
    res = CryptImportKey(provider, keyData, keyLen, publickey, NULL, &session);
    if (!res)
        printf("CryptImportKey(): %X\n", GetLastError());

#ifdef DEBUG
    printf("session: %X\n", session);
#endif
    res = CryptDecrypt(session, NULL, 1, NULL, userData, &decryptLen);
    if (!res)
        printf("CryptDecrypt(): %X\n", GetLastError());

    printf("Расшифрованное сообщение: \n");
    printBytes(userData, decryptLen);
    printf("\n");
    system("pause");
    NTE_BAD_KEY; ERROR_MORE_DATA;

    CryptReleaseContext(provider, 0);
    CryptDestroyKey(session);
    CryptDestroyKey(publickey);

    system("pause");
}

void printBytes(byte* arr, int len) {
    for (int i = 0; i < len; i++) {
        printf("%c", arr[i]);
    }
    printf("\n");
}

byte* getDataFromFile(DWORD* len, const char* str) {
    char* filepath = (char*)malloc(100);
    byte* data = (byte*)malloc(10000);
    byte* dataRet;
    int index = 0;
    char symbol;

    printf("Введите путь до файла %s: ", str);
    scanf("%s", filepath);

    FILE* read;
    read = fopen(filepath, "rb");

    while (fscanf(read, "%c", &symbol) != EOF) {
        data[index++] = symbol;
    }
    dataRet = (byte*)malloc(index + 1);

    for (int i = 0; i < index; i++) {
        dataRet[i] = data[i];
    }
    dataRet[index] = '\0';
    free(data);
    *len = index;
    return dataRet;
}