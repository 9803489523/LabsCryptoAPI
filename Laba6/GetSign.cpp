#define _CRT_SECURE_NO_WARNINGS 1

#include <iostream>
#include <fstream>
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <wincrypt.h>

//filepath C:\C++\test.txt

//#define DEBUG
#define DEFAULT_CONTAINER  "0"

void hashing(HCRYPTHASH* hash, byte* data, HCRYPTPROV prov, DWORD dataLen);

void keyExtraction(HCRYPTKEY* key, HCRYPTPROV prov);

void inputUserData(char* str);

void printBytes(byte* arr, int len, const char* mode);

void release(HCRYPTPROV prov, HCRYPTKEY key, HCRYPTHASH hash);

void getLastError(DWORD error);

byte* getDataFromFile(DWORD* len);

void writeToFileSign(byte* sign, DWORD signLen);

int main()
{
    setlocale(LC_ALL, "rus");
    HCRYPTPROV prov;
    HCRYPTHASH hash;
    HCRYPTKEY key;
    byte* data;
    BYTE* sign;
    DWORD dataLen;
    DWORD signLen;
    bool res;
    int err;

    data = getDataFromFile(&dataLen);



    res = CryptAcquireContext(&prov, TEXT(DEFAULT_CONTAINER), MS_DEF_PROV, PROV_RSA_FULL, CRYPT_SILENT);
    if (!res)
        printf("Error in CryptAcquireContext: %X\n", GetLastError());

    printf("--------Вычисление цифровой подписи---------\n\n");

    hashing(&hash, data, prov, dataLen);
    keyExtraction(&key, prov);

#ifdef DEBUG
    printf("Данные из файла: \n");
    printBytes(data, dataLen, "%c");
    printf("datalen: %d", dataLen);
    printf("Hash value: %X\n", hash);
    printf("Key value: %X\n", key);
#endif

    res = CryptSignHash(hash, AT_SIGNATURE, TEXT("text"), NULL, NULL, &signLen);
    if (!res) {
        err = GetLastError();
        printf("Error in CryptSignHash: %X\n", err);
        getLastError(err);
    }

    sign = (byte*)malloc(signLen);

    res = CryptSignHash(hash, AT_SIGNATURE, TEXT("text"), NULL, sign, &signLen);
    if (!res) {
        err = GetLastError();
        printf("Error in CryptSignHash: %X\n", err);
        getLastError(err);
    }
    printf("Значение цифровой подписи: ");
    printBytes(sign, signLen, "%X");

#ifdef DEBUG
    printf("strlen(CP) = %d, strlen(data) = %d\ndataLen = %d, signLen = %d\n", strlen((char*)sign), strlen((char*)data), dataLen, signLen);
#endif

    writeToFileSign(sign, signLen);
    release(prov, key, hash);

    NTE_BAD_KEY;
}

void hashing(HCRYPTHASH* hash, byte* data, HCRYPTPROV prov, DWORD dataLen) {
    bool res;

    res = CryptCreateHash(prov, CALG_MD5, 0, 0, hash);
    if (!res)
        printf("Error in CryptCreateHash: %X\n", GetLastError());

    res = CryptHashData(*hash, data, dataLen, 0);
    if (!res)
        printf("Error in CryptCreateHash: %X\n", GetLastError());
}


void keyExtraction(HCRYPTKEY* key, HCRYPTPROV prov) {
    bool res;
    /*
    res = CryptGenKey(prov, AT_SIGNATURE, CRYPT_EXPORTABLE, key);
    if (!res) {
        printf("Error in CryptGenKey: %X\n", GetLastError());
    }
    */
    res = CryptGetUserKey(prov, AT_SIGNATURE, key);
    if (!res) {
        printf("Error in CryptGetUserKey: %X\n", GetLastError());
    }
}

void inputUserData(char* str) {
    printf("Введите данные: ");
    scanf("%s", str);
    printf("\n");
}


void printBytes(byte* arr, int len, const char* mode) {
    for (int i = 0; i < len; i++) {
        printf(mode, arr[i]);
    }
    printf("\n");
}

void release(HCRYPTPROV prov, HCRYPTKEY key, HCRYPTHASH hash) {
    bool res;

    res = CryptDestroyHash(hash);
    if (!res)
        printf("Error in CryptDestroyHash: %X\n", GetLastError());

    res = CryptDestroyKey(key);
    if (!res)
        printf("Error in CryptDestroyKey: %X\n", GetLastError());

    res = CryptReleaseContext(prov, 0);
    if (!res)
        printf("Error in CryptReleaseContext: %X\n", GetLastError());
}

void getLastError(DWORD error) {
    switch (error) {
    case ERROR_INVALID_HANDLE:
        printf("Один из параметров указывает на недопустимый дескриптор\n");
        break;
    case ERROR_INVALID_PARAMETER:
        printf("Один из параметров содержит недопустимое значение. Чаще всего это указатель\n");
        break;
    case ERROR_MORE_DATA:
        printf("Буфер, указанный в pbSignature недостаточно велик для хранения возвращаемых данных\n");
        break;
    case NTE_BAD_ALGID:
        printf("Дескриптор, hhash указывает алгоритм, который не поддерживается этим поставщиком служб конфигурации или параметр dwKeySpec имеет неправильное значение\n");
        break;
    case NTE_BAD_FLAGS:
        printf("Параметр dwFlags не является нулевым\n");
        break;
    case NTE_BAD_HASH:
        printf("Недопустимый хэш-объект, заданный параметром hHash\n");
        break;
    case NTE_BAD_UID:
        printf("Контекст CSP, заданный при создании хэш-объекта не найден\n");
        break;
    case NTE_NO_KEY:
        printf("Закрытый ключ, указанный dwKeyspec, не существует\n");
        break;
    case NTE_NO_MEMORY:
        printf("Поставщику служб конфигурации не хватает памяти во время операции\n");
        break;
    }
}

byte* getDataFromFile(DWORD* len) {
    char* filepath = (char*)malloc(100);
    byte* data = (byte*)malloc(10000);
    byte* dataRet;
    int index = 0;
    char symbol;

    printf("Введите путь до файла: ");
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

void writeToFileSign(byte* sign, DWORD signLen) {
    char* filepath = (char*)malloc(100);
    FILE* write;

    printf("Введите путь к файлу для записи цифровой подписи: ");
    scanf("%s", filepath);

    write = fopen(filepath, "wb");
    fprintf(write, (char*)sign);

    free(filepath);
    fclose(write);
}
