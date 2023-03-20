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

byte* getDataFromFile(DWORD* len, const char* str);

void writeToFileSign(byte* sign, DWORD signLen);

byte* getSignFile(DWORD* len, const char* str);

int main()
{
    setlocale(LC_ALL, "rus");

    printf("\n\n--------Проверка цифровой подписи---------\n\n");
    HCRYPTPROV provCheck;
    HCRYPTKEY keyCheck;
    HCRYPTHASH hashCheck;
    byte* sign;
    byte* data;
    DWORD signLen;
    DWORD dataLen;
    bool res;
    LPCSTR text = "data";

    data = getDataFromFile(&dataLen, "с данными");
    sign = getDataFromFile(&signLen, "с цифровой подписью");
#ifdef DEBUG
    printf("Данные из файла: \n");
    printBytes(data, dataLen, "%c");
#ifdef DEBUG
    printf("strlen(CP) = %d, strlen(data) = %d\ndataLen = %d, signLen = %d\n", strlen((char*)sign), strlen((char*)data), dataLen, signLen);
#endif
#endif

    res = CryptAcquireContext(&provCheck, TEXT(DEFAULT_CONTAINER), MS_DEF_PROV, PROV_RSA_FULL, CRYPT_SILENT);
    if (!res)
        printf("Error in CryptAcquireContext: %X\n", GetLastError());

    hashing(&hashCheck, data, provCheck, dataLen);
    keyExtraction(&keyCheck, provCheck);

#ifdef DEBUG
    printf("\nKey value: %X\n", keyCheck);
    printf("Hash value: %X\n", hashCheck);
#endif

    printf("Цифровая подпись: \n");
    printBytes(sign, signLen, "%X");

    res = CryptVerifySignature(hashCheck, sign, 64, keyCheck, TEXT("text"), NULL);
#ifdef DEBUG
    printf("strlen(CP) = %d, strlen(data) = %d\ndataLen = %d, signLen = %d\n", strlen((char*)sign), strlen((char*)data), dataLen, signLen);
#endif
    if (!res) {
        int err = GetLastError();
        printf("Error in CryptVerifySignature: %X\n", err);
        getLastError(err);
    }
    else {
        printf("Проверка цифровой подписи прошла успешно\n");
    }

    release(provCheck, keyCheck, hashCheck);
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
    case NTE_BAD_SIGNATURE:
        printf("Подпись недопустима. Данные изменились, строка описания не совпадала или был указан неправильный открытый ключ\n");
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

void writeToFileSign(byte* sign, DWORD signLen) {
    char* filepath = (char*)malloc(100);
    FILE* write;

    printf("Введите путь к файлу для записи цифровой подписи: ");
    scanf("%s", filepath);

    write = fopen(filepath, "wb");
    fwrite(sign, sizeof(byte), signLen, write);

    free(filepath);
    fclose(write);
}

byte* getSignFile(DWORD* len, const char* str) {
    using namespace std;
    char* filepath = (char*)malloc(100);
    printf("Введите путь до файла %s: ", str);
    scanf("%s", filepath);
    byte* ret;

    ifstream read(filepath);
    string readSign;
    getline(read, readSign);

    *len = readSign.length();
    ret = (byte*)malloc(*len + 1);
    for (int i = 0; i < *len; i++) {
        ret[i] = readSign[i];
    }

    ret[*len] = '\0';
    return ret;
}
