#include "BruteForce.h"

void writeHashToFile(HCRYPTPROV prov,
    HCRYPTHASH* hash)
{
    char* filepath = (char*)malloc(100);
    byte* pass = (byte*)malloc(4);
    byte* hashData;
    DWORD hashDataLen;

    printf("Введите значение пароля: ");
    scanf("%s", pass);
    printf("Введите путь к файлу: ");
    scanf("%s", filepath);

    CryptCreateHash(prov, CALG_MD5, 0, 0, hash);
    CryptHashData(*hash, pass, strlen((char*)pass), 0);


    CryptGetHashParam(*hash, HP_HASHVAL, NULL, &hashDataLen, 0);
    hashData = (byte*)malloc(hashDataLen);
    CryptGetHashParam(*hash, HP_HASHVAL, hashData, &hashDataLen, 0);

    FILE* pf;
    if (!(pf = fopen(filepath, "w"))) {
        std::cout << "Error\n";
    }
    for (int i = 0; i < hashDataLen; i++) {
        fprintf(pf, "%.2X", hashData[i]);
    }

    fclose(pf);
    CryptDestroyHash(*hash);
}

void readHashFromFile(byte* arr)
{
    char* filepath = (char*)malloc(100);
    printf("Введите путь к файлу, из которого нужно считать хэш: ");
    scanf("%s", filepath);
    std::ifstream read(filepath);
    int counter = 0;
    char symbol;
    char buff[2];

    while (!read.eof()) {
        read >> symbol;
        buff[0] = symbol;
        if (!read)
            break;
        read >> symbol;
        buff[1] = symbol;
        arr[counter++] = symbolTransform(buff[0]) * 16 + symbolTransform(buff[1]);
    }
    for (int i = 0; i < counter; i++) {
        printf("%X", arr[i]);
    }
    printf("\n");
    free(filepath);
    read.close();
}

void bruteForce(byte* hash, DWORD hashLength) {

    byte* check1 = (byte*)malloc(1);
    byte* check2 = (byte*)malloc(2);
    byte* check3 = (byte*)malloc(3);
    byte* check4 = (byte*)malloc(4);
    DWORD dwlen1 = 1;
    DWORD dwlen2 = 2;
    DWORD dwlen3 = 3;
    DWORD dwlen4 = 4;
    byte* hashGet = (byte*)malloc(16);

    for (int it1 = 0; it1 < 10; it1++) {
        check1[0] = it1 + 48;
        check2[0] = it1 + 48;
        check3[0] = it1 + 48;
        check4[0] = it1 + 48;
        for (int it2 = 0; it2 < 10; it2++) {
            check2[1] = it2 + 48;
            check3[1] = it2 + 48;
            check4[1] = it2 + 48;
            for (int it3 = 0; it3 < 10; it3++) {
                check3[2] = it3 + 48;
                check4[2] = it3 + 48;
                for (int it4 = 0; it4 < 10; it4++) {
                    check4[3] = it4 + 48;

                    getHashValue(check1, &dwlen1, hashGet);
                    dwlen1 = 1;
                    if (hashEquals(hash, hashGet, hashLength)) {
                        printf("Взлом пароля: ");
                        printBytes(check1, dwlen1, 48);
                        goto stop;
                    }

                    getHashValue(check2, &dwlen2, hashGet);
                    dwlen2 = 2;
                    if (hashEquals(hash, hashGet, hashLength)) {
                        printf("Взлом пароля: ");
                        printBytes(check2, dwlen2, 48);
                        goto stop;
                    }

                    getHashValue(check3, &dwlen3, hashGet);
                    dwlen3 = 3;
                    if (hashEquals(hash, hashGet, hashLength)) {
                        printf("Взлом пароля: ");
                        printBytes(check3, dwlen3, 48);
                        goto stop;
                    }

                    getHashValue(check4, &dwlen4, hashGet);
                    dwlen4 = 4;
                    if (hashEquals(hash, hashGet, hashLength)) {
                        printf("Взлом пароля: ");
                        printBytes(check4, dwlen4, 48);
                        goto stop;
                    }
                }
            }
        }
    }
    printf("Пароль удалось взломать");
stop:
    free(check1);
    free(check2);
    free(check3);
    free(check4);
}

void releaseContext(HCRYPTPROV prov,
    HCRYPTHASH hash)
{
    CryptDestroyHash(hash);
    CryptReleaseContext(prov, 0);
}

int symbolTransform(char symbol)
{
    switch (symbol) {
    case 'A':
        return 10;
    case 'B':
        return 11;
    case 'C':
        return 12;
    case 'D':
        return 13;
    case 'E':
        return 14;
    case 'F':
        return 15;
    default:
        return int(symbol) - 48;
    }
}

void getHashValue(byte* data,
    DWORD* dataLen,
    byte* hash)
{
    HCRYPTPROV prov;
    HCRYPTHASH hhash;

    CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
    CryptCreateHash(prov, CALG_MD5, 0, 0, &hhash);
    CryptHashData(hhash, data, *dataLen, 0);

    CryptGetHashParam(hhash, HP_HASHVAL, NULL, dataLen, 0);
    CryptGetHashParam(hhash, HP_HASHVAL, hash, dataLen, 0);

    releaseContext(prov, hhash);
}

bool hashEquals(byte* hash1,
    byte* hash2,
    int len)
{
    for (int i = 0; i < len; i++) {
        if (hash1[i] != hash2[i])
            return false;
    }
    return true;
}

void printBytes(byte* arr,
    int len,
    int minus)
{
    for (int i = 0; i < len; i++) {
        printf("%X", arr[i] - minus);
    }
    printf("\n");
}
