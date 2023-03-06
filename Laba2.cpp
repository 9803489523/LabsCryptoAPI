#define _CRT_SECURE_NO_WARNINGS 1

#include <stdio.h>
#include <iostream>
#include <fstream>
#include <string>
#include <Windows.h>
#include <Wincrypt.h>
#include <stdlib.h>

#define NUMBER 10
//#define DEBUG
//#define MODE_WITH_GENERATE_HASH_AND_BROOTFORCE
//path E:\C\c++\data.txt
//path D:\password.txt

using namespace std;

bool hashEquals(byte* hash1, byte* hash2, int len);

void getHashValue(byte* data, DWORD* data_len, byte* pb_data);

void printBytes(byte* arr, int len, int minus);

void readHashFromFileToByteArr(char* filepath, byte* arr);

int symbolTransform(char symbol);

int main()
{
    setlocale(LC_ALL, "rus");
    char* filepath;
    filepath = (char*)malloc(100);
#ifdef MODE_WITH_GENERATE_HASH_AND_BROOTFORCE
    HCRYPTPROV hprov;
    HCRYPTHASH hcrypt;

    string read_data;
    string data;
    byte* byte_data;
    byte* pb_data;

    printf("Введите путь к файлу для чтения пароля: ");
    scanf("%s", filepath);

    ifstream in(filepath);

    if (in.is_open())
    {
        while (getline(in, read_data)) {
            data.append(read_data);
        }
    }

    in.close();

    if (data.empty()) {
        printf("\nУказан некорректный путь к файлу\n");
        goto stop;
    }
    {
#ifdef DEBUG
        std::cout << "\n" << data << "\n";
#endif   
        byte_data = (byte*)malloc(data.length());
        DWORD len = data.length();
        memcpy(byte_data, data.data(), data.length());

        CryptAcquireContext(&hprov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
        CryptCreateHash(hprov, CALG_MD5, 0, 0, &hcrypt);
        CryptHashData(hcrypt, byte_data, len, 0);

        CryptGetHashParam(hcrypt, HP_HASHVAL, NULL, &len, 0);
        pb_data = (byte*)malloc(len);
        CryptGetHashParam(hcrypt, HP_HASHVAL, pb_data, &len, 0);
#endif
        printf("Введите путь к файлу с хэшем пароля: ");
        scanf("%s", filepath);

        ofstream out;
        int hashLength = 16;
        byte* hash_byte;
        byte* check1;
        byte* check2;
        byte* check3;
        byte* check4;
        DWORD dwlen1 = 1;
        DWORD dwlen2 = 2;
        DWORD dwlen3 = 3;
        DWORD dwlen4 = 4;
        byte* hash_get;
        char* data_to_write;


        check1 = (byte*)malloc(1);
        check2 = (byte*)malloc(2);
        check3 = (byte*)malloc(3);
        check4 = (byte*)malloc(4);


#ifdef MODE_WITH_GENERATE_HASH_AND_BROOTFORCE

        data_to_write = (char*)malloc(len);
        memcpy(data_to_write, pb_data, len);

        FILE* pf;
        if (!(pf = fopen(filepath, "w")))
        {
            cout << "Error\n";
            goto stop;
        }
        for (int i = 0; i < len; i++) {
            fprintf(pf, "%.2X", pb_data[i]);
        }
        fclose(pf);
#endif

        hash_byte = (byte*)malloc(hashLength);
        hash_get = (byte*)malloc(hashLength);

        readHashFromFileToByteArr(filepath, hash_byte);

        printf("\nХэш, полученный из файла %s:\n", filepath);
        for (int i = 0; i < hashLength; i++) {
            printf("%X", hash_byte[i]);
        }
        printf("\n");

        for (int it1 = 0; it1 < NUMBER; it1++) {
            check1[0] = it1 + 48;
            check2[0] = it1 + 48;
            check3[0] = it1 + 48;
            check4[0] = it1 + 48;
            for (int it2 = 0; it2 < NUMBER; it2++) {
                check2[1] = it2 + 48;
                check3[1] = it2 + 48;
                check4[1] = it2 + 48;
                for (int it3 = 0; it3 < NUMBER; it3++) {
                    check3[2] = it3 + 48;
                    check4[2] = it3 + 48;
                    for (int it4 = 0; it4 < NUMBER; it4++) {
                        check4[3] = it4 + 48;

                        getHashValue(check1, &dwlen1, hash_get);
                        dwlen1 = 1;
                        if (hashEquals(hash_byte, hash_get, hashLength)) {
                            printf("Взлом пароля: ");
                            printBytes(check1, dwlen1, 48);
                            goto forCheck1Stop;
                        }

                        getHashValue(check2, &dwlen2, hash_get);
                        dwlen2 = 2;
                        if (hashEquals(hash_byte, hash_get, hashLength)) {
                            printf("Взлом пароля: ");
                            printBytes(check2, dwlen2, 48);
                            goto forCheck1Stop;
                        }

                        getHashValue(check3, &dwlen3, hash_get);
                        dwlen3 = 3;
                        if (hashEquals(hash_byte, hash_get, hashLength)) {
                            printf("Взлом пароля: ");
                            printBytes(check3, dwlen3, 48);
                            goto forCheck1Stop;
                        }

                        getHashValue(check4, &dwlen4, hash_get);
                        dwlen4 = 4;
                        if (hashEquals(hash_byte, hash_get, hashLength)) {
                            printf("Взлом пароля: ");
                            printBytes(check4, dwlen4, 48);
                            goto forCheck1Stop;
                        }

                    }
                }
            }
        }
    forCheck1Stop:
#ifdef MODE_WITH_GENERATE_HASH_AND_BROOTFORCE
        CryptReleaseContext(hprov, 0);
        CryptDestroyHash(hcrypt);
        free(byte_data);
        free(pb_data);
#endif
        free(filepath);
        free(check1);
        free(check2);
        free(check3);
        free(check4);
        system("pause");
    }
#ifdef MODE_WITH_GENERATE_HASH_AND_BROOTFORCE
    stop :
    system("pause");
}
#endif
bool hashEquals(byte* hash1, byte* hash2, int len) {
    for (int i = 0; i < len; i++) {
        if (hash1[i] != hash2[i])
            return false;
    }
    return true;
}

void getHashValue(byte* data, DWORD* data_len, byte* pb_data) {
    HCRYPTPROV prov;
    HCRYPTHASH hash;

    CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
    CryptCreateHash(prov, CALG_MD5, 0, 0, &hash);
    CryptHashData(hash, data, *data_len, 0);

    CryptGetHashParam(hash, HP_HASHVAL, NULL, data_len, 0);
    CryptGetHashParam(hash, HP_HASHVAL, pb_data, data_len, 0);

    CryptReleaseContext(prov, 0);
    CryptDestroyHash(hash);
}

void printBytes(byte* arr, int len, int minus) {
    for (int i = 0; i < len; i++) {
        printf("%X", arr[i] - minus);
    }
    printf("\n");
}

void readHashFromFileToByteArr(char* filepath, byte* arr) {
    ifstream read(filepath);
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
    printf("\n");
    read.close();
}

int symbolTransform(char symbol) {
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