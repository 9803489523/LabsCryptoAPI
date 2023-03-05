#define _CRT_SECURE_NO_WARNINGS 1

#include <stdio.h>
#include <iostream>
#include <fstream>
#include <string>
#include <Windows.h>
#include <Wincrypt.h>
#include <stdlib.h>

//#define DEBUG

using namespace std;

LPCSTR getAlgID(byte * arr);

int main()
{
    setlocale(LC_ALL, "rus");

    HCRYPTPROV hprov;
    HCRYPTHASH hcrypt;
    char * filepath;
    string read_data;
    string data;
    byte * byte_data;
    byte * pb_data;
    byte * hash_alg;
    DWORD len_hash_alg = 0;

    filepath = (char *)malloc(100);

    printf("Введите путь к файлу: ");
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
        CryptCreateHash(hprov, CALG_SHA1, 0, 0, &hcrypt);
        CryptHashData(hcrypt, byte_data, len, 0);

        CryptGetHashParam(hcrypt, HP_HASHVAL, NULL, &len, 0);
        pb_data = (byte *)malloc(len);
        CryptGetHashParam(hcrypt, HP_HASHVAL, pb_data, &len, 0);

        CryptGetHashParam(hcrypt, HP_ALGID, NULL, &len_hash_alg, 0);
        hash_alg = (byte*)malloc(len_hash_alg);
        CryptGetHashParam(hcrypt, HP_ALGID, hash_alg, &len_hash_alg, 0);

        printf("\nХэш-значение данных в файле %s:\n", filepath);
        for (int i = 0; i < len; i++) {
            printf("%X", pb_data[i]);
        }
        printf("\nИдентификатор алгоритма хэщирования: %s (%d)\n", getAlgID(hash_alg), len_hash_alg);
     
        CryptReleaseContext(hprov, 0);
        CryptDestroyHash(hcrypt);
        free(byte_data);
        free(pb_data);
        free(filepath);
        free(hash_alg);
        system("pause");
    }
    stop:
        system("pause");
}

LPCSTR getAlgID(byte* arr) {
    switch (arr[0]){
    case 1:
        return "CALG_MD2";
    case 2:
        return "CALG_MD4";
    case 3:
        return "CALG_MD5";
    case 4:
        return "CALG_SHA";
    default:
        return "undefined";
    }
}