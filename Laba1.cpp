#define _CRT_SECURE_NO_WARNINGS 1

#include <iostream>
#include <Windows.h>
#include <Wincrypt.h>
#include <stdlib.h>
#include <fstream>
/*
    shell command "certutil -csplist"
*/
/*
    file_path "D:\abs.txt"
*/
typedef struct {
    const char* provFullName;
    const wchar_t* provPsevdonim;
    int provType;
} Provider;

void menuProviders(int* input, Provider* provider, Provider* providers, int provNumber);

void inputArr(int* length);

int main()
{
    Provider providers[10] = { {MS_DEF_PROV_A, MS_DEF_PROV, PROV_RSA_FULL},
                                {MS_DEF_DSS_DH_PROV_A, MS_DEF_DSS_DH_PROV, PROV_DSS_DH},
                                {MS_DEF_DSS_PROV_A, MS_DEF_DSS_PROV, PROV_DSS},
                                {MS_SCARD_PROV_A, MS_SCARD_PROV, PROV_RSA_FULL},
                                {MS_DEF_DH_SCHANNEL_PROV_A, MS_DEF_DH_SCHANNEL_PROV, PROV_DH_SCHANNEL},
                                {MS_ENHANCED_PROV_A, MS_ENHANCED_PROV, PROV_RSA_FULL},
                                {MS_ENH_DSS_DH_PROV_A, MS_ENH_DSS_DH_PROV, PROV_DSS_DH},
                                {MS_ENH_RSA_AES_PROV_A, MS_ENH_RSA_AES_PROV, PROV_RSA_AES},
                                {MS_DEF_RSA_SCHANNEL_PROV_A, MS_DEF_RSA_SCHANNEL_PROV, PROV_RSA_SCHANNEL},
                                {MS_STRONG_PROV_A, MS_STRONG_PROV, PROV_RSA_FULL} };
    setlocale(LC_ALL, "rus");
    Provider prov = {};
    int input = 0;

    menuProviders(&input, &prov, providers, 10);

    int dataLength = 0;
    inputArr(&dataLength);
    byte* random_data_generate = (byte*)malloc(dataLength);

    HCRYPTPROV hprov;

    char* filePath;
    filePath = (char*)malloc(100);

    printf("\nВведите путь к файлу: ");
    scanf("%s", filePath);

    std::ofstream out;
    out.open(filePath);

    CryptAcquireContext(&hprov, NULL, prov.provPsevdonim, prov.provType, CRYPT_VERIFYCONTEXT);
    CryptGenRandom(hprov, dataLength, random_data_generate);

    if (out.is_open()) {
        out << "Random data with length " << dataLength << "\n";
        out << "As string\n";
        for (int i = 0; i < dataLength; i++) {
            out << random_data_generate[i];
        }
        out << "\nAs integer\n";
        for (int i = 0; i < dataLength; i++) {
            if (i != (dataLength - 1))
                out << (int)random_data_generate[i] << ", ";
            else
                out << (int)random_data_generate[i] << ".";
        }
    }
    else {
        printf("Ошибка при записи файла.");
    }

    CryptReleaseContext(hprov, 0);
    free(random_data_generate);
    free(filePath);

    system("pause");
}

void menuProviders(int* input, Provider* provider, Provider* providers, int provNumber) {
    printf("Выберете криптопровайдера из списка: \n");
    for (int i = 0; i < provNumber; i++) {
        printf("\t%d). %s\n", i + 1, providers[i].provFullName);
    }
    scanf("%d", input);
    if ((*input < 1) || (*input > provNumber)) {
        printf("Данные некорректны! Повторите ввод.\n");
        menuProviders(input, provider, providers, provNumber);
    }
    else {
        *provider = providers[*input - 1];
    }
}

void inputArr(int* length) {
    printf("Введите длину произвольного массива данных: ");
    scanf("%d", length);
    if (!(length > 0)) {
        printf("Данные некорректны! Повторите ввод.\n");
        inputArr(length);
    }
}