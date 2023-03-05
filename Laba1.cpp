#define _CRT_SECURE_NO_WARNINGS 1

#include <iostream>
#include <Windows.h>
#include <Wincrypt.h>
#include <stdlib.h>
#include <fstream>

int main()
{
    setlocale(LC_ALL, "rus");
    srand(time(NULL));

    int random_number = rand() % 100;
    byte* random_data_generate = (byte*)malloc(random_number);
    HCRYPTPROV hprov;
    char * filePath;
    filePath = (char *)malloc(100);

    printf("Введите путь к файлу: ");
    scanf("%s", filePath);

    std::ofstream out;         
    out.open(filePath); 

    CryptAcquireContext(&hprov, NULL, NULL, 1, CRYPT_VERIFYCONTEXT); 
    CryptGenRandom(hprov, random_number, random_data_generate);
  
    if (out.is_open()) {
        out << "Random data with length " << random_number << "\n";
        out << "As string\n";
        for (int i = 0; i < random_number; i++) {
                out << random_data_generate[i];
        }
        out << "\nAs integer\n";
        for (int i = 0; i < random_number; i++) {
            if (i != (random_number - 1))
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
}


