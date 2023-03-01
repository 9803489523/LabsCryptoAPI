#include <iostream>
#include <Windows.h>
#include <Wincrypt.h>
#include <stdlib.h>

int main()
{
    setlocale(LC_ALL, "rus");
    srand(time(NULL));

    int random_number = rand() % 100;
    byte* random_data_generate = (byte*)malloc(random_number);
    HCRYPTPROV hprov;
    /*
        Используется CRYPT_VERIFYCONTEXT, так как с 0 не работает
    */
    CryptAcquireContext(&hprov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT); 
    CryptGenRandom(hprov, random_number, random_data_generate);

    printf("Произвольная строка длины: %d\n", random_number);

    for (int i = 0; i < random_number; i++) {
        if (i != (random_number - 1))
            printf("%d, ", random_data_generate[i]);
        else
            printf("%d\n", random_data_generate[i]);
    }

    CryptReleaseContext(hprov, 0);
    free(random_data_generate);
}