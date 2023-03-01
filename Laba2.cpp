#include <iostream>
#include <fstream>
#include <string>
#include <Windows.h>
#include <Wincrypt.h>
#include <stdlib.h>

using namespace std;

int main()
{
    setlocale(LC_ALL, "rus");

    HCRYPTPROV hprov;
    HCRYPTHASH hcrypt;

    ifstream in("hello.txt");
    string read_data;
    string data;
    byte * byte_data;
    byte * pb_data;
   
    if (in.is_open())
    {
        while (getline(in, read_data)) {
            data.append(read_data);
        }
    }

    in.close();

    byte_data = (byte *)malloc(data.length());
    pb_data = (byte *)malloc(100);
    memset(pb_data, 0, 100);
    DWORD len = data.length();
    memcpy(byte_data, data.data(), data.length());

    CryptAcquireContext(&hprov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
    CryptCreateHash(hprov, CALG_MD5, 0, 0, &hcrypt);
    CryptHashData(hcrypt, byte_data, len, 0);
    CryptGetHashParam(hcrypt, HP_HASHVAL, pb_data, &len, 0);
    printf("Хэш-значение данных в файле hello.txt:\n");
    for (int i = 0; i < 97; i++) {
        if (pb_data[i] == 0 &&
            pb_data[i + 1] == 0 &&
            pb_data[i + 2] == 0) {
            break;
        }
        printf("%X", pb_data[i]);
    }

    CryptReleaseContext(hprov, 0);
    CryptDestroyHash(hcrypt);
    free(byte_data);
    free(pb_data);
}
