#pragma once
#include <iostream>
#include <fstream>
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <wincrypt.h>

/*
    Функция для отладки, выводит результат выполнения промежуточных функций
*/
void writeFunc(bool func);

/*
    Генерирует ключи для шифрования и расшифровки
*/
void deriveKey(HCRYPTPROV* prov,
    HCRYPTHASH* hash,
    HCRYPTKEY* key,
    char* secret
);

/*
    Шифрует строку
*/
PBYTE encrypt(HCRYPTPROV* prov,
    HCRYPTHASH* hash,
    HCRYPTKEY* key,
    char* secret,
    char* msg
);

/*
    Расшифровывает строку
*/
PBYTE decrypt(HCRYPTPROV* prov,
    HCRYPTHASH* hash,
    HCRYPTKEY* key,
    char* secret,
    char* encrypt
);

/*
    Функция для ввода как секретных данных, так и данных для шифрования
*/
void inputData(char* secret, char* msg);

/*
    Функция для чтения данных из файла и записи их в строку
*/
char* readDataFromFile(char* filepath);

/*
    Функция для записи данных в файл
*/
void writeStringToFile(char* data, char* filepath);

/*
    Функция ввода секретного пароля для шифрования/расшифрования
*/
void inputSecret(char* secret);