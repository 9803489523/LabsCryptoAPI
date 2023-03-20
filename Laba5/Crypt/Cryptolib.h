#pragma once
#include <iostream>
#include <fstream>
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <wincrypt.h>

#define DEFAULT_CONTAINER  "laba5"

void fillInContainer();

byte* userInput();

void printBytes(byte* arr, int len);

void writeDataToFile(byte* data, DWORD dataLen, char* filepath);

byte* readDataFromFile(char* filepath);
