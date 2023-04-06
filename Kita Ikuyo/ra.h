#pragma once
#include <Windows.h>
#include <vector>
#include <string>
#include <fstream>
#include <iostream>

using namespace std;

class RA
{
public:
	vector<BYTE> ReadWholeBytes(string fileName);

	template <class T>
	void ReadMemory(vector<BYTE>& src, T& dst, int offset) {
		memcpy(&dst, &src[0] + offset, sizeof(dst));
	}
};

