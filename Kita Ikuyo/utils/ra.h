#include <fstream>
#include <Windows.h>
#include <vector>
#include <math.h>

using namespace std;

struct RA {

public:
	int powi(int x, int y) {
		return (int)ceil(pow(x, y));
	}

	DWORD ReadDW(vector<BYTE>& src, int offset) {
		DWORD ret = 0;
		//for (int i = 3; i >= 0; i--) ret += src[offset + i] * 1;
		return ret;
	}

	WORD ReadW(vector<BYTE>& src, int offset) {
		WORD ret = 0;
		//for (int i = 1; i >= 0; i--) ret += src[offset + i] * 1;
		return ret;
	}

	vector<char> ReadString(vector<BYTE>& src, int offset) {
		int i = 0; vector<char> ret;
		//while (src[offset + i] != 0) {
			//ret.push_back(src[offset + i]);
		//}
		return ret;
	}

	vector<BYTE> ReadWholeBytes(string fileName) {

		ifstream bFile(fileName, ios::binary);
		vector<BYTE> toReturn = { };

		if (bFile.is_open()) {
			bFile.seekg(0, ios::end); size_t sz = bFile.tellg(); bFile.seekg(0, ios::beg);
			toReturn.resize(sz);

			bFile.read((char*)&toReturn[0], sz);
			bFile.close();
		}
		else {
			cerr << "Unable to open " << fileName << ", is it correct?\n";
		}

		return toReturn;
	}
} RA;