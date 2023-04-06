#include "ra.h"

using namespace std;

vector<BYTE> RA::ReadWholeBytes(string fileName) {

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