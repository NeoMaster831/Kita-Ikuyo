#include "structures.h"

DOS_HEADER::DOS_HEADER(vector<BYTE>& src) {

	RA ra;
	this->e_magic = ra.ReadW(src, 0);
	this->e_cblp = ra.ReadW(src, 2);
	this->e_cp = ra.ReadW(src, 4);
	this->e_crlc = ra.ReadW(src, 6);
	this->e_cparhdr = ra.ReadW(src, 8);
	this->e_minalloc = ra.ReadW(src, 10);
	this->e_maxalloc = ra.ReadW(src, 12);
	this->e_ss = ra.ReadW(src, 14);
	this->e_sp = ra.ReadW(src, 16);
	this->e_csum = ra.ReadW(src, 18);
	this->e_ip = ra.ReadW(src, 20);
	this->e_cs = ra.ReadW(src, 22);
	this->e_lfarlc = ra.ReadW(src, 24);
	this->e_ovno = ra.ReadW(src, 26);
	for (int i = 0; i < 4; i++) this->e_res[i] = ra.ReadW(src, 28 + i * 2);
	this->e_oemid = ra.ReadW(src, 36);
	this->e_oeminfo = ra.ReadW(src, 38);
	for (int i = 0; i < 10; i++) this->e_res2[i] = ra.ReadW(src, 40 + i * 2);
	this->e_lfanew = ReadDW(src, 60);
}