#pragma once
#include <iostream>
#include <Windows.h>
#include <vector>

using namespace std;

typedef struct DOS_HEADER // DOS .EXE header
{
public:
    void PrintInformation();
    WORD e_magic = 0xC0DE;       // Magic number
    WORD e_cblp;        // Byte on last page of file
    WORD e_cp;          // Pages in file
    WORD e_crlc;        // Relocations
    WORD e_cparhdr;     // Size of header in paragraphs
    WORD e_minalloc;    // Minimum extra paragraphs needed
    WORD e_maxalloc;    // Maximum extra paragraphs needed
    WORD e_ss;          // Initial (relative) SS value
    WORD e_sp;          // Checksum
    WORD e_ip;          // Initital IP value
    WORD e_cs;          // Initial (relative) CS value
    WORD e_lfarlc;      // File address of relocation table
    WORD e_ovno;        // Overlay number
    WORD e_res[4];      // Reserved words
    WORD e_oemid;       // OEM identifier (for e_oeminfo)
    WORD e_oeminfo;     // OEM information; e_oemid specific
    WORD e_res2[10];    // Reserved words
    LONG e_lfanew;      // File address of new exe header
} DOS_HEADER;

typedef struct FILE_HEADER {
public:
    void PrintInformation();
    WORD  Machine;
    WORD  NumberOfSections;
    DWORD TimeDateStamp;
    DWORD PointerToSymbolTable;
    DWORD NumberOfSymbols;
    WORD  SizeOfOptionalHeader;
    WORD  Characteristics;
} FILE_HEADER;

typedef struct DATA_DIRECTORY {
public:
    void PrintInformation(int of);
    DWORD VirtualAddress;
    DWORD Size;
} DATA_DIRECTORY;

typedef struct OPTIONAL_HEADER32 {
    WORD                 Magic;
    BYTE                 MajorLinkerVersion;
    BYTE                 MinorLinkerVersion;
    DWORD                SizeOfCode;
    DWORD                SizeOfInitializedData;
    DWORD                SizeOfUninitializedData;
    DWORD                AddressOfEntryPoint;
    DWORD                BaseOfCode;
    DWORD                BaseOfData;
    DWORD                ImageBase;
    DWORD                SectionAlignment;
    DWORD                FileAlignment;
    WORD                 MajorOperatingSystemVersion;
    WORD                 MinorOperatingSystemVersion;
    WORD                 MajorImageVersion;
    WORD                 MinorImageVersion;
    WORD                 MajorSubsystemVersion;
    WORD                 MinorSubsystemVersion;
    DWORD                Win32VersionValue;
    DWORD                SizeOfImage;
    DWORD                SizeOfHeaders;
    DWORD                CheckSum;
    WORD                 Subsystem;
    WORD                 DllCharacteristics;
    DWORD                SizeOfStackReserve;
    DWORD                SizeOfStackCommit;
    DWORD                SizeOfHeapReserve;
    DWORD                SizeOfHeapCommit;
    DWORD                LoaderFlags;
    DWORD                NumberOfRvaAndSizes;
    DATA_DIRECTORY DataDirectory[16];
} OPTIONAL_HEADER32;

typedef struct OPTIONAL_HEADER64 {
public:
    void PrintInformation();
    WORD                 Magic;
    BYTE                 MajorLinkerVersion;
    BYTE                 MinorLinkerVersion;
    DWORD                SizeOfCode;
    DWORD                SizeOfInitializedData;
    DWORD                SizeOfUninitializedData;
    DWORD                AddressOfEntryPoint;
    DWORD                BaseOfCode;
    ULONGLONG            ImageBase;
    DWORD                SectionAlignment;
    DWORD                FileAlignment;
    WORD                 MajorOperatingSystemVersion;
    WORD                 MinorOperatingSystemVersion;
    WORD                 MajorImageVersion;
    WORD                 MinorImageVersion;
    WORD                 MajorSubsystemVersion;
    WORD                 MinorSubsystemVersion;
    DWORD                Win32VersionValue;
    DWORD                SizeOfImage;
    DWORD                SizeOfHeaders;
    DWORD                CheckSum;
    WORD                 Subsystem;
    WORD                 DllCharacteristics;
    ULONGLONG            SizeOfStackReserve;
    ULONGLONG            SizeOfStackCommit;
    ULONGLONG            SizeOfHeapReserve;
    ULONGLONG            SizeOfHeapCommit;
    DWORD                LoaderFlags;
    DWORD                NumberOfRvaAndSizes;
    DATA_DIRECTORY DataDirectory[16];
} OPTIONAL_HEADER64;

typedef struct NT_HEADER32 {
    DWORD                   Signature;
    FILE_HEADER       FileHeader;
    OPTIONAL_HEADER32 OptionalHeader;
} NT_HEADER32;

typedef struct NT_HEADER64 {
public:
    DWORD Signature;
    FILE_HEADER FileHeader;
    OPTIONAL_HEADER64 OptionalHeader;
} NT_HEADER64;

typedef struct SECTION_HEADER {
public:
    void PrintInformation(OPTIONAL_HEADER64 op64);
    BYTE  Name[8];
    union {
        DWORD PhysicalAddress;
        DWORD VirtualSize;
    } Misc;
    DWORD VirtualAddress;
    DWORD SizeOfRawData;
    DWORD PointerToRawData;
    DWORD PointerToRelocations;
    DWORD PointerToLinenumbers;
    WORD  NumberOfRelocations;
    WORD  NumberOfLinenumbers;
    DWORD Characteristics;
} SECTION_HEADER;

typedef struct IMPORT_DESCRIPTOR {
public:
    void PrintInformation(vector<BYTE>& src, OPTIONAL_HEADER64 op64, vector<SECTION_HEADER>& sorted_secs);
    DWORD OriginalFirstThunk;
    DWORD TimeDateStamp;
    DWORD ForwarderChain;
    DWORD Name;
    DWORD FirstThunk;
} IMPORT_DESCRIPTOR;

class UTILS
{
public:
    bool IsPE(DOS_HEADER dos) {
        if (dos.e_magic != 0x5a4d) return false;
        return true;
    }

    bool Check64(NT_HEADER32 nt) {
        if (nt.OptionalHeader.Magic == 0x20b) return true;
        else return false;
    }

    DWORD RVA2RAW(DWORD rva, DWORD va, DWORD ptrtrd) {
        return rva - va + ptrtrd;
    }

    SECTION_HEADER FindSectionByRVA(DWORD rva, vector<SECTION_HEADER>& sorted_secs, OPTIONAL_HEADER64 op64) {
        SECTION_HEADER inv; inv.VirtualAddress = 0xDEADC0DE; 
        BYTE d[8] = {'I', 'N', 'V', 'A', 'L', 'I', 'D', '\0'};
        for (int i = 0; i < 8; i++) inv.Name[i] = d[i];

        for (int i = 0; i < sorted_secs.size(); i++) {
            if (sorted_secs[i].VirtualAddress > rva) {
                if (i == 0) return inv;
                return sorted_secs[i - 1];
            }
        }
        return rva < op64.SizeOfImage ? sorted_secs[sorted_secs.size() - 1] : inv;
    }
};

