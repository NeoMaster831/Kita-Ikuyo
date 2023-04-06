#include "magic.h"
#include "ra.h"

using namespace std;

void DOS_HEADER::PrintInformation() {
	cout << hex;
	string valid = this->e_magic == 0x5a4d ? "VALID" : "INVALID";
	cout << "* DOS Header Signature: " << valid << "; 0x" << this->e_magic << '\n';
    cout << "e_cblp: 0x" << this->e_cblp << '\n';
    cout << "e_cp: 0x" << this->e_cp << '\n';
    cout << "e_crlc: 0x" << this->e_crlc << '\n';
    cout << "e_cparhdr: 0x" << this->e_cparhdr << '\n';
    cout << "e_minalloc: 0x" << this->e_minalloc << '\n';
    cout << "e_maxalloc: 0x" << this->e_maxalloc << '\n';
    cout << "e_ss: 0x" << this->e_ss << '\n';
    cout << "e_sp: 0x" << this->e_sp << '\n';
    cout << "e_ip: 0x" << this->e_ip << '\n';
    cout << "e_cs: 0x" << this->e_cs << '\n';
    cout << "e_lfarlc: 0x" << this->e_lfarlc << '\n';
    cout << "e_ovno: 0x" << this->e_ovno << '\n';
    cout << "e_res: ";
    for (int i = 0; i < 4; i++) cout << "0x" << e_res[i] << " (" << i << "); ";
    cout << '\n';
    cout << "e_oemid: 0x" << this->e_oemid << '\n';
    cout << "e_oeminfo: 0x" << this->e_oeminfo << '\n';
    cout << "e_res2: ";
    for (int i = 0; i < 10; i++) cout << "0x" << e_res2[i] << " (" << i << "); ";
    cout << '\n';
    cout << "* Address of IMAGE_NT_HEADER: 0x" << this->e_lfanew << '\n';
    cout << dec;
}

void FILE_HEADER::PrintInformation() {

    cout << "* Executable Machine: ";
    switch (this->Machine) {
    case 0x14c: cout << "x86"; break;
    case 0x200: cout << "Intel Itanium"; break;
    case 0x8664: cout << "x64"; break;
    default: cout << "Unknown"; break;
    }
    cout << '\n';
    cout << "* Number of Sections: " << this->NumberOfSections << '\n';
    cout << "Updated Timestamp: 0x" << hex << this->TimeDateStamp << '\n';
    cout << "Pointer to Symbol Table: 0x" << hex << this->PointerToSymbolTable << '\n';
    cout << "Number of Symbols: " << dec << this->NumberOfSymbols << '\n';
    cout << "* Size of Optional Header: 0x" << hex << this->SizeOfOptionalHeader << dec << '\n';
    cout << dec << "* Attributes:\n"; WORD Attribute = this->Characteristics;
    if (Attribute & 0x0001) cout << "\tIMAGE_FILE_RELOCS_STRIPPED\n";
    if (Attribute & 0x0002) cout << "\t* Executable\n";
    if (Attribute & 0x0004) cout << "\tIMAGE_FILE_LINE_NUMS_STRIPPED\n";
    if (Attribute & 0x0008) cout << "\tIMAGE_FILE_LOCAL_SYMS_STRIPPED\n";
    if (Attribute & 0x0010) cout << "\tIMAGE_FILE_AGGRESSIVE_WS_TRIM\n";
    if (Attribute & 0x0020) cout << "\tCan handle addresses larger than 2GB\n";
    if (Attribute & 0x0080) cout << "\tIMAGE_FILE_BYTES_REVERSED_LO\n";
    if (Attribute & 0x0100) cout << "\t* x32 compatible\n";
    if (Attribute & 0x0200) cout << "\tIMAGE_FILE_DEBUG_STRIPPED\n";
    if (Attribute & 0x0400) cout << "\tIMAGE_FILE_REMOVABLE_RUN_FROM_SWAP\n";
    if (Attribute & 0x0800) cout << "\tIMAGE_FILE_NET_RUN_FROM_SWAP\n";
    if (Attribute & 0x1000) cout << "\t* System File\n";
    if (Attribute & 0x2000) cout << "\t* DLL File\n";
    if (Attribute & 0x4000) cout << "\tShould run in unicomputer system\n";
    if (Attribute & 0x8000) cout << "\tIMAGE_FILE_BYTES_REVERSED_HI\n";
    cout << dec;
}

void OPTIONAL_HEADER64::PrintInformation() {

    cout << "* Signature: ";
    switch (this->Magic) {
    case 0x20b: cout << "x64"; break;
    case 0x10b: cout << "x32"; break;
    }
    cout << '\n';

    cout << "Major Linker Version: " << this->MajorLinkerVersion << '\n';
    cout << "Minor Linker Version: " << this->MinorLinkerVersion << '\n';
    cout << hex;
    cout << "Size of Code: 0x" << this->SizeOfCode << '\n';
    cout << "Size of Initialized Data: 0x" << this->SizeOfInitializedData << '\n';
    cout << "Size of Uninitialized Data: 0x" << this->SizeOfUninitializedData << '\n';
    cout << "* RVA of Entry Point: 0x" << this->AddressOfEntryPoint << '\n';
    cout << "Base of Code: 0x" << this->BaseOfCode << '\n';
    cout << "* Image Base: 0x" << this->ImageBase << '\n';
    cout << "* Minimal Unit of Section in Memory: 0x" << this->SectionAlignment << '\n';
    cout << "* Minimal Unit of Section in File: 0x" << this->FileAlignment << '\n';
    cout << dec;
    cout << "Major Operating System Version: " << this->MajorOperatingSystemVersion << '\n';
    cout << "Minor Operating System Version: " << this->MinorOperatingSystemVersion << '\n';
    cout << "Major Image Version: " << this->MajorImageVersion << '\n';
    cout << "Minor Image Version: " << this->MinorImageVersion << '\n';
    cout << "Win32 Version Value: " << this->Win32VersionValue << '\n';
    cout << hex;
    cout << "* Size of Memory that allocates when executed: 0x" << this->SizeOfImage << '\n';
    cout << "* Size of Header (in File): 0x" << this->SizeOfHeaders << '\n';
    cout << "Checksum: 0x" << this->CheckSum << '\n';
    cout << dec;

    cout << "Execute Attributes: ";
    switch (this->Subsystem) {
    case 1: cout << "Driver File"; break;
    case 2: cout << "User Interface File"; break;
    case 3: cout << "Console File"; break;
    }
    cout << '\n';

    cout << hex;
    cout << "DLL Attributes: 0x" << this->DllCharacteristics << '\n';
    cout << "Stack Reserve Size: 0x" << this->SizeOfStackReserve << '\n';
    cout << "Stack Commit Size: 0x" << this->SizeOfStackCommit << '\n';
    cout << "Heap Reserve Size: 0x" << this->SizeOfHeapReserve << '\n';
    cout << "Heap Commit Size: 0x" << this->SizeOfHeapCommit << '\n';
    cout << "Loader Flags: 0x" << this->LoaderFlags << '\n';
    cout << dec;

    cout << "* Number of Directories: " << this->NumberOfRvaAndSizes << '\n';
    cout << "* Directories: \n";
    for (DWORD i = 0; i < this->NumberOfRvaAndSizes; i++) {
        this->DataDirectory[i].PrintInformation(i);
    }

}

void DATA_DIRECTORY::PrintInformation(int of) {
    string d[16] = { "Export", "Import", "Resource", "Exception", "Security", "BaseRelocation", "Debug", "Copyright", "Global Pointer", "TLS", "Load Config", "Bound Import", "IAT", "Delay Import", "Com Descriptor", "Reserved" };
    cout << "\t* " << d[of] << '\n';
    cout << "\t - Size: " << hex << this->Size << '\n';
    cout << "\t - RVA of pointer: 0x" << hex << this->VirtualAddress << '\n';
    cout << dec;
}

void SECTION_HEADER::PrintInformation(OPTIONAL_HEADER64 op64) {
    cout << hex;
    cout << "Name: ";
    for (int i = 0; i < 8; i++) cout << this->Name[i];
    cout << '\n';

    cout << "Size of Section in Memory: 0x" << this->Misc.VirtualSize << '\n';
    cout << "Section Start Address in Memory: 0x" << this->VirtualAddress << '\n';
    cout << "Size of Section in File: 0x" << this->SizeOfRawData << '\n';
    cout << "Section Start Address in File: 0x" << this->PointerToRawData << '\n';
    cout << "Attributes: \n"; DWORD att = this->Characteristics;
    if (att & 0x20) cout << "\tSection contains code" << '\n';
    if (att & 0x40) cout << "\tSection contains data" << '\n';
    if (att & 0x80) cout << "\tSection contains BSS" << '\n';
    if (att & 0x20000000) cout << "\tSection is Executable" << '\n';
    if (att & 0x40000000) cout << "\tSection is Readable" << '\n';
    if (att & 0x80000000) cout << "\tSection is Writable" << '\n';
    cout << dec;
}

void IMPORT_DESCRIPTOR::PrintInformation(vector<BYTE>& src, OPTIONAL_HEADER64 op64, vector<SECTION_HEADER>& sorted_secs) {
    cout << hex;
    UTILS util; RA ra;
    cout << "Name: ";
    SECTION_HEADER ns = util.FindSectionByRVA(this->Name, sorted_secs, op64);
    DWORD rawName = util.RVA2RAW(this->Name, ns.VirtualAddress, ns.PointerToRawData);
    while (src[rawName] != 0) {
        cout << src[rawName]; rawName++;
    }
    cout << '\n';

    SECTION_HEADER ints = util.FindSectionByRVA(this->OriginalFirstThunk, sorted_secs, op64);
    DWORD rawINT = util.RVA2RAW(this->OriginalFirstThunk, ints.VirtualAddress, ints.PointerToRawData);
    while (src[rawINT] != 0) {
        DWORD off; ra.ReadMemory(src, off, rawINT);
        SECTION_HEADER Imports = util.FindSectionByRVA(off, sorted_secs, op64);
        DWORD rawOff = util.RVA2RAW(off, Imports.VirtualAddress, Imports.PointerToRawData);
        cout << '\t';
        while (src[rawOff] != 0) {
            cout << src[rawOff]; rawOff++;
        }
        cout << '\n';
        rawINT += 8;
    }
    cout << dec;
}