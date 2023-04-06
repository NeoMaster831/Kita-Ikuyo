#include <iostream>
#include "ra.h"
#include "magic.h"
#include <algorithm>

using namespace std;
#define CLEARCONSOLE for (int i = 0; i < 100; i++) cout << '\n';

bool cmp_rva(SECTION_HEADER left, SECTION_HEADER right) {
    return left.VirtualAddress < right.VirtualAddress;
}

int main()
{
    cout << "Gimme the path of input file" << '\n';
    string inp; getline(cin, inp);

    RA ra;
    vector<BYTE> PE = ra.ReadWholeBytes(inp);
    UTILS util;

    DOS_HEADER dos;
    ra.ReadMemory(PE, dos, 0);

    if (!util.IsPE(dos)) {
        cout << "This is not PE file! Please check it out!" << '\n';
        return EXIT_FAILURE;
    }

    NT_HEADER32 nt32;
    ra.ReadMemory(PE, nt32, dos.e_lfanew);

    if (util.Check64(nt32)) {
        NT_HEADER64 nt64;
        ra.ReadMemory(PE, nt64, dos.e_lfanew);
        //nt64.OptionalHeader.PrintInformation();
        vector<SECTION_HEADER> secs;

        int j = 0;
        for (int i = 0; i < nt64.FileHeader.NumberOfSections; i++) {
            SECTION_HEADER se;
            ra.ReadMemory(PE, se, dos.e_lfanew + sizeof(nt64) + j);
            secs.push_back(se);
            j += sizeof(se);
        }
        sort(secs.begin(), secs.end(), cmp_rva);
        
        //secs[0].PrintInformation(nt64.OptionalHeader);
        SECTION_HEADER hs = util.FindSectionByRVA(nt64.OptionalHeader.DataDirectory[1].VirtualAddress, secs, nt64.OptionalHeader);
        DWORD im = util.RVA2RAW(nt64.OptionalHeader.DataDirectory[1].VirtualAddress, hs.VirtualAddress, hs.PointerToRawData);
        vector<IMPORT_DESCRIPTOR> ide;
        while (PE[im] != 0) {
            IMPORT_DESCRIPTOR idee;
            ra.ReadMemory(PE, idee, im);
            ide.push_back(idee);
            im += sizeof(IMPORT_DESCRIPTOR);
        }

        while (1) {

            CLEARCONSOLE;
            cout << "\nQueries:\n\t1: DOS Header\n\t2: File Header\n\t3: Optional Header\n\t4: Section Headers\n\t5: Import Descriptors\n\t6 <RVA>: Show attributes of <RVA>. the arg is hex.\n\t7: NULL Padding Areas\n\t8: Exit\n";
            int q; cin >> q;

            switch (q) {
            case 1:
                CLEARCONSOLE;
                dos.PrintInformation(); cout << '\n';
                break;
            case 2:
                CLEARCONSOLE;
                nt64.FileHeader.PrintInformation(); cout << '\n';
                break;
            case 3:
                CLEARCONSOLE;
                nt64.OptionalHeader.PrintInformation(); cout << '\n';
                break;
            case 4:
                CLEARCONSOLE;
                for (int i = 0; i < secs.size(); i++) {
                    secs[i].PrintInformation(nt64.OptionalHeader);
                }
                cout << '\n';
                break;
            case 5:
                CLEARCONSOLE;
                cout << "*** IMPORT MODULE SIZE: " << ide.size() << " ***" << '\n';
                for (int i = 0; i < ide.size(); i++) {
                    ide[i].PrintInformation(PE, nt64.OptionalHeader, secs);
                }
                cout << '\n';
                break;
            case 6:
                CLEARCONSOLE;
                int query; cin >> hex >> query;
                SECTION_HEADER isc = util.FindSectionByRVA(query, secs, nt64.OptionalHeader);
                cout << "This is not accurate in all of cases! (like the case of Size differ)" << '\n';
                cout << hex << "Your Input: HEX; 0x" << query; cout << dec << " DEC; " << query << '\n';
                cout << "Section Name: " << isc.Name << '\n';
                cout << hex;
                cout << "RVA to RAW: 0x" << util.RVA2RAW(query, isc.VirtualAddress, isc.PointerToRawData) << '\n';
                cout << "Section Area: 0x" << isc.VirtualAddress << " ~ 0x" << isc.Misc.VirtualSize << '\n';
                cout << dec;
                break;
            case 7:
                CLEARCONSOLE;
                cout << hex << '\n';
                cout << "All of these values are RVAs! You should add Image Base into this.\n";
                for (int i = 0; i < secs.size() - 1; i++) {
                    if (secs[i + 1].VirtualAddress == secs[i].Misc.VirtualSize + secs[i].VirtualAddress) continue;
                    cout << "0x" << secs[i].Misc.VirtualSize + secs[i].VirtualAddress << " ~ 0x" << secs[i + 1].VirtualAddress - 1 << '\n';
                }
                cout << "0x" << secs[secs.size() - 1].VirtualAddress + secs[secs.size() - 1].Misc.VirtualSize << " ~ 0x" << nt64.OptionalHeader.SizeOfImage - 1 << '\n';
                cout << dec << '\n';
                break;
            case 8:
                CLEARCONSOLE;
                return EXIT_SUCCESS;
            default:
                CLEARCONSOLE;
                cout << "Invalid Query!\n";
                break;
            }

            cout << "Input any string to escape\n";
            string key; cin >> key;
        }

    }
    else {
        cout << "We don't support 32 bits at the moment!" << '\n';
    }

}
