#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ElfHooker.h"

int main(int argc, char* argv[])
{
    char ch = 0;
    ElfHooker hooker;
    hooker.testDLOpen();
log_dbg("begin self code..\n");
//    hooker.phraseProcMaps();
//    hooker.dumpModuleList();
    // hooker.hookAllModules();

    do {
        ch = getc(stdin);
    } while(ch != 'q');
    return 0;
}
