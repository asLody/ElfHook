#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ElfHooker.h"

int main(int argc, char* argv[])
{
    printf("hello world\n");
    ElfHooker hooker;
    hooker.testDlOpen();
    hooker.phraseProcMaps();
    hooker.dumpModuleList();
    hooker.hookAllModules();

    return 0;
}
