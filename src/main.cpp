#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ElfHooker.h"

int main(int argc, char* argv[])
{
    printf("hello world\n");
    ElfHooker hooker;
    hooker.phraseProcMaps();
    hooker.dumpModuleList();
    hooker.hookAllModules();
    hooker.testDlOpen();
    return 0;
}
