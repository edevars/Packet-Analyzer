#include <stdio.h>
#include "myUtils.h"
#include <stdlib.h>
#include <stdbool.h>

int main(int argc, char const *argv[])
{
    bool existArguments = validateArguments(argv);
    if (existArguments == true)
    {
        printf("All is ok! the arguments are: \npackages: %s \nnetwork card name: %s\n", argv[1], argv[2]);
    }

    return 0;
}
