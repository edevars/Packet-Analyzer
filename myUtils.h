#include <stdio.h>
#include <stdbool.h>

bool validateArguments(char const *arg[])
{
    if (arg[1] == NULL)
    {
        printf("\e[38;5;196mPlease insert the number of packages that will be captured\n");
        return false;
    }

    if (arg[2] == NULL)
    {
        printf("\e[38;5;196mPlease insert the name of your network card\n");
        return false;
    }

    return true;
}