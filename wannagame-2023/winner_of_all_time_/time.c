#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

int main()
{
    srand(time(NULL));
    printf("%d\n", rand());
    getchar();
}