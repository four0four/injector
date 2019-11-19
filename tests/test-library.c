#include <stdio.h>
#include <stdlib.h>

extern int exit_value;

__attribute__((constructor))
void init()
{
	printf("hello from injection\n");
    exit_value = 123;
}
