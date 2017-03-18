#include <stdio.h>

int main(int argc, char *argv[])
{
	char *args[3];
	args[0] = argv[1];
	args[1] = argv[2];
	args[2] = NULL;
	if(execve("1", args, NULL) < 0)
		printf("fail\n");
	return 0;
}
