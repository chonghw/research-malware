#include <stdio.h>
#include <sys/stat.h>

int main(int argc, char *argv[])
{
	struct stat buf;
	FILE *in, *out;
	char input[256];

	system("gcc -Wall -O2 -o kis loader.c; strip kis");

	lstat("./kis", &buf);
	
	if((in = fopen("loader.c", "r")) == NULL)
	{
		fprintf(stderr, "error opening loader.c for read access\n");
		exit(-1);
	}

	if((out = fopen("loader2.c", "w")) == NULL)
	{
		fprintf(stderr, "error opening loader2.c for write access\n");
		fclose(in);
		exit(-1);
	}

	while(!feof(in))
	{
		memset(input, 0, sizeof(input));
		if(fgets(input, sizeof(input), in) == NULL)
			break;
		if(strncmp("long big", input, 8) == 0)
			fprintf(out, "long big = %d;\n", buf.st_size);
		else
			fprintf(out, "%s", input);
	}

	fclose(in);
	fclose(out);

	printf("loader binary: %d bytes\n", buf.st_size);
	rename("loader2.c", "loader.c");
	system("gcc -O2 -Wall -o kis loader.c; strip kis");
	lstat("kis.o", &buf);
	printf("module: %d bytes\n", buf.st_size);
	return 0;
}

