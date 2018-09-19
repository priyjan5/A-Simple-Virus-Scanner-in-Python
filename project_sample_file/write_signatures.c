#include <stdio.h>
#include <string.h>

int main() {
  int i;
  char* sig[] = {"Congratulations!\n", "try again\n", "RIT\n", "\x2c\x34\x30\x34\x34\x34\x38\x34\x3c\x34\x40\x34\x44\x34\x48\x34\n"};
  FILE*fp;

  if((fp=fopen("signatures","wb"))==NULL)
    {
      puts("Cannot oepn the file");
      return 1;
    }

  for(i = 0; i < 4; ++i)
    fwrite((const void *)sig[i], sizeof(char), strlen(sig[i]), fp);

  fclose(fp);
  return 0;
}
