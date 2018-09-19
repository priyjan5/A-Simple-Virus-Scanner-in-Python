#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main (int argc, char **argv) {
  FILE * pFile;
  long lSize;
  char * buffer, *bbuffer;
  int i ;
  int count = 0;
  char *sig[1024]; // Assuming the maximum number of signatures is 1024

  if (argc != 3) {
        fprintf(stderr, "Usage: %s virus_file signature_file\n", *argv);
        exit(1);
    }

  pFile = fopen ( argv[2] , "rb" );
  if (pFile==NULL) exit (1);

  //get file size
  fseek (pFile , 0 , SEEK_END);
  lSize = ftell (pFile);
  rewind (pFile);

  //allocate memory
  buffer = (char*) malloc (lSize);
  if (buffer == NULL) exit (2);

  //read file into buffer
  fread (buffer,1,lSize,pFile);

  //parse signatures
  sig[0] = strtok(buffer, "\n");
  ++count;
  while (1) {
    sig[count] = strtok(NULL, "\n");
    if (sig[count] == NULL) {
      break;
    }
    ++count;
  }

  fclose (pFile);

  //read in a virus file
  pFile = fopen ( argv[1] , "rb" );
  if (pFile==NULL) exit (1);

  //get file size
  fseek (pFile , 0 , SEEK_END);
  lSize = ftell (pFile);
  rewind (pFile);

  //allocate memory
  bbuffer = (char*) malloc (lSize);
  if (bbuffer == NULL) exit (2);

  //read file into buffer
  fread (bbuffer,1,lSize,pFile);

  //match signatures -- a simple way
  int idx, sidx;
  for(i = 0; i < count; ++i) {
    for(idx = 0; idx < lSize; ++idx){
      int matched = 0;
      for(sidx = 0; sidx < strlen(sig[i]); ++sidx) {
	if(*(sig[i]+sidx) != bbuffer[idx]) {
	  break;
	}
	++matched;
	++idx;
	if(matched == strlen(sig[i])) {
	  printf("The file contains virus %d\n", i+1);
	  idx = lSize;
	}
      }
    }
  }
  fclose (pFile);
  free (buffer);
  free(bbuffer);
  return 0;
}
