#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include "round.h"
#include "sponge.h"
uint64_t SH[64];
int main(int argc, char *argv[]){
	//argv = "ABC";
  int32_t size=strlen(argv[1]);
  int32_t *psize=&size;
  uint8_t *newmessage;
  int32_t i;

  //for(i=0;i<64;i++){
  //	  SH[i] = (uint64_t)0x8000000000000000>>i;
  //}
  newmessage=sponge((uint8_t *)argv[1],*psize);
  for(i=0;i<64;i++){
    printf("%d %X\n",i,*(newmessage+i));
  }
  return 0;
}
