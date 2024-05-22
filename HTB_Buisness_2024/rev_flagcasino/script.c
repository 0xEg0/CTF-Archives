#include <stdio.h>
#include <stdlib.h>

void main(){
  int check[0x1d] = 
  {
      0x244b28be,
      0x0af77805,
      0x110dfc17,
      0x07afc3a1,
      0x6afec533,
      0x4ed659a2,
      0x33c5d4b0,
      0x286582b8,
      0x43383720,
      0x055a14fc,
      0x19195f9f,
      0x43383720,
      0x63149380,
      0x615ab299,
      0x6afec533,
      0x6c6fcfb8,
      0x43383720,
      0x0f3da237,
      0x6afec533,
      0x615ab299,
      0x286582b8,
      0x055a14fc,
      0x3ae44994,
      0x06d7dfe9,
      0x4ed659a2,
      0x0ccd4acd,
      0x57d8ed64,
      0x615ab299,
      0x22e9bc2a
  };

  for (int i = 0; i < 0x1d; i++){
    int j = 0;
    while (j < 0x7f){
      srand(j);
      int num = rand();
      if (num == check[i]){
        printf("%c", j);
        j = 0x80;
      }
      j += 1;
    }
  }
}
