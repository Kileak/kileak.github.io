#include <stdio.h>

int CRCTABLE[256];

void initCRCTable() {
  int currentCRC = 0, v3 = 0, counter = 0;

  while ( 1 )
  {
    counter = 8;
    currentCRC = v3 << 24;
    do
    {
      while ( currentCRC >= 0 )
      {
        currentCRC *= 2;
        if ( !--counter )
          goto LABEL_6;
      }
      currentCRC = 2 * currentCRC ^ 0x4C11DB7;
      --counter;
    }
    while ( counter );

LABEL_6:
    CRCTABLE[v3++] = currentCRC;

    if(v3==256)
	break;
  }
}

int calcCRC(char val) {
  int crcSize = 1;
  int v4 = 0, v6 = 0, v7 = 0, v8 = 0, v9 = 0, curWord = 0;

  if ( crcSize <= 0 )
  {
    v4 = -1;
  }
  else
  {
      v4 = -1;

      curWord = val;

      v6 = 7;
      v7 = 0;

      do
      {
        if ( curWord & 1 )  
          v7 |= 1 << v6;    

        --v6;

        curWord >>= 1;      
      }
      while ( v6 != -1 );

      v4 = CRCTABLE[(unsigned char)((char)(v4) ^ v7)] ^ (v4 << 8);
  }

  v8 = 31;
  v9 = 0;

  do
  {
    if ( v4 & 1 )
      v9 |= 1 << v8;
    --v8;
    v4 >>= 1;
  }
  while ( v8 != -1 );

  return ~v9;
}


int main() {
  initCRCTable();

  for (int i=0; i<256; i++) {
    printf("0x%x,", calcCRC((char)i));
  }
}
