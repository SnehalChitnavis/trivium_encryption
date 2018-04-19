#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define BIT(hex, i) ((hex >> i) & 1)
#define NUM_BITS_PT (240)

int main()
{
  unsigned int key[80], iv[80], states[288], ct[60], Z_k[60], r_pt[60], rec_plain_text[NUM_BITS_PT], ciphertext[NUM_BITS_PT], z[NUM_BITS_PT], t1, t2, t3, temp, tempx;

  int i,j,k;
  unsigned char key_h[] = {0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a};
  unsigned char iv_h[] =  {0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca};
  unsigned char pt[] =    {0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59,
	  		   0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a, 0x86, 0xa7, 0xa9, 0x53,
			   0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31};

  printf("\nKey (80 bit):\t");
  for (i = 0; i < 10; i++)
    printf("%0x",key_h[i]);
  printf("\nIV (80 bit):\t");
  for (i = 0; i < 10; i++)
    printf("%0x",iv_h[i]);
    printf("\nPlaintext (240 bit):\t");
  for (i = 0; i < 30; i++)
    printf("%0x",pt[i]);

  // Convert to bit
  for (i=0; i<10; i++){
	  for(j=0; j<8; j++){
		  key[8*i + j] = BIT(key_h[i], (7-j));
		   iv[8*i + j] = BIT(iv_h[i],  (7-j));
	  }
  }
 /* for (i=0; i<30; i++)
	  for(j=0; j<8; j++)
		  plain_text[8*i + j] = BIT(pt[i], (7-j));
*/
  // Key and IV initialization

  for(i=0; i<93; i++){
	  if(i < 80)
		  states[i] = key[i];
	  else
		  states[i] = 0;
  }
  for(i=93; i<177; i++){
	  if((i-93) < 80)
		  states[i] = iv[i-93];
	  else
		  states[i] = 0;
  }
  for(i=177; i<288; i++){
	  if(i<285)
		  states[i] = 0;
	  else
		  states[i] = 1;
  }

  for(j=0; j<(4*288); j++){
	  // t1 <- s65 + (s90*s91) + s92 + s170
	  t1 = states[65] ^ (states[90] * states[91]) ^ states[92] ^ states[170];
	  // t2 <- s161 + (s174*s175) + s176 + s263
	  t2 = states[161] ^ (states[174] * states[175]) ^ states[176] ^ states[263];
	  // t3 <- s242 + (s285*s286) + s287 + s68
	  t3 = states[242] ^ (states[285] * states[286]) ^ states[287] ^ states[68];

	  for(i=0; i<93; i++){
		if(i == 0){
			temp = states[i];
			states[i] = t3;
		}
	  	else{
			tempx = states[i];
			states[i] = temp;
			temp = tempx;
		}
	  }
	  for(i=93; i<177; i++){
		if(i == 93){
			temp = states[i];
			states[i] = t1;
		}
	  	else{
			tempx = states[i];
			states[i] = temp;
			temp = tempx;
		}
	  }
	  for(i=177; i<288; i++){
		if(i == 177){
			temp = states[i];
			states[i] = t2;
		}
	  	else{
			tempx = states[i];
			states[i] = temp;
			temp = tempx;
		}
	  }

  }
  
  // KEY Generation
  for(j=0; j<NUM_BITS_PT; j++){
	  t1 = states[65] ^ states[92];
	  t2 = states[161] ^ states[176];
	  t3 = states[242] ^ states[287];

	  z[j] = t1 ^ t2 ^ t3;

	  t1 ^= (states[90]*states[91])^states[170];
	  t2 ^= (states[174]*states[175])^states[263];
	  t3 ^= (states[285]*states[286])^states[68];

	  for(i=0; i<93; i++){
		if(i == 0){
			temp = states[i];
			states[i] = t3;
		}
	  	else{
			tempx = states[i];
			states[i] = temp;
			temp = tempx;
		}
	  }
	  for(i=93; i<177; i++){
		if(i == 93){
			temp = states[i];
			states[i] = t1;
		}
	  	else{
			tempx = states[i];
			states[i] = temp;
			temp = tempx;
		}
	  }
	  for(i=177; i<288; i++){
		if(i == 177){
			temp = states[i];
			states[i] = t2;
		}
	  	else{
			tempx = states[i];
			states[i] = temp;
			temp = tempx;
		}
	  }

  }  
  printf("\nKey\n");

  for(j=0; j<NUM_BITS_PT/4; j++){	
		  Z_k[j] = z[4*j]*(8) + z[4*j+1]*(4) + z[4*j+2]*(2) + z[4*j+3]*(1);
		  printf("%0x",Z_k[j]);
  }

/*  for(i=0; i<NUM_BITS_PT; i++)
	  ciphertext[i] = plain_text[i] ^ z[i];
*/
  printf("\nCiphertext\n");

  for(j=0; j<NUM_BITS_PT/4; j++){	
		  ct[j] = ciphertext[4*j]*(8) + ciphertext[4*j+1]*(4) + ciphertext[4*j+2]*(2) + ciphertext[4*j+3]*(1);
		  printf("%0x",ct[j]);
  }

  for(i=0; i<NUM_BITS_PT; i++)
	  rec_plain_text[i] = ciphertext[i] ^ z[i];

  printf("\nReceived PT\n");
  for(j=0; j<NUM_BITS_PT/4; j++){	
		  r_pt[j] = rec_plain_text[4*j]*(8) + rec_plain_text[4*j+1]*(4) + rec_plain_text[4*j+2]*(2) + rec_plain_text[4*j+3]*(1);
		  printf("%0x",r_pt[j]);
  }

  return 0;
}


