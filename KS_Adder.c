/*
 *

 * KS_Adder.c
 *
 * Created: 10/28/2014 2:04:47 PM
 *  Author: Praveen Vadnala (praveen.vadnala@uni.lu)
  


    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/**
 * 
 * The following code implements the first-order secure conversion conversion 
    scheme proposed by Coron-Gorschadl-Tibochi-Vadnala at FSE 2015. The 
	implementations given are first-order A->B conversion as well as 
	addition using 	Kogge-Stone adder.
 * Author:      Praveen Vadnala
 * email:       praveen.vadnala@uni.lu
 * License:     GPLv3 or later
 **/


#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>

typedef uint8_t BYTE;
typedef uint16_t WORD16;
typedef uint32_t WORD32;
typedef uint64_t WORD64;


/* Parameters for random number generation */
static unsigned long x=123456789, y=362436069, z=521288629;
static uint64_t  w=88172645463325252LL;
static unsigned long y1=2463534242;
 
 uint64_t  xor64() __attribute__((always_inline));
 unsigned long xor32() __attribute__((always_inline));
 unsigned long xorshf96(void) __attribute__((always_inline));
							 
/* Generates 64-bit random number */
uint64_t  xor64()
{
	w ^= (w<<13); 
	w ^= (w>>7); 
	return (w ^= (w<<17));	
}	

/* Generates 32-bit random number */
unsigned long xor32() 
{

	y1 ^= (y1<<13); 
	y1=(y1>>17); 
	return (y1 ^= (y1<<5)); 
}

/* Random number generator based on LSFR (http://en.wikipedia.org/wiki/Xorshift)*/			 
unsigned long xorshf96(void)
 {
	unsigned long t;
	x ^= x << 16;
	x ^= x >> 5;
	x ^= x << 1;

	t = x;
	x = y;
	y = z;
	z = t ^ x ^ y;
	return z;
}



/*Secure AND implementation using constant randoms */
WORD32 SecAnd_Const (WORD32 x1, WORD32 y1, WORD32 s, WORD32 t, WORD32 u)
{
	WORD32 x2, z1;

    x2 = x1 & y1;    
	x2 = x2 ^ u;

	z1 = x2 ^ (x1 & t);
	z1 = z1 ^ (y1 & s);
	z1 = z1 ^ (s & t);

	return z1;
}

/*Secure shift implementation using constant randoms */
WORD32 SecShift_Const (WORD32 x1, WORD32 s, WORD32 t, WORD32 j)
{
	WORD32 z_1;
	z_1 = (x1 << j);
	z_1 = z_1 ^ t;
	z_1 = (z_1 ^ (s << j));	
	return z_1;
}

/*Secure XOR implementation using constant randoms */
WORD32 SecXor_Const (WORD32 x1, WORD32 y1, WORD32 s, WORD32 u)
{
	WORD32 z1;
	z1 = x1 ^ y1;
	z1 = z1 ^ u;
	return z1;
}

/*Arithmetic to Boolean conversion using Kogge-Stone adder and constant randoms*/
WORD32 Kogge_Stone_Arith_Bool_Const (WORD32 A, WORD32 r, WORD32 s, WORD32 t, 
									WORD32 u, WORD32 k)
{
	WORD32 P1, G1, H, G2, x1, x2;
	int i = 1;

	P1 = A ^ s;
	P1 = P1 ^ r;
	G1 = s ^ ((A^t)&r);
	G1 = G1 ^ (t&r);

	while (i < (k/2))
	{

        H = SecShift_Const (G1, s, t, i);
        G2 = SecAnd_Const (P1, H, s, t, u);
        G1 = SecXor_Const (G2, G1, s, u);
        H = SecShift_Const (P1, s, t, i);
        P1 = SecAnd_Const (P1, H, s, t, u);
        P1 = (P1^s)^u;
        
		i <<= 1;		
	}	

    H = SecShift_Const (G1, s, t, i);		
    G2 = SecAnd_Const (P1, H, s, t, u);
    G1 = SecXor_Const (G2, G1, s, u);
   	    
	x1 = ((2*G1) ^ A) ^ (2*s);
    
	return x1;

}



/*Masked addition using Kogge-Stone adder */
void Kogge_Stone_Masked_Add_Const (WORD32 x1, WORD32 s, WORD32 y1, WORD32 r, 
							WORD32 t, WORD32 u, BYTE k, WORD32* z1, WORD32* z2)
{
	WORD32 P1, G1, H, G2, p1, x2;
	int i = 1;


	P1 = SecXor_Const(x1,y1,s,r);
	G1 = SecAnd_Const (x1, y1, s, r, u);

	G1 = (G1^s)^u;
       
	while (i < k/2)
	{

        H = SecShift_Const (G1, s, t, i);
        G2 = SecAnd_Const (P1, H, s, t, u);
        G1 = SecXor_Const (G2, G1, s, u);
        H = SecShift_Const (P1, s, t, i);
        P1 = SecAnd_Const (P1, H, s, t, u);
        P1 = (P1^s)^u;
        
		i <<= 1;		
	}		

    H = SecShift_Const (G1, s, t, i);
    G2 = SecAnd_Const (P1, H, s, t, u);
    G1 = SecXor_Const (G2, G1, s, u);
    *z1 = SecXor_Const (y1, x1, r, s);


    *z1 = (*z1) ^ (2*G1);
    *z1 = (*z1) ^ (2*s);
    *z2 = r;
}

int main(void)
{
   WORD32 x, y, z, R1, R2, z1, z2, A;
   WORD32 x1, y1, s, t, u;
   WORD32 word_size;

   printf ("Enter the word size: choose between 8, 16 and 32: ");
   scanf ("%u", &word_size);
	
	if (word_size == 8)
	{
		x = xorshf96()&0xFF;
		y = xorshf96()&0xFF;
		R1 = xorshf96()&0xFF;
		R2 = xorshf96()&0xFF;
		s = xorshf96()&0xFF;
		t = xorshf96()&0xFF;
		u = xorshf96()&0xFF;
		x1 = x^R1;
		y1 = y^R2;

		A = x - R1;
		
		x1 = Kogge_Stone_Arith_Bool_Const (A, R1, s, t, 8, u);

		if ((x1 ^ R1) != x)
			printf ("FAILURE conversion: 8-bit %x %x \n", x1 ^ R1, x); 
		else
			printf("SUCCESS conversion\n");          
			
		Kogge_Stone_Masked_Add_Const (x1, R1, y1, R2, t, u,  8, &z1, &z2);

		if ((z1^z2)%256 != ((x+y)%256))
			printf ("FAILURE Addition: 8-bit %x %x \n", (z1^z2)%256,((x+y)%256));
		else
			printf("SUCCESS Addition\n"); 	
	}
	else if (word_size == 16)
	{
		x = xorshf96()&0xFFFF;
		y = xorshf96()&0xFFFF;
		R1 = xorshf96()&0xFFFF;
		R2 = xorshf96()&0xFFFF;
		s = xorshf96()&0xFFFF;
		t = xorshf96()&0xFFFF;
		u = xorshf96()&0xFFFF;
		x1 = x^R1;
		y1 = y^R2;

		A = x - R1;
		x1 = Kogge_Stone_Arith_Bool_Const (A, R1, s, t, 16, u);
		
		if ((x1 ^ R1) != x)
			printf ("FAILURE conversion: 16-bit %x %x \n", x1 ^ R1, x);
		else
			printf("SUCCESS conversion\n"); 	
		
		Kogge_Stone_Masked_Add_Const (x1, R1, y1, R2, t, u, 16, &z1, &z2);
			
		if ((z1^z2)%65536 != ((x+y)%65536))
			printf ("FAILURE Addition: 16-bit %x %x \n", (z1^z2)%65536,((x+y)%65536));
		else
			printf("SUCCESS Addition\n"); 		

	}
   
	else if (word_size == 32)
	{

		x = xorshf96();
		y = xorshf96();
		R1 = xorshf96();
		R2 = xorshf96();
		s = xorshf96();
		t = xorshf96();
		u = xorshf96();
		x1 = x^R1;
		y1 = y^R2;
		A = x - R1;

		x1 = Kogge_Stone_Arith_Bool_Const (A, R1, s, t, u, 32);
		
		if ((x1 ^ R1) != x)
			printf ("conversion: 32-bit %x %x \n", x1 ^ R1, x);
		else
			printf("SUCCESS conversion\n");	

		Kogge_Stone_Masked_Add_Const (x1, R1, y1, R2, t, u, 32, &z1, &z2);
		
		
		if ((z1^z2) != ((x+y)))
			printf ("FAILURE Addition: 32-bit %x %x \n", (z1^z2),(x+y));

		else
			printf("SUCCESS Addition\n");

	}

	else
	{
		printf ("wrong word size, please enter: 8, 16 or 32\n");
	}
	
	return 0;
}


