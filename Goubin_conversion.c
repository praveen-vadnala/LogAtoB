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
    scheme proposed by Louis Goubin at CHES 2001. 
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



WORD32 Goubin_conversion_bool_arith(WORD32 x1, WORD32 R)
{

	WORD32 r, T, u, A;
	r  = xorshf96() ;

	u = r;
	T = x1 ^ u;
	T = T - u;
	T = T ^ x1;
	u = u ^ R;
	A = x1 ^ u;
	A = A - u;
	A = A ^ T;

	return A;

}

WORD32 Goubin_conversion_arith_bool(WORD32 A, WORD32 R)
{

	unsigned int k;
	WORD32 r, s, T, x1, u;


	r  = xorshf96() ;

	s = r;
	T = 2*s;
	x1 = s^R;
	u = s&x1;
	x1 = T^A;
	s = s^x1;
	s = s & R;
	u = u ^ s;
	s = T&A;
	u = u ^s;

	for (k=1; k <=31; k++)
	{
		s = T & R;
		s = s ^ u;
		T = T & A;
		s = s ^ T;
		T = 2 * s;
	}

	x1 = x1 ^ T;
	
	return x1;
	
}




int main(void)
{
   WORD32 x, y, z, R1, R2, z1, z2, A;
   WORD32 x1, y1, s, t, u;
   
    x = xorshf96();
    R1 = xorshf96();
    A = x - R1;

    /* Verify Arith to bool conversion*/
    x1 = Goubin_conversion_arith_bool (A, R1);
    
    if ((x1 ^ R1) != x)
        printf ("FAILURE A->B conversion: %x %x \n", x1 ^ R1, x);
    else
        printf("SUCCESS A->B conversion\n");	

    /* Verify Bool to Arith conversion*/
    A = Goubin_conversion_bool_arith (x1, R1);
    
    if ((A + R1) != x)
        printf ("FAILURE B->A conversion %x %x \n", x1 ^ R1, x);
    else
        printf("SUCCESS B->A conversion\n");	

	return 0;
}


