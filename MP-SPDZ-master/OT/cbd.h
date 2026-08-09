#ifndef CBD_H
#define CBD_H

#include <stdint.h>
#include "poly.h"
#include "params.h"

#if (KYBER_ETA == 4)
#define cbd cbdeta4 
#else 
#define cbd cbdref
#endif

extern void cbd(poly *r, const unsigned char *buf) asm("cbdeta4");


//void cbd(poly *r, const unsigned char *buf);


#endif
