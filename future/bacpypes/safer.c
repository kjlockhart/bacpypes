/* safer.c
 *
 * DESCRIPTION:    block-cipher algorithm SAFER (Secure And Fast Encryption
 *                 Routine) in its four versions: SAFER K-64, SAFER K-128,
 *                 SAFER SK-64 and SAFER SK-128.
 *
 * AUTHOR:         Richard De Moliner (demoliner@isi.ee.ethz.ch)
 *                 Signal and Information Processing Laboratory
 *                 Swiss Federal Institute of Technology
 *                 CH-8092 Zuerich, Switzerland
 *
 * DATE:           September 9, 1995
 *
 * REMARKS: - Any changes made to this file must also be made to _inSafer.c
 *            and vice versa where relevant.
 *          - _inSafer.c is a version of this file that is used for the InstallShield-
 *            based installers' resource DLLs.  That file is necessary, because the
 *            Historian installer needs to have access to the encryption routine, but
 *            pulling delta.dll into the installer to get that access is highly
 *            problematic.  The differences between that file and this one are that
 *            the dependencies on verious Delta definitions, such as the sy* macros,
 *            have been removed so as to allow the encryption routine to be used
 *            outside of the ORCA software context.
 *          - _inSafer.c is located in the owssuite/install/resource DLLs/
 *            _Ins50ows repository.
 *
 * $Header: safer.c: Revision: 1: Author: tharms: Date: Wednesday, September 30, 2009 2:48:26 PM$
 * $Log$
 * tharms - Wednesday, September 30, 2009 2:48:26 PM
 * Added DeltaProprietary Foreign Device registration to Quattro.  Quattro will now send both a BACnet ForeignDevice registration and a Delta Foreign Device registration when trying toconnect to a BBMD.  The user name andpassword can be specified for each BBMD port using the setup system parameters CFG_BNIP_BBMD_SECURITY_USERand CFG_BNIP_BBMD_SECURITY_PWD.
 * Rholstein - Tuesday, March 11, 2008 4:16:34 PM
 * Updated the header comment to point out the existance of an installer-specific version of this file (needed to fix bug #45869)
 * Cjakeway - Tuesday, July 11, 2006 10:07:39 AM
 * Fixed up Log wildcard in file header for use with Surround SCM.
 * 
 * 11    8/06/04 4:18p Apang
 * 
 * 7     10/02/03 10:08a Alehmann
 * Add checks for IMG_DSX
*/


/******************* External Headers *****************************************/
//#include <sy/base.h>   // Delta Controls Inc. Include
//#include <sy/systring.h>
#include <stdio.h>
#include <string.h>

typedef char*   PSTR;
typedef unsigned char*   PBYTE;
typedef unsigned char    BYTE;
typedef long    DWORD;
typedef int     INT;


/******************* Local Headers ********************************************/
#include "safer.h"

/******************* Constants ************************************************/
#define TAB_LEN      256

/******************* Assertions ***********************************************/

/******************* Macros ***************************************************/
#define ROL(x, n)    ((unsigned char)((unsigned int)(x) << (n)\
                                     |(unsigned int)((x) & 0xFF) >> (8 - (n))))
#define EXP(x)       exp_tab[(x) & 0xFF]
#define LOG(x)       log_tab[(x) & 0xFF]
#define PHT(x, y)    { y += x; x += y; }
#define IPHT(x, y)   { x -= y; y -= x; }

/******************* Types ****************************************************/
static unsigned char exp_tab[TAB_LEN];
static unsigned char log_tab[TAB_LEN];

/******************* Module Data **********************************************/

/******************* Functions ************************************************/
#define syMemSet(dst,ch,len)		memset(dst,(int)ch,len)
#define syMemMove(dst,src,len)  memmove(dst,src,len)
#define syStrLength(s)          strlen(s)

#define syMin(_a, _b)  (((_a) < (_b)) ? (_a) : (_b))
#define syMax(_a, _b)  (((_a) > (_b)) ? (_a) : (_b))
#define TRUE  1
#define FALSE 0

static safer_key_t  gisSaferKey;               // Private Safer Key built in isInit



/******************************************************************************/
// Do not generate the tables for SC platform, as they are explicitly defined
// as constants.
void Safer_Init_Module(void)
  {
    unsigned int exp, i;

    // Clear the tables so no unintialized memory
    syMemSet(&exp_tab[0], 0, TAB_LEN);
    syMemSet(&log_tab[0], 0, TAB_LEN);

    exp = 1;
    for (i = 0; i < TAB_LEN; i++)
      {
        exp_tab[i] = (unsigned char)(exp & 0xFF);
        log_tab[exp_tab[i]] = (unsigned char)i;
        exp = exp * 45 % 257;
      }

    printf("\nexp_tab\n");
    for (i=0; i < TAB_LEN; i++)
        printf("%i, ",exp_tab[i]);

    printf("\nlog_tab\n");
    for (i=0; i < TAB_LEN; i++)
        printf("%i, ",log_tab[i]);

    printf("\n");
  } /* Safer_Init_Module */


/******************************************************************************/
void Safer_Expand_Userkey(safer_block_t userkey_1,
                          safer_block_t userkey_2,
                          unsigned int  nof_rounds,
                          int           strengthened,
                          safer_key_t   key)
  {
    unsigned int i, j;
    unsigned char ka[SAFER_BLOCK_LEN + 1];
    unsigned char kb[SAFER_BLOCK_LEN + 1];
    INT k;
    unsigned char * keyBuf= (unsigned char *)key;
    
    printf("\nExpand_userkey\n");
    printf("\nkey sch(before)=\n");
    for (i=0; i< SAFER_KEY_LEN; i++)
      printf("%u, ",gisSaferKey[i]);
      if (i%16==0) printf("\n");
    printf("\n");

    printf("\nUserKey1=");
    for (i=0; i< 8; i++)
      printf("%i, ",userkey_1[i]);
      
    printf("\nUserKey2=");
    for (i=0; i< 8; i++)
      printf("%i, ",userkey_2[i]);


    syMemSet(&ka[0], 0, (SAFER_BLOCK_LEN + 1));
    syMemSet(&kb[0], 0, (SAFER_BLOCK_LEN + 1));

    if (SAFER_MAX_NOF_ROUNDS < nof_rounds)
      nof_rounds = SAFER_MAX_NOF_ROUNDS;

    *key++ = (unsigned char)nof_rounds;
    ka[SAFER_BLOCK_LEN] = 0;
    kb[SAFER_BLOCK_LEN] = 0;

    for (j = 0; j < SAFER_BLOCK_LEN; j++)
      {
        ka[SAFER_BLOCK_LEN] ^= ka[j] = ROL(userkey_1[j], 5);
        kb[SAFER_BLOCK_LEN] ^= kb[j] = *key++ = userkey_2[j];
      }

    printf("\n[0]key=");
    for (k=0; k< 16; k++)
      printf("%d, ",keyBuf[k]);

    printf("\nStep1: roll key=");
    printf("\nka=");
    for (k=0; k< 8; k++)
      printf("%d, ",ka[k]);
    printf("\nkb=");
    for (k=0; k< 8; k++)
      printf("%d, ",kb[k]);

    
    for (i = 1; i <= nof_rounds; i++)
      {
        for (j = 0; j < SAFER_BLOCK_LEN + 1; j++)
          {
            ka[j] = ROL(ka[j], 6);
            kb[j] = ROL(kb[j], 6);
          }

        for (j = 0; j < SAFER_BLOCK_LEN; j++)
          if (strengthened)
            *key++ = (ka[(j + 2 * i - 1) % (SAFER_BLOCK_LEN + 1)]
                            + exp_tab[exp_tab[18 * i + j + 1]]) & 0xFF;
          else
            *key++ = (ka[j] + exp_tab[exp_tab[18 * i + j + 1]]) & 0xFF;

        for (j = 0; j < SAFER_BLOCK_LEN; j++)
          if (strengthened)
            *key++ = (kb[(j + 2 * i) % (SAFER_BLOCK_LEN + 1)]
                            + exp_tab[exp_tab[18 * i + j + 10]]) & 0xFF;
          else
            *key++ = (kb[j] + exp_tab[exp_tab[18 * i + j + 10]]) & 0xFF;
      }

    for (j = 0; j < SAFER_BLOCK_LEN + 1; j++)
        ka[j] = kb[j] = 0;

    printf("\nkey sch(after)=\n");
    for (i=0; i< SAFER_KEY_LEN; i++)
      printf("%3u, ",gisSaferKey[i]);
      if (i%16==0) printf("\n");
    printf("\n");

  } /* Safer_Expand_Userkey */


#if (HW!=HW_SC) || (HW==HW_SC && ((IMGTYPE == IMG_DSC) || (IMGTYPE == IMG_DSX))) 
/******************************************************************************/
void Safer_Encrypt_Block(safer_block_t block_in,
                         safer_key_t key, 
                         safer_block_t block_out)
  {
    unsigned char a, b, c, d, e, f, g, h, t;
    unsigned int round;
    INT   i;

    printf("\nEncrypt in=");
    printf("\n%u,%u,%u,%u, %u,%u,%u,%u",a,b,c,d,e,f,g,h);
    for(i=0; i<8; i++)
      printf("%u, ",block_in[i]);
      
    a = block_in[0]; b = block_in[1]; c = block_in[2]; d = block_in[3];
    e = block_in[4]; f = block_in[5]; g = block_in[6]; h = block_in[7];
    if (SAFER_MAX_NOF_ROUNDS < (round = *key))
      round = SAFER_MAX_NOF_ROUNDS;
    
    while(round--)
      {
        printf("\nRound %d\n",round);
        printf("\nA-%u,%u,%u,%u, %u,%u,%u,%u",a,b,c,d,e,f,g,h);
        a ^= *++key; b += *++key; c += *++key; d ^= *++key;
        e ^= *++key; f += *++key; g += *++key; h ^= *++key;
        printf("\nB-%u,%u,%u,%u, %u,%u,%u,%u",a,b,c,d,e,f,g,h);
        a = EXP(a) + *++key; b = LOG(b) ^ *++key;
        c = LOG(c) ^ *++key; d = EXP(d) + *++key;
        e = EXP(e) + *++key; f = LOG(f) ^ *++key;
        g = LOG(g) ^ *++key; h = EXP(h) + *++key;
        printf("\nC-%u,%u,%u,%u, %u,%u,%u,%u",a,b,c,d,e,f,g,h);
        PHT(a, b); PHT(c, d); PHT(e, f); PHT(g, h);
        printf("\nP1-%u,%u,%u,%u, %u,%u,%u,%u",a,b,c,d,e,f,g,h);
        PHT(a, c); PHT(e, g); PHT(b, d); PHT(f, h);
        printf("\nP2-%u,%u,%u,%u, %u,%u,%u,%u",a,b,c,d,e,f,g,h);
        PHT(a, e); PHT(b, f); PHT(c, g); PHT(d, h);
        printf("\nP3-%u,%u,%u,%u, %u,%u,%u,%u",a,b,c,d,e,f,g,h);
        t = b; b = e; e = c; c = t; t = d; d = f; f = g; g = t;
        printf("\nE-%u,%u,%u,%u, %u,%u,%u,%u",a,b,c,d,e,f,g,h);
      }

    a ^= *++key; b += *++key; c += *++key; d ^= *++key;
    e ^= *++key; f += *++key; g += *++key; h ^= *++key;
    printf("\n*-%u,%u,%u,%u, %u,%u,%u,%u",a,b,c,d,e,f,g,h);
    block_out[0] = a & 0xFF; block_out[1] = b & 0xFF;
    block_out[2] = c & 0xFF; block_out[3] = d & 0xFF;
    block_out[4] = e & 0xFF; block_out[5] = f & 0xFF;
    block_out[6] = g & 0xFF; block_out[7] = h & 0xFF;

    printf("\nEncrypt out=");
    for(i=0; i<8; i++)
      printf("%u, ",block_out[i]);
      
    printf("\n");
  } /* Safer_Encrypt_Block */
#endif


/******************************************************************************/
void Safer_Decrypt_Block(safer_block_t  block_in,
                         safer_key_t    key, 
                         safer_block_t  block_out)
  {
    unsigned char a, b, c, d, e, f, g, h, t;
    unsigned int round;
    INT   i;

    printf("\nDecrypt in=");
    for(i=0; i<8; i++)
      printf("%x, ",block_in[i]);
      
    a = block_in[0]; b = block_in[1]; c = block_in[2]; d = block_in[3];
    e = block_in[4]; f = block_in[5]; g = block_in[6]; h = block_in[7];
    if (SAFER_MAX_NOF_ROUNDS < (round = *key)) round = SAFER_MAX_NOF_ROUNDS;
    key += SAFER_BLOCK_LEN * (1 + 2 * round);
    h ^= *key; g -= *--key; f -= *--key; e ^= *--key;
    d ^= *--key; c -= *--key; b -= *--key; a ^= *--key;
    while (round--)
    {
        //printf("\nRound %d\n",round);
        //printf("\nE-%u,%u,%u,%u, %u,%u,%u,%u",a,b,c,d,e,f,g,h);
        t = e; e = b; b = c; c = t; t = f; f = d; d = g; g = t;
        //printf("\nP3-%u,%u,%u,%u, %u,%u,%u,%u",a,b,c,d,e,f,g,h);
        IPHT(a, e); IPHT(b, f); IPHT(c, g); IPHT(d, h);
        //printf("\nP2-%u,%u,%u,%u, %u,%u,%u,%u",a,b,c,d,e,f,g,h);
        IPHT(a, c); IPHT(e, g); IPHT(b, d); IPHT(f, h);
        //printf("\nP1-%u,%u,%u,%u, %u,%u,%u,%u",a,b,c,d,e,f,g,h);
        IPHT(a, b); IPHT(c, d); IPHT(e, f); IPHT(g, h);
        //printf("\nC-%u,%u,%u,%u, %u,%u,%u,%u",a,b,c,d,e,f,g,h);
        h -= *--key; g ^= *--key; f ^= *--key; e -= *--key;
        d -= *--key; c ^= *--key; b ^= *--key; a -= *--key;
        //printf("\nB-%u,%u,%u,%u, %u,%u,%u,%u",a,b,c,d,e,f,g,h);
        h = LOG(h) ^ *--key; g = EXP(g) - *--key;
        f = EXP(f) - *--key; e = LOG(e) ^ *--key;
        d = LOG(d) ^ *--key; c = EXP(c) - *--key;
        b = EXP(b) - *--key; a = LOG(a) ^ *--key;
        //printf("\nA-%u,%u,%u,%u, %u,%u,%u,%u",a,b,c,d,e,f,g,h);
    }
    block_out[0] = a & 0xFF; block_out[1] = b & 0xFF;
    block_out[2] = c & 0xFF; block_out[3] = d & 0xFF;
    block_out[4] = e & 0xFF; block_out[5] = f & 0xFF;
    block_out[6] = g & 0xFF; block_out[7] = h & 0xFF;

    printf("\nDecrypt out=");
    for(i=0; i<8; i++)
      printf("%x, ",block_out[i]);
      
    printf("\n");
} /* Safer_Decrypt_Block */

/******************************************************************************/
// From: 	// quattro/src/osal/sy/syencrypt.c

void _syResetFilter(
    PSTR szPrivateKey)     // IN - PrivateKey String to build IS global key
  {  
    #define MAX_SHORT_KEY_STRING_LEN  8  // maximal length for a 64-bit key
    #define MAX_LONG_KEY_STRING_LEN   16 // maximal length for a 128-bit key
    #define NOF_CHARS                 ('~' - ' ' + 1) // # of printable chars
    #define END_OF_LINE               (NOF_CHARS + 0) // end of line character
    #define IS_SAFER128_NO_OF_ROUNDS  11 // Number of Rounds to build key


    BYTE  UserKey1[MAX_SHORT_KEY_STRING_LEN] = {0}; // ALWAYS init to zeros
    BYTE  UserKey2[MAX_SHORT_KEY_STRING_LEN] = {0}; // ALWAYS init to zeros
    BYTE  InKey[MAX_LONG_KEY_STRING_LEN] = {0};     // ALWAYS init to zeros
    DWORD  nVal;
    INT   nCount;
    INT   nIndex;
    INT   i;

  	printf("NOF_CHARS=%i\n",NOF_CHARS);
  	printf("END_OF_LINE=%i\n",END_OF_LINE);

    // Copy Private key into User Keys they will NOT be NULL terminated
    syMemMove(UserKey1, szPrivateKey, syMin(syStrLength(szPrivateKey), MAX_SHORT_KEY_STRING_LEN));
    syMemMove(UserKey2, (PSTR)(szPrivateKey + MAX_SHORT_KEY_STRING_LEN),
               sizeof (UserKey2));
    syMemMove(InKey, szPrivateKey, syMin(syStrLength(szPrivateKey), sizeof(InKey)));

    printf("\nUserKey1=");
    for (i=0; i< 8; i++)
      printf("%u, ",UserKey1[i]);
      
    printf("\nUserKey2=");
    for (i=0; i< 8; i++)
      printf("%u, ",UserKey2[i]);
      
    printf("\nKey before= ");
    for(i=0; i<16; i++)
      printf("%u, ",InKey[i]);
      
    // Mess up key for security before Expanding key
    for (nCount = 0; nCount < MAX_LONG_KEY_STRING_LEN; nCount++)
      {
        if (' ' <= InKey[nCount] && InKey[nCount] <= '~')
          nVal = (DWORD)(InKey[nCount] - ' ');
        else
          nVal = (DWORD)END_OF_LINE;
        
        for (nIndex = 0; nIndex < SAFER_BLOCK_LEN; nIndex++)
          {
            nVal += (DWORD)UserKey1[nIndex] * NOF_CHARS;
            UserKey1[nIndex] = (BYTE)(nVal & 0xFF);
            nVal >>= 8;
          }

        for (nIndex = 0; nIndex < SAFER_BLOCK_LEN; nIndex++)
          {
            nVal += (DWORD)UserKey2[nIndex] * NOF_CHARS;
            UserKey2[nIndex] = (BYTE)(nVal & 0xFF);
            nVal >>= 8;
          }
      }

    printf("\nUserKey1 (messed)=");
    for (i=0; i< 8; i++)
      printf("%u, ",UserKey1[i]);
      
    printf("\nUserKey2 (messed)=");
    for (i=0; i< 8; i++)
      printf("%u, ",UserKey2[i]);
      
      
    // Build the SAFER 128-bit Private KEY
    Safer_Expand_Userkey(UserKey1, UserKey2,
                         IS_SAFER128_NO_OF_ROUNDS, TRUE, gisSaferKey);
  }

/******************************************************************************/

#define SY_SAFER128_PUBLIC_KEY    "DeltaControlsInc."

int main(void)
{
  safer_block_t inpBuf,outBuf,tmpBuf;
  int i;
  
	printf("Safer SK-128 Encryption\n");
	Safer_Init_Module();
	
	_syResetFilter("DeltaControlsInc.");
	// encrypt data - 8 bytes at a time

/*
  strcpy(inpBuf,"12345678");
  printf("\ninpBuf=%s",inpBuf);
  
  Safer_Encrypt_Block(inpBuf, gisSaferKey, outBuf);
  printf("\noutBuf=%s",outBuf);
  Safer_Decrypt_Block(outBuf, gisSaferKey, tmpBuf);
  
  printf("\ntmpBuf=%s",tmpBuf);
  if (strcmp(inpBuf,tmpBuf)==0)
    printf("\nsuccess");
  else
    printf("\nfailure");
*/
    
  // pkt[26]="\x86\xf0\xcc\x03\x28\x22\xb8\x59\xcf\xd8\xe6\x35\x18\x27\xb7\xfb\xf2\x7c\xcf\x5c\x3f\xd0\x4d\x33";
  strncpy(inpBuf,"\x86\xf0\xcc\x03\x28\x22\xb8\x59",8);
  Safer_Decrypt_Block(inpBuf, gisSaferKey, tmpBuf);

  strncpy(inpBuf,"\xcf\xd8\xe6\x35\x18\x27\xb7\xfb",8);
  Safer_Decrypt_Block(inpBuf, gisSaferKey, tmpBuf);

  strncpy(inpBuf,"\xf2\x7c\xcf\x5c\x3f\xd0\x4d\x33",8);
  Safer_Decrypt_Block(inpBuf, gisSaferKey, tmpBuf);

  printf("\nDone\n");
}

