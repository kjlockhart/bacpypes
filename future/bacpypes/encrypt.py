''' encrypt.py - Safer-K128 Encryption
     
Copyright (C) 2017 CopperTree Analytics Inc.

usage:

Note:
'''
#--- standard Python modules ---

#--- 3rd party modules ---

#--- this application's modules ---


'''
/******************************************************************************
 * SYENCRYPT.C - Basic Encryption and Decryption Routines
 * Copyright (C) Delta Controls Inc. 1994 - 2008
 *
 * $Header: syencrypt.c: Revision: 1: Author: Cjakeway: Date: Tuesday, July 23, 2013 4:41:19 PM$
 * $Log$
 * Cjakeway - Tuesday, July 23, 2013 4:41:19 PM
 * Fixed up safer encryption for foreign connections with SUA checking.  QS-3075
 * Cjakeway - Tuesday, July 23, 2013 4:36:07 PM
 * Fixed up length sizes for 64-bit Linux.  QS-3075
 * dyu - Thursday, March 21, 2013 2:28:46 PM
 * QS-2777 - The decryption of the old password was not clearing the buffer correctly, leaving garbage data behind.
 * dyu - Wednesday, August 29, 2012 9:52:28 AM
 * QS-2260 - 64bit preps. Updated the Quattro code for the setup types:
 * dyu - Tuesday, August 21, 2012 3:10:34 PM
 * QS-2260 - 64 bit prep.
 * dyu - Wednesday, March 30, 2011 4:19:40 PM
 * QS-1322 : Initial check in for the LDAP support in Quattro.
 * tharms - Wednesday, October 07, 2009 3:48:28 PM
 * Add software licensing (temporary) to Quattro
 * tharms - Wednesday, September 30, 2009 2:48:05 PM
 * Added DeltaProprietary Foreign Device registration to Quattro.  Quattro will now send both a BACnet ForeignDevice registration and a Delta Foreign Device registration when trying toconnect to a BBMD.  The user name andpassword can be specified for each BBMD port using the setup system parameters CFG_BNIP_BBMD_SECURITY_USERand CFG_BNIP_BBMD_SECURITY_PWD.
 */
'''

#include <sy/base.h>
#include <sy/systring.h>
#include <thirdparty/safer/safer.h>

// Max size that can be used for unencrypted data in remove or apply of filters
#define SY_MAX_FILTER_BLOCK_SIZE (0xffff - SAFER_BLOCK_LEN) 
#define SY_USERPASS_STRING_SIZE        128 // size of user and password strings


// *********** GLOBAL VARIABLES **********************************************
static safer_key_t  gisSaferKey;               // Private Safer Key built in isInit
BOOL                gbSyResetFilter = FALSE; // Prevents syResetFilter running 2x
 

// *********** INTERNAL FUNCTION PROTOTYPES **********************************
STATUS _syResetFilter(PSTR sPrivateKey);        // IN - PrivateKey String to build SY global key


/* syInitFilter 
 *   Sets up the safer module and creates the global key()
 *
 *
 * *** THIS FUNCTION IS AMBIGIOUSLY NAMED TO MASK ITS TRUE FUNCTION
 *
 *
 * Returns:
 *   OK - If key built sucessfully
 */
STATUS syInitFilter(VOID)
  {
    // Key Must be 8<KeyLength<=16 not including NULL termination
    // Change this key and we haveno way of unencrypting old data
    #define SY_SAFER128_PUBLIC_KEY    "DeltaControlsInc."

    CHAR    sPrivateKey[SY_USERPASS_STRING_SIZE] = SY_SAFER128_PUBLIC_KEY;
    STATUS  Result;

    // Initialize the SAFER.C module
    Safer_Init_Module();
    Result = _syResetFilter(sPrivateKey);

    // For security reasons clear private key buf
    syMemSet(sPrivateKey, 0, sizeof (sPrivateKey));

    return Result;

    #undef IS_SAFER128_PUBLIC_KEY
  }


''' encrypt - Encrypts the data to Cipher Text using SAFER-K128 using our private 128 bit key.

 * Returns:
 *  OK - If Data was encrypted successfully
 *  QERR_PARAMETER - If any arguments are invalid
 *  QERR_BUFFER_TOO_SMALL - If Data Out Buffer is too small - lpnDataOutSize
 *                             now contains the needed size
 *  QERR_INTERNAL - Can only handle SY_MAX_FILTER_BLOCK_SIZE
 */
'''
class Safer_K128:
    key= None
    
    def encrypt(DataIn):
    
,         // IN - Buffer containing data to encrypt
    WORD   nDataInSize,     // IN - Actual size of data to encrypt
    PVOID  pDataOut,        // IN/OUT - Buffer to put encrypted data
    PWORD  pnDataOutSize)   // IN/OUT - Size of encrypt data buffer but on
                            //          exit the size of encrypted data
  {  
    WORD    nTotalBlocks;
    WORD    nBlockPartialSize;
    WORD    nBlockCount;
    WORD    nSizeRequiredBuf;
    PBYTE   pCurrInBlock;
    PBYTE   pCurrOutBlock;
    BOOL    bNeedExtraBlock = FALSE;
    WORD    RemainingOctets;
    safer_block_t LastBlock;
    safer_block_t EncryptBlock;

    if len(DataIn) > 65536:
        raise QERR_INTERNAL;

    // Estimate the # of blocks to encrypt
    nTotalBlocks = nDataInSize / SAFER_BLOCK_LEN;
    if ((nBlockPartialSize = nDataInSize % SAFER_BLOCK_LEN) > 0)
      nTotalBlocks++;

    // Do we need extra block to encode size
    bNeedExtraBlock = (nBlockPartialSize == 0) ||
                      (nBlockPartialSize > 0 &&
                       (SAFER_BLOCK_LEN - nBlockPartialSize) < sizeof (DWORD));

    // Prepare the last block
    syMemSet(LastBlock, 0, sizeof (safer_block_t));

    // If extra block needed then add one to total count
    if (bNeedExtraBlock)
      nTotalBlocks++;
    else  // No extra block so we need to keep the partial data
      syMemMove(LastBlock,
                (PBYTE)((PBYTE)pDataIn + (nTotalBlocks - 1) * SAFER_BLOCK_LEN),
                nBlockPartialSize);

    // If the DataOut Buffer is too small then return error and needed size
    if (*pnDataOutSize < (nSizeRequiredBuf = nTotalBlocks * SAFER_BLOCK_LEN))
      {
        *pnDataOutSize = nSizeRequiredBuf;
        return QERR_BUFFER_TOO_SMALL;
      }

    // encode size
    *(PDWORD)&(LastBlock[SAFER_BLOCK_LEN - sizeof (DWORD)]) = (DWORD)nDataInSize;

    // Setup the pointers and counters for encrypt function
    pCurrInBlock = pDataIn;
    pCurrOutBlock = pDataOut;
    RemainingOctets = nDataInSize;

    // Loop through each block encrypting
    for (nBlockCount = 1; nBlockCount < nTotalBlocks; nBlockCount++)
      {
        // If there are enough remaining octets to fill the encrypt block then
        // copy a block of octets into the encrypt block.  If there aren't enough
        // octets left, then zero out the encrypt block and then copy the 
        // remaining octets in.
        if (RemainingOctets >= SAFER_BLOCK_LEN)
          {
            // copy the next block of data into the encrypt block
            syMemMove(EncryptBlock, pCurrInBlock, SAFER_BLOCK_LEN);
            RemainingOctets -= SAFER_BLOCK_LEN;
          }
        else
          {
            // Zero the Encrypt block because it will only be partially filled
            // and then copy the remaining octets into the encrypt block.
            syMemSet(EncryptBlock, 0, sizeof(safer_block_t));
            syMemMove(EncryptBlock, pCurrInBlock, RemainingOctets);
            RemainingOctets = 0;
          }

        Safer_Encrypt_Block(EncryptBlock,
                            gisSaferKey,
                            pCurrOutBlock);
        pCurrInBlock += (DWORD)SAFER_BLOCK_LEN;
        pCurrOutBlock += (DWORD)SAFER_BLOCK_LEN;
      }

    // Encrypt the last block
    Safer_Encrypt_Block(LastBlock, gisSaferKey, pCurrOutBlock);

    // Setup return arguments and return with status
    *pnDataOutSize = nSizeRequiredBuf;

    return OK;
  }



/* syClearFilter 
 *   Decrypts the data from Cipher Text using SAFER-K128 
 *   using our private 128 bit key.
 *
 * *** THIS FUNCTION IS AMBIGIOUSLY NAMED TO MASK ITS TRUE FUNCTION
 *
 *
 * Returns:
 *  OK - If Data was encrypted successfully
 *  QERR_PARAMETER - If any arguments are invalid
 *  QERR_BUFFER_TOO_SMALL - If Data Out Buffer is too small - lpnDataOutSize
 *                             now contains the needed size
 *  QERR_INTERNAL - Can only handle SY_MAX_FILTER_BLOCK_SIZE
 */
STATUS syClearFilter(
    PVOID  pDataIn,         // IN - Buffer containing encrypted data
    WORD   nDataInSize,     // IN - Actual size of encrypted data
    PVOID  pDataOut,        // IN/OUT - Buffer to put the decrypted data
    PWORD  pnDataOutSize)   // IN/OUT  - Size of decrypted data buffer but
                            //           on exit size of decrypted data
  {  
    WORD    nTotalBlocks;
    WORD    nBlockCount;
    WORD    nSizeRequiredBuf;
    PBYTE   pCurrInBlock;
    PBYTE   pCurrOutBlock;

    safer_block_t LastBlock;

    // Has Filter been reset (key created) if not do it
    if (gbSyResetFilter == FALSE)
      syInitFilter();

    // Validate the arguments
    if (!pDataIn || nDataInSize <= 0 ||
        !pDataOut ||!pnDataOutSize)
      return QERR_PARAMETER;

    if ((nDataInSize % SAFER_BLOCK_LEN) > 0)
      return QERR_INTERNAL;

    // Estimate the # of blocks to encrypt
    nTotalBlocks = nDataInSize / SAFER_BLOCK_LEN;

    // Dig out size from last block so we can determine if buffer is too small
    Safer_Decrypt_Block((PBYTE)((PBYTE)pDataIn + 
                        (nTotalBlocks - 1) * SAFER_BLOCK_LEN),
                        gisSaferKey,
                        LastBlock);
    nSizeRequiredBuf = (WORD)(*(PSIZE_T)&(LastBlock[SAFER_BLOCK_LEN - sizeof (DWORD)]));

    // If the DataOut Buffer is too small then return error and needed size
    if (*pnDataOutSize < (nTotalBlocks * SAFER_BLOCK_LEN))
      {
        *pnDataOutSize = nTotalBlocks * SAFER_BLOCK_LEN;
        return QERR_BUFFER_TOO_SMALL;
      }

    // Setup the pointers and counters for encrypt function
    pCurrInBlock = pDataIn;
    pCurrOutBlock = pDataOut;

    // Loop through each block decrypting
    for (nBlockCount = 1; nBlockCount <= nTotalBlocks; nBlockCount++)
      {
        Safer_Decrypt_Block(pCurrInBlock,
                            gisSaferKey,
                            pCurrOutBlock);
        pCurrInBlock += (DWORD)SAFER_BLOCK_LEN;
        pCurrOutBlock += (DWORD)SAFER_BLOCK_LEN;
      }

    // Clear remaining Data out buffer
    syMemSet((PBYTE)pDataOut + nSizeRequiredBuf,
             0,
             *pnDataOutSize - nSizeRequiredBuf);

    // Setup return arguments and return with status
    *pnDataOutSize = nSizeRequiredBuf;

    return OK;
  }


//**************** INTERNAL FUNCTIONS ******************************************


/*-----------------------------------------------------------------------------
_isV3ResetFilter -> Builds our Private key used for encryption and decryption
    using SAFER-K128. Note that we use a 128 bit key so the private key is
    always converted to a 128 bit key no matter the length.


  *** THIS FUNCTION IS AMBIGIOUSLY NAMED TO MASK ITS TRUE FUNCTION WHEN EXPORTING


 Returns:
   OK - If key built sucessfully
-----------------------------------------------------------------------------*/
STATUS _syResetFilter(
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

    // if we have already reset filter then just exit
    if (gbSyResetFilter == TRUE)
      return OK;

    // Copy Private key into User Keys they will NOT be NULL terminated
    syMemMove(UserKey1, szPrivateKey, syMin(syStrLength(szPrivateKey), MAX_SHORT_KEY_STRING_LEN));
    syMemMove(UserKey2, (PSTR)(szPrivateKey + MAX_SHORT_KEY_STRING_LEN),
               sizeof (UserKey2));
    syMemMove(InKey, szPrivateKey, syMin(syStrLength(szPrivateKey), sizeof(InKey)));

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

    // Build the SAFER 128-bit Private KEY
    Safer_Expand_Userkey(UserKey1, UserKey2,
                         IS_SAFER128_NO_OF_ROUNDS, TRUE, gisSaferKey);

    // Clear the original key so it doesn't sit around in memory
    syMemSet(szPrivateKey, 0, syStrLength(szPrivateKey));
    syMemSet(UserKey1, 0, sizeof (UserKey1));
    syMemSet(UserKey2, 0, sizeof (UserKey2));
    syMemSet(InKey, 0, sizeof (InKey));

    gbSyResetFilter = TRUE;
    return OK;

    // Keep things tidy
    #undef MAX_SHORT_KEY_STRING_LEN
    #undef MAX_LONG_KEY_STRING_LEN
    #undef NOF_CHARS
    #undef END_OF_LINE
    #undef IS_SAFER128_NO_OF_ROUNDS
  }


// End of ISENCRYPT.C
