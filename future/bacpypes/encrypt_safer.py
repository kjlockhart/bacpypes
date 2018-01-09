''' SAFER (Secure And Fast Encryption Routine) block-cipher algorithm [SAFER SK-128] 

SAFER is designed for use in software (of embedded systems).  Unlike DEA, or IDEA, it 
does not divide the block into parts where some parts affect others; instead the plaintexxt 
is directly changed by going through S-boxes [and its inverse when decrypting]. 

See: SAFER K-64: A Byte-Oriented Block-Ciphering Algorithm, James L. Massey.  AND
     SAFER K-64: One Year Later, James L. Massey.

     Signal and Information Processing Laboratory
     Swiss Federal Institute of Technology
     ETH Zentrum, CH-8092 Zuerich, Switzerland
     Circa: 1994

Ported to Python 2018-01-04 CopperTree Analytics

Note: Delta Controls uses this [obscure] encryption algorithm in its BBMD controllers to 
    add proprietary security to BACnet's unprotected BBMD RegistForeignDevice service.
 
'''
#--- standard Python modules ---
#--- 3rd party modules ---
#--- this application's modules ---

#-------------------------------------------------------------------------
SAFER_K128_DEFAULT_ROUNDS=   10
SAFER_SK128_DEFAULT_ROUNDS=  10
SAFER_MAX_ROUNDS=            13
SAFER_BLOCK_LEN= 8
SAFER_KEY_LEN= (1 + SAFER_BLOCK_LEN * (1 + 2 * SAFER_MAX_ROUNDS))

TAB_LEN= 256

#-------------------------------------------------------------------------

''' Generate the algorithm's Exponents and Logarithms tables.  (Powers of 45)
'''
exp_tab= [(45**exp)%257 for exp in range(256)]
exp_tab[128]=0      # fixup the one that exceeds a byte

log_tab= [0 for i in range(256)]
for i in range(256):
    log_tab[exp_tab[i]]= i

#print(exp_tab)
#print(log_tab)
#print(exp_tab[128],log_tab[0],exp_tab[1])

''' Prepare the encryption's key schedule.  
    Since Delta uses a const (although obscured) secret key, the schedule will also be a constant.
    Porting all the algorithm's code from TurboPascal, C, or Delta's custom implementation is 
    both time consumming and frought with errors.
'''    
key='DeltaControlsInc'      # Delta's secret key (surprise!)
ka=[84, 253, 73, 117, 108, 70, 85, 19]      # obscured version of the Key[0:8]
kb=[211, 16, 172, 104, 152, 87, 59, 187]    # obscured version of the Key[8:16]

''' SAFER SK-128 key schedule derived from the obscured secret key.
'''
'''
keysch= [
[ 11, 211,  16, 172, 104, 152,  87,  59,     187,   5, 189, 230, 129, 192,  26,  85],   # round 0
[ 85, 114, 152,  74,  43, 191, 101, 154,      58, 155, 146,  47,  97,  54, 253, 109],
[ 50,  82, 207, 219, 103, 232, 226, 237,     117, 233,  17,  30,  84,  55, 246,  62],
[176,  82, 202,  38, 140,  19,  60, 100,      58, 204,  40, 192,   8, 108, 109, 120],
[156, 227,  59, 176,  17, 197, 239, 233,      90,  19,  75,   5, 205,  36, 240,  37],   # round 4
[ 84, 103, 191, 121,  80,  54, 134,  34,      68, 143, 229, 239, 204, 144, 119,  16],
[233,  21, 178,  82, 183,  59,  98,  36,      50, 181,  36,  76, 128,  53,   4, 109],
[199,  91,  38, 190,  61,  32, 112, 240,     179, 119, 113,  31,  50, 110, 171,   7],
[185,  56, 245, 133, 255, 110, 239, 102,     204, 226, 164, 127, 153, 217, 213, 101],   # round 8
[ 47, 129, 211, 212, 155,   8, 153, 245,      29, 117,  49,  60, 185, 161, 226,  81],
[239,  12,  77, 145,  89, 188,  16, 226,     201,  48, 150,  34, 137,  96, 148,  36],
[  9,  98, 119, 229, 148, 218,  55, 222,      20,   0,   0,   0,   0,   0,   0,   0],
[  0,   0,   0,   0,   0,   0,   0,   0,       0,   0,   0,   0,   0,   0,   0,   0],   # round 12
  ]
'''
rounds= 11
keysch= [
[211,  16, 172, 104, 152,  87,  59, 187,      5, 189, 230, 129, 192,  26,  85,  85],
[114, 152,  74,  43, 191, 101, 154,  58,    155, 146,  47,  97,  54, 253, 109,  50],
[ 82, 207, 219, 103, 232, 226, 237, 117,    233,  17,  30,  84,  55, 246,  62, 176],
[ 82, 202,  38, 140,  19,  60, 100,  58,    204,  40, 192,   8, 108, 109, 120, 156],
[227,  59, 176,  17, 197, 239, 233,  90,     19,  75,   5, 205,  36, 240,  37,  84],
[103, 191, 121,  80,  54, 134,  34,  68,    143, 229, 239, 204, 144, 119,  16, 233],
[ 21, 178,  82, 183,  59,  98,  36,  50,    181,  36,  76, 128,  53,   4, 109, 199],
[ 91,  38, 190,  61,  32, 112, 240, 179,    119, 113,  31,  50, 110, 171,   7, 185],
[ 56, 245, 133, 255, 110, 239, 102, 204,    226, 164, 127, 153, 217, 213, 101,  47],
[129, 211, 212, 155,   8, 153, 245,  29,    117,  49,  60, 185, 161, 226,  81, 239],
[ 12,  77, 145,  89, 188,  16, 226, 201,     48, 150,  34, 137,  96, 148,  36,   9],
[ 98, 119, 229, 148, 218,  55, 222,  20,      0,   0,   0,   0,   0,   0,   0,   0],
[  0,   0,   0,   0,   0,   0,   0,   0,      0,   0,   0,   0,   0,   0,   0,   0],
 ]

'''
ka= [(i>>3)+(i<<5) for i in ka]   # bytes of keyA are right rotated by 3
kb= [int(c) for c in keyB]

for i in range(11):         # SAFER_K128_DEFAULT_ROUNDS+1):
    for j in range(8):
        ka[j]= (j<<6)+(j>>2)
        kb[j]= (j<<6)+(j>>2)

        k[2*i][j] = (ka[(j + 2 * i - 1) % (SAFER_BLOCK_LEN + 1)]
                            + exp_tab[exp_tab[18 * i + j + 1]]) & 0xFF;
        k[2*i+1][j] = (kb[(j + 2 * i) % (SAFER_BLOCK_LEN + 1)]
                            + exp_tab[exp_tab[18 * i + j + 10]]) & 0xFF;

        #k[2*i][j]  = ka[j] + exp_tab[exp_tab[18*i+j]]
        #k[2*i+1][j]= kb[j] + exp_tab[exp_tab[18*i+9+j]]
'''

'''
class SAFER:
    
    __init__():
        pass
'''
    
    
'''
/******************* Macros ***************************************************/
#define ROL(x, n)    ((unsigned char)((unsigned int)(x) << (n)\
                                     |(unsigned int)((x) & 0xFF) >> (8 - (n))))
#define EXP(x)       exp_tab[(x) & 0xFF]
#define LOG(x)       log_tab[(x) & 0xFF]
#define PHT(x, y)    { y += x; x += y; }
#define IPHT(x, y)   { x -= y; y -= x; }

/******************************************************************************/
'''
def EXP(x):
    x &= 0xff
    return exp_tab[x]

def LOG(x):
    x &= 0xff
    return log_tab[x]
    
def PHT(x,y):   
    y= (y + x)&0xff
    x= (x + y)&0xff
    return (x,y)

def IPHT(x,y):
    x = (x - y)&0xff
    y = (y - x)&0xff
    return (x,y)


def encrypt(inp):
    # encrypts 8 bytes at a time
    block_in= [ord(c) for c in inp]
    
    a = block_in[0]; b = block_in[1]; c = block_in[2]; d = block_in[3];
    e = block_in[4]; f = block_in[5]; g = block_in[6]; h = block_in[7];
    
    for r in range(rounds):
        print('\nA-',a,b,c,d,e,f,g,h)
        k= keysch[r]
        a ^= k[0]; b += k[1]; c += k[2]; d ^= k[3]
        e ^= k[4]; f += k[5]; g += k[6]; h ^= k[7];
        print('B-',a,b,c,d,e,f,g,h)
        
        a = EXP(a) + k[ 8]; b = LOG(b) ^ k[ 9]; c = LOG(c) ^ k[10]; d = EXP(d) + k[11];
        e = EXP(e) + k[12]; f = LOG(f) ^ k[13]; g = LOG(g) ^ k[14]; h = EXP(h) + k[15];
        print('C-',a,b,c,d,e,f,g,h)

        a,b=PHT(a,b); c,d=PHT(c,d); e,f=PHT(e,f); g,h=PHT(g,h);
        print('P1-',a,b,c,d,e,f,g,h)
        a,c=PHT(a,c); e,g=PHT(e,g); b,d=PHT(b,d); f,h=PHT(f,h);
        print('P2-',a,b,c,d,e,f,g,h)
        a,e=PHT(a,e); b,f=PHT(b,f); c,g=PHT(c,g); d,h=PHT(d,h);
        print('P3-',a,b,c,d,e,f,g,h)
        t = b; b = e; e = c; c = t; t = d; d = f; f = g; g = t;
        print('E-',a,b,c,d,e,f,g,h)

    k= keysch[r+1]
    a ^= k[0]; b += k[1]; c += k[2]; d ^= k[3];
    e ^= k[4]; f += k[5]; g += k[6]; h ^= k[7];
    print('*-',a,b,c,d,e,f,g,h)
    s= [a,b,c,d,e,f,g,h]
    block_out= ''.join(chr(i&0xff) for i in s) 

    print([ord(c) for c in block_out])
    return block_out


def decrypt(inp):
    # encrypts 8 bytes at a time
    block_in= [ord(c) for c in inp]

    a = block_in[0]; b = block_in[1]; c = block_in[2]; d = block_in[3];
    e = block_in[4]; f = block_in[5]; g = block_in[6]; h = block_in[7];

    k= keysch[11]
    h ^= k[7]; g= (g-k[6])&0xff; f= (f-k[5])&0xff; e ^= k[4];
    d ^= k[3]; c= (c-k[2])&0xff; b= (b-k[1])&0xff; a ^= k[0];
    
    for r in range(rounds-1,-1,-1):
        k= keysch[r]
        print('\nE-',a,b,c,d,e,f,g,h)
        t = e; e = b; b = c; c = t; t = f; f = d; d = g; g = t;
        print('P3-',a,b,c,d,e,f,g,h)
        a,e=IPHT(a,e); b,f=IPHT(b,f); c,g=IPHT(c,g); d,h=IPHT(d,h);
        print('P2-',a,b,c,d,e,f,g,h)
        a,c=IPHT(a,c); e,g=IPHT(e,g); b,d=IPHT(b,d); f,h=IPHT(f,h);
        print('P1-',a,b,c,d,e,f,g,h)
        a,b=IPHT(a,b); c,d=IPHT(c,d); e,f=IPHT(e,f); g,h=IPHT(g,h);
        print('C-',a,b,c,d,e,f,g,h)
        
        h= (h-k[15])&0xff; g ^= k[14]; f ^= k[13]; e= (e-k[12])&0xff;
        d= (d-k[11])&0xff; c ^= k[10]; b ^= k[9];  a= (a-k[8])&0xff;
        print('B-',a,b,c,d,e,f,g,h)
        
        h= LOG(h)^k[7]; g= (EXP(g)-k[6])&0xff; f= (EXP(f)-k[5])&0xff; e= LOG(e)^k[4];
        d= LOG(d)^k[3]; c= (EXP(c)-k[2])&0xff; b= (EXP(b)-k[1])&0xff; a= LOG(a)^k[0];
        print('A-',a,b,c,d,e,f,g,h)

    s= [a,b,c,d,e,f,g,h]
    block_out= ''.join(chr(i&0xff) for i in s) 

    print([ord(c) for c in block_out])
    return block_out


#-------------------------------------------------------------------------

if __name__ == '__main__':
    print("Safer SK-128 Encryption\n");

    # encrypt data - 8 bytes at a time
    inpBuf= "12345678"
    outBuf= encrypt(inpBuf)
    #Encrypt in=49, 50, 51, 52, 53, 54, 55, 56, 
    # Encrypt out=48, 227, 197, 55, 200, 79, 125, 76,

    print("outBuf=",outBuf);
    tmpBuf= decrypt(outBuf)
    #Decrypt in=48, 227, 197, 55, 200, 79, 125, 76, 
    #Decrypt out=49, 50, 51, 52, 53, 54, 55, 56,
  
    print("tmpBuf=",tmpBuf)
    if (inpBuf == tmpBuf):
        print("success")
    else:
        print("failure")

    print("Done");
