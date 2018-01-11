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
import datetime
import struct

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
    # encrypt an 8 byte bytearray
    block_in= list(inp)
    
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
    return bytearray([n&0xff for n in s])


def decrypt(inp):
    # decrypt an 8 byte bytearray
    block_in= list(inp)

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

    return bytearray([a,b,c,d,e,f,g,h])


#-------------------------------------------------------------------------

if __name__ == '__main__':
    print("Safer SK-128 Encryption\n");

    # encrypt data - 8 bytes at a time
    inpBuf= b"12345678"
    outBuf= encrypt(inpBuf)

    print("outBuf=",outBuf);
    tmpBuf= decrypt(outBuf)
    #Decrypt in=48, 227, 197, 55, 200, 79, 125, 76, 
    #Decrypt out=49, 50, 51, 52, 53, 54, 55, 56,
  
    print("tmpBuf=",tmpBuf)
    if (inpBuf == tmpBuf):
        print("success")
    else:
        print("failure")

    # test 1:
    inp= b'\x0c\x06\x2e\x09\x76\x01\x0a\x03'
    out= b'\x86\xf0\xcc\x03\x28\x22\xb8\x59' 
    tmp= encrypt(inp)
    print(tmp == out)
    tmp= decrypt(tmp) 
    print(tmp == inp)

    # test 2:
    inp= b'\x3c\x00\x08\x00\x4c\x4f\x47\x49'
    out= b'\xcf\xd8\xe6\x35\x18\x27\xb7\xfb'
    tmp= encrypt(inp)
    print(tmp == out)
    tmp= decrypt(tmp) 
    print(tmp == inp)

    # test 3:    
    inp= b'\x4e\x00\x00\x00\x12\x00\x00\x00'
    out= b'\xf2\x7c\xcf\x5c\x3f\xd0\x4d\x33'
    tmp= encrypt(inp)
    print(tmp == out)
    tmp= decrypt(tmp) 
    print(tmp == inp)

    
    ''' Register-Foreign-Device
            Src: 192.168.87.37 -> 96.1.47.121 (Booth), Port 47810
            BVLC(81), Register-Foreign-Device(5), Len(0006), TTL(003c)
        [81, 05, 00, 06, 00, 03]
        
        Delta Register-Foreign-Device
    Data: 000844454c544100001a86f0cc032822b859cfd8e6351827...

00:08:44:45:4c:54:41:00:00:1a:86:f0:cc:03:28:22:b8:59:cf:d8:e6:35:18:27:b7:fb:f2:7c:cf:5c:3f:d0:4d:33


[81, fe, 00,26, 00,08,]
    
0000   00 08 44 45 4c 54 41 00 00 1a 86 f0 cc 03 28 22  ..DELTA.......("
0010   b8 59 cf d8 e6 35 18 27 b7 fb f2 7c cf 5c 3f d0  .Y...5.'...|.\?.
0020   4d 33                                            M3

encrypt= 86 f0 cc 03 28 22  b8 59 cf d8 e6 35 18 27 b7 fb f2 7c cf 5c 3f d0 4d 33
    '''
        
    out= decrypt(b'\x86\xf0\xcc\x03\x28\x22\xb8\x59')
    print('Time: {}:{}:{}.{}  Date: {}-{}-{}-{}'.format(
        out[0],out[1],out[2],out[3], out[4]+1900,out[5],out[6],out[7] )) 
    
    out= decrypt(b'\xcf\xd8\xe6\x35\x18\x27\xb7\xfb')
    print('TTL: {} sec   len({}) Pwd:{}'.format(out[0], out[2], out[4:]))

    out= decrypt(b'\xf2\x7c\xcf\x5c\x3f\xd0\x4d\x33')
    print('{}'.format(out))


    ''' build up a packet binary packet
        pkt= {user}{encrypted payload}
        user= <len+3>USER<0>
        payload= <len+2>{time}{date}{password}
        password= <len+3>PASSWORD<0>
    '''
    user= b'DELTA'
    fmt= '>h{}sB'.format(len(user))
    bin1= struct.pack(fmt,len(user)+3,user,0)

    utc_now= datetime.datetime.utcnow()
    tz_offset= -8
    blt= utc_now + datetime.timedelta(hours=tz_offset)
    ttl= 60
    dt= struct.pack('BBBBBBBBh',
             blt.hour,blt.minute,blt.second,blt.microsecond//10000,
             blt.year-1900,blt.month,blt.day,blt.isoweekday(), ttl)
    
    pwd= b'LOGIN'
    fmt= 'h{}sBBBBBBBB'.format(len(pwd))
    bin2= struct.pack(fmt,len(pwd)+3,pwd,0,0,0,0,0,0,0,0)

    payload= dt+bin2
    ep= b''
    for i in range(len(payload)//8):
        out= encrypt(payload[i*0:8])
        ep += out
        
    pkt= bin1 + struct.pack('>h',len(ep)+2) + ep
    
    print("Done");
