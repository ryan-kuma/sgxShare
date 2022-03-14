/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "Enclave.h"
#include "Enclave_t.h" /* print_string */
#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string.h>
#include <stdlib.h>
#include <sgx_trts.h>

#include "ippcp.h"

#define Delen 50
#define Solen 100


/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
int printf(const char* fmt, ...)
{
    char buf[BUFSIZ] = { '\0' };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
    return (int)strnlen(buf, BUFSIZ - 1) + 1;
}

int Bitsize2Wordsize(int nBits)
{
    return (nBits+31)>>5;    
}

Ipp32u* rand32(Ipp32u* px, int size)
{
    for (int i = 0; i < size; i++)    
    {
        int val1, val2;
        sgx_read_rand((unsigned char*)&val1, 4);
        sgx_read_rand((unsigned char*)&val2, 4);
        px[i] = (val1<<16) + val2;    
    }

    return px;
}

IppsPRNGState* newPRNG(int seedBitsize) 
{ 
    int seedSize = Bitsize2Wordsize(seedBitsize);
    Ipp32u* seed = new Ipp32u[seedSize];
    Ipp32u* augm = new Ipp32u[seedSize];
    
    int size;
    IppsBigNumState* pTmp;
    ippsPRNGGetSize(&size);
    IppsPRNGState* pCtx = (IppsPRNGState*)( new Ipp8u [size] ); 
    ippsPRNGInit(seedBitsize, pCtx); 

    ippsPRNGSetSeed(pTmp=newBN(seedSize, rand32(seed,seedSize)), pCtx);
    delete [](Ipp8u*)pTmp;
    ippsPRNGSetAugment(pTmp=newBN(seedSize, rand32(augm, seedSize)), pCtx);
    delete [](Ipp8u*)pTmp;

    delete []seed;
    delete []augm;

    return pCtx; 
} 

void deletePRNG(IppsPRNGState* pPRNG)
{
    delete[] (Ipp8u*)pPRNG;
}

void Type_BN(const char *pMsg, const IppsBigNumState* pBN)
{
	int size;
	ippsGetSize_BN(pBN, &size);
 		
	Ipp8u* bnValue = new Ipp8u [size*4];
	ippsGetOctString_BN(bnValue, size*4, pBN);
 		
	if(pMsg)
        printf("%s: ",pMsg);

	for(int n=0; n<size*4; n++)
        printf("%02x",(int)bnValue[n]);
    printf("\n");

	delete [] bnValue;     
}

void copy_BN(char *pDst, const IppsBigNumState* pBN)
{
	int size;
	ippsGetSize_BN(pBN, &size);
 		
	Ipp8u* bnValue = new Ipp8u [size*4];
	ippsGetOctString_BN(bnValue, size*4, pBN);
    
	for(int n=0; n<size*4; n++)
    {
        snprintf(pDst+2*n, 4, "%02x", bnValue[n]);
    }

	delete [] bnValue;     
}

IppsECCPState* newStd_256_ECP(void)
{
    int ctxSize;
    ippsECCPGetSize(256, &ctxSize);    
    IppsECCPState *pCtx = (IppsECCPState*)(new Ipp8u [ctxSize]);
    ippsECCPInit(256, pCtx);
    ippsECCPSetStd(IppECCPStd256r1, pCtx);
    return pCtx;
}

IppsBigNumState* newBN(int len,const Ipp32u* pData) 
{ 
   int ctxSize; 
   ippsBigNumGetSize(len, &ctxSize); 
   IppsBigNumState* pBN = (IppsBigNumState*)( new Ipp8u [ctxSize] ); 
   ippsBigNumInit(len, pBN); 
   if(pData) 
      ippsSet_BN(IppsBigNumPOS, len, pData, pBN); 
   return pBN; 
} 

IppsECCPPointState* newECP_256_point(void)
{
    int ctxSize;
    ippsECCPPointGetSize(256, &ctxSize);    
    IppsECCPPointState* pPoint = (IppsECCPPointState*)(new Ipp8u [ctxSize]);
    ippsECCPPointInit(256, pPoint);
    return pPoint;
}


//根据x和多项式求y
IppsBigNumState* calculate_Y(IppsBigNumState* x, IppsBigNumState** poly, int polylen)
{
    Ipp32u one = 1;
    const Ipp8u maxp[] ="\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFE\xBA\xAE\xDC\xE6\xAF\x48\xA0\x3B\xBF\xD2\x5E\x8C\xD0\x36\x41\x41";
    IppsBigNumState* bnMaxp = newBN(8);
    ippsSetOctString_BN(maxp, 32, bnMaxp);

    int bigsize = sizeof(maxp)/sizeof(Ipp32u);
    IppsBigNumState* bntmp = newBN(1,&one);

    IppsBigNumState* bnytmp = newBN(2*bigsize);
	for (int i = 0; i < polylen; i++) {
        IppsBigNumState* coeff = poly[i];
        IppsBigNumState* tmpMul = newBN(bigsize*2);

        ippsMul_BN(coeff, bntmp, tmpMul);
        ippsAdd_BN(tmpMul, bnytmp, bnytmp);
        
        ippsMul_BN(bntmp,x,bntmp);
        delete[] (Ipp8u*)tmpMul;
	}

    IppsBigNumState* bny = newBN(bigsize);
    ippsMod_BN(bnytmp, bnMaxp, bny);

    delete[] (Ipp8u*)bntmp;
    delete[] (Ipp8u*)bnMaxp;
	return bny;	
}


//使用x数组根据拉格朗日插值法计算secrete,默认数组长度为3
IppsBigNumState* verify(IppsBigNumState** piece)
{
    //Ipp32u maxp[] = {0xD0364141, 0xBFD25E8C, 0xAF48A03B, 0xBAAEDCE6, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF};
    const Ipp8u maxp[] ="\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFE\xBA\xAE\xDC\xE6\xAF\x48\xA0\x3B\xBF\xD2\x5E\x8C\xD0\x36\x41\x41";
    IppsBigNumState* bnMaxp = newBN(8);
    ippsSetOctString_BN(maxp, 32, bnMaxp);

    int bigsize = sizeof(maxp)/sizeof(Ipp32u);

/*
    Ipp32u maxp = 839;
    int bigsize = 1;
    IppsBigNumState* bnMaxp = newBN(1, &maxp);
    */

    IppsBigNumState* secrete = newBN(bigsize);
    IppsBigNumState* secretetmp = newBN(2*bigsize);

    for (int i = 0; i < 3; i++)
    {
        Ipp32u piece_i = i+1;
        Ipp32u one = 1;
        IppsBigNumState* bn_one = newBN(1, &one);
        IppsBigNumState* bn_tmp = newBN(bigsize);
        ippsAdd_BN(bn_tmp, bn_one, bn_tmp);
        IppsBigNumState* bn_mulpiece = newBN(2*bigsize);
        for (int j = 0; j < 3; j++)
        {
            if (j == i)
                continue;
            Ipp32u k = j-i;
            Ipp32u incj = j+1;
            int negative = 0;
            if (j < i)
            {
                negative = 1;
                k = i-j;    
            }
            IppsBigNumState* bn_k = newBN(1, &k);
            IppsBigNumState* bn_j = newBN(1, &incj);
            IppsBigNumState* bn_inverse = newBN(bigsize);
            IppStatus st = ippsModInv_BN(bn_k,bnMaxp,bn_inverse);
            if (negative == 1)
                ippsSub_BN(bnMaxp, bn_inverse,bn_inverse);

            IppsBigNumState* bn_mulj = newBN(bigsize*2);
            IppsBigNumState* bn_multmp = newBN(bigsize);
            ippsMul_BN(bn_inverse, bn_j, bn_mulj);
            ippsMod_BN(bn_mulj, bnMaxp, bn_multmp);

            ippsMul_BN(bn_multmp, bn_tmp, bn_mulj);
            ippsMod_BN(bn_mulj, bnMaxp, bn_tmp);

            delete [] (Ipp8u*)bn_k;
            delete [] (Ipp8u*)bn_j;
            delete [] (Ipp8u*)bn_inverse;
            delete [] (Ipp8u*)bn_mulj;
            delete [] (Ipp8u*)bn_multmp;
        }


        ippsMul_BN(piece[i],bn_tmp,bn_mulpiece);
//        Type_BN("bntmp is", bn_mulpiece);
        ippsAdd_BN(bn_mulpiece, secretetmp, secretetmp);

        delete [] (Ipp8u*)bn_tmp;
        delete [] (Ipp8u*)bn_mulpiece;
    }

    ippsMod_BN(secretetmp, bnMaxp, secrete);

    delete [] (Ipp8u*) bnMaxp;
    delete [] (Ipp8u*) secretetmp;

    return secrete;
}

void secret_sharing(char* pDst, int piece_n, int piece_k)
//void secret_sharing(char *pubA, int piece_n, int piece_k)
{

    /*
	int piece_n = 11;
	int piece_k = 3;
    */
    piece_k = 3;

    //标准256位椭圆曲线
    IppsECCPState* pECP = newStd_256_ECP();
    const Ipp8u maxp[] ="\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFE\xBA\xAE\xDC\xE6\xAF\x48\xA0\x3B\xBF\xD2\x5E\x8C\xD0\x36\x41\x41";
    IppsBigNumState* bnmaxp = newBN(8);
    ippsSetOctString_BN(maxp, 32, bnmaxp);
    int ordsize = sizeof(maxp)/sizeof(Ipp32u);

    IppsPRNGState* pRandGen = newPRNG();

    //随机生成A的私钥和椭圆公钥
    IppsBigNumState* keyPriA = newBN(ordsize);
    ippsTRNGenRDSEED_BN(keyPriA, 256,pRandGen);
    ippsMod_BN(keyPriA, bnmaxp, keyPriA);
    IppsECCPPointState* keyPubA = newECP_256_point();
    ippsECCPPublicKey(keyPriA, keyPubA, pECP);
    //A椭圆曲线x坐标,y坐标
    IppsBigNumState* keyPubA_x = newBN(ordsize);
    IppsBigNumState* keyPubA_y = newBN(ordsize);
    ippsECCPGetPoint(keyPubA_x,keyPubA_y, keyPubA, pECP);

    
    IppsBigNumState* poly[piece_k] = {0};
    IppsBigNumState* piece[piece_n] = {0};
    poly[0] = keyPriA;

    //随机生成piece_k阶多项式
    Ipp32u tmpData[8];
    for (int i = 1; i < piece_k; i++)
    {
        IppsBigNumState* bn_tmp = newBN(ordsize);
        ippsTRNGenRDSEED_BN(bn_tmp, 256, pRandGen);

        poly[i] = bn_tmp;
    }

    //根据多项式生成piece_n个分片
    for (int i = 1; i <= piece_n; i++)
    {
        Ipp32u x = i;
        IppsBigNumState* bnx = newBN(1, &x);
        IppsBigNumState* y = calculate_Y(bnx, poly, piece_k);    

        piece[i-1] = y;

        delete[] (Ipp8u*)bnx;
    }

    Type_BN("pri key is: ", keyPriA);
    Type_BN("coordinate x of pub key is: ", keyPubA_x);
    Type_BN("coordinate y of pub key is: ", keyPubA_y);

    //将公钥复制出来
    for (int i = 1; i < piece_n; i++)
    {
        Type_BN("piece is \n", piece[i-1]);
    }
    IppsBigNumState* sum_piece = verify(piece);
    Type_BN("sum_piece is:",sum_piece);

    copy_BN(pDst, keyPubA_x);

    delete [] (Ipp8u*) sum_piece;

    for (int i = 1; i < piece_k; i++)
        delete[] (Ipp8u*) poly[i];


    delete[] (Ipp8u*) keyPubA;
    delete[] (Ipp8u*) keyPriA;
    delete[] (Ipp8u*) bnmaxp;
    deletePRNG(pRandGen);

    for(int i = 1; i <= piece_n; i++)
        delete[] (Ipp8u*) piece[i-1];

    return ;


}
