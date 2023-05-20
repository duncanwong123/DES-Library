// *****
// * PROJECT:		DESLib (DES)
// * FILENAME: 		DESLibPrv.c
// * AUTHOR:		Hector Ho Fuentes
// *
// *				
// * 
// * DESCRIPTION:	DES library functionality interface implementation.
// *
// * HISTORY:		Hector Ho Fuentes 4/4/2001
// *
// *
// * COPYRIGHT:		
// *
// *****

#include <PalmOS.h>											// Standard Palm stuff
#include "DESLib.h"
#include "DESLibPrv.h"

#define RE_LEN 0x0406

static void Unpack(unsigned char *, UInt32 *);
static void Pack(UInt32 *, unsigned char *);
static void DESKey(UInt32 *, unsigned char *, int);
static void CookKey(UInt32 *, UInt32 *, int);
static void DESFunction(UInt32 *, UInt32 *);

 /***********************************************************************
 *
 * FUNCTION:    DES_Init
 *
 * DESCRIPTION: Initialize context.  Caller must zeroize the context when finished.
 *
 * PARAMETERS: 
 *				DES_CTX *context:			context 
 *				unsigned char key[]:		key 
 *				unsigned char iv[]:			initializing vector
 *				int encrypt					encrypt flag (1 = encrypt, 0 = decrypt) 
 *
 *
 * RETURNED:    nothing
 *
 * REVISION HISTORY:
 *			Name	Date		Description
 *			----	----		-----------
 *			
 *
 ***********************************************************************/
 
void DES_Init (DES_CTX *context, unsigned char key[], unsigned char iv[], int encrypt)
{  
  /* Copy encrypt flag to context.
   */
  context->encrypt = encrypt;
  
  /* Pack initializing vector into context.
   */
  Pack (context->iv, iv);

  /* Save the IV for use in Restart */
  context->originalIV[0] = context->iv[0];
  context->originalIV[1] = context->iv[1];

  /* Precompute key schedule
   */
  if((context->desmode == OFBISO) || (context->desmode == CFB)|| (context->desmode == OFBFIPS81)) 
  DESKey (context->subkeys[0], key, ENCRYPT);
  else 
  DESKey (context->subkeys[0], key, context->encrypt);
  
}

 /***********************************************************************
 *
 * FUNCTION:    DES_ECBpdate
 *
 * DESCRIPTION: DES-ECB block update operation. Continues a DES-ECB encryption
 *  			operation, processing eight-byte message blocks, and updating
 *  			the context.
 *
 * PARAMETERS: 
 *				DES_CTX *context: 	context 
 *				unsigned char *output: 	output block 
 *				unsigned char *input: 	input block 
 *				unsigned int len: 		length of input and output blocks 
 *
 *
 * RETURNED:    nothing
 *
 * REVISION HISTORY:
 *			Name	Date		Description
 *			----	----		-----------
 *			
 *
 ***********************************************************************/
int DES_ECBUpdate (DES_CTX *context, unsigned char *output, unsigned char *input, unsigned long len)
{
  UInt32 inputBlock[2], work[2];
  int i;
  
  if (len % 8)
    return (RE_LEN);

  for (i = 0; i < len/8; i++) {
    Pack (inputBlock, &input[8*i]);
        
  work[0] = inputBlock[0];
  work[1] = inputBlock[1];         

  DESFunction(work, context->subkeys[0]);

  Unpack (&output[8*i], work);
  }
  
  /* Zeroize sensitive information.
  R_memset ((POINTER)inputBlock, 0, sizeof (inputBlock));
  R_memset ((POINTER)work, 0, sizeof (work));
  */
  return (0);
}

/***********************************************************************
 *
 * FUNCTION:    DES_CBCUpdate
 *
 * DESCRIPTION: DES-CBC block update operation. Continues a DES-CBC encryption
 *  			operation, processing eight-byte message blocks, and updating
 *  			the context.
 *
 * PARAMETERS: 
 *				DES_CTX *context: 	context 
 *				unsigned char *output: 	output block 
 *				unsigned char *input: 	input block 
 *				unsigned int len: 		length of input and output blocks 
 *
 *
 * RETURNED:    nothing
 *
 * REVISION HISTORY:
 *			Name	Date		Description
 *			----	----		-----------
 *			
 *
 ***********************************************************************/
int DES_CBCUpdate (DES_CTX *context, unsigned char *output, unsigned char *input, unsigned long len)
{
  UInt32 inputBlock[2], work[2];
  int i;
  
  if (len % 8)
    return (RE_LEN);

  for (i = 0; i < len/8; i++) {
    Pack (inputBlock, &input[8*i]);
        
    /* Chain if encrypting.
     */
    if (context->encrypt) {
      work[0] = inputBlock[0] ^ context->iv[0];
      work[1] = inputBlock[1] ^ context->iv[1];
    }
    else {
      work[0] = inputBlock[0];
      work[1] = inputBlock[1];         
    }

    DESFunction(work, context->subkeys[0]);

    /* Chain if decrypting, then update IV.
     */
    if (context->encrypt) {
      context->iv[0] = work[0];
      context->iv[1] = work[1];
    }
    else {
      work[0] ^= context->iv[0];
      work[1] ^= context->iv[1];
      context->iv[0] = inputBlock[0];
      context->iv[1] = inputBlock[1];
    }
    Unpack (&output[8*i], work);
  }
  
  /* Zeroize sensitive information.
  R_memset ((POINTER)inputBlock, 0, sizeof (inputBlock));
  R_memset ((POINTER)work, 0, sizeof (work));
  */
  return (0);
}

/***********************************************************************
 *
 * FUNCTION:    DES_CFBUpdate
 *
 * DESCRIPTION: DES-CFB block update operation. Continues a DES-CFB encryption
 *  			operation, processing eight-byte message blocks, and updating
 *  			the context.
 *
 * PARAMETERS: 
 *				DES_CTX *context: 	context 
 *				unsigned char *output: 	output block 
 *				unsigned char *input: 	input block 
 *				unsigned int len: 		length of input and output blocks 
 *
 *
 * RETURNED:    nothing
 *
 * REVISION HISTORY:
 *			Name	Date		Description
 *			----	----		-----------
 *			
 *
 ***********************************************************************/
int DES_CFBUpdate (DES_CTX *context, unsigned char *output, unsigned char *input, unsigned long len)
{
  UInt32 inputBlock[2], work[2], outputBlocks[2];
  int i,j, rounds, maxlen, nbitshift;
  UInt8 tempBlocks[8];
  
  maxlen=len/8;
  rounds = 64/context->n;
  nbitshift = context->n;
  
  if ((nbitshift == 8) || (nbitshift == 16) || (nbitshift == 32) || (nbitshift == 64) || (nbitshift == 1)){
    
  for (i = 0; i < maxlen; i++) {
   
    Pack (inputBlock, &input[8*i]);
    
    for(j=0;j<8;j++) tempBlocks[j]=0;
    outputBlocks[0]=0;
    outputBlocks[1]=0;
   
    for(j=0; j < rounds ; j++){    
   		work[0] = context->iv[0];
   		work[1] = context->iv[1];
			
	    DESFunction(work, context->subkeys[0]);
		
	   	
		
		if(nbitshift==1){
				if(j<8) tempBlocks[0] =  tempBlocks[0] | (((UInt8) (work[0]>>31) &0x00000001) << (7-j)); 
				else if (j<16) tempBlocks[1] =  tempBlocks[1] | (((UInt8) (work[0]>>31) &0x00000001) <<(15-j)); 
				else if (j<24) tempBlocks[2] =  tempBlocks[2] | (((UInt8) (work[0]>>31) &0x00000001) <<(23-j)); 
				else if (j<32) tempBlocks[3] =  tempBlocks[3] | (((UInt8) (work[0]>>31) &0x00000001) <<(31-j));
				else if (j<40) tempBlocks[4] =  tempBlocks[4] | (((UInt8) (work[0]>>31) &0x00000001) <<(39-j));
				else if (j<48) tempBlocks[5] =  tempBlocks[5] | (((UInt8) (work[0]>>31) &0x00000001) <<(47-j));
				else if (j<56) tempBlocks[6] =  tempBlocks[6] | (((UInt8) (work[0]>>31) &0x00000001) <<(55-j)); 
				else tempBlocks[7] =  tempBlocks[7] | (((UInt8) (work[0]>>31) &0x00000001) <<(61-j));
				context->iv[0] = (context->iv[0]<<1)| ((context->iv[1] >> 31) & 0x00000001);
			   
				if(context->encrypt==ENCRYPT) 
			   		context->iv[1] = (context->iv[1]<<1)| (((work[0] >> 31) ^ (inputBlock[j/32]>>(31-(j%32)))) & 0x00000001);
				else 
					context->iv[1] = (context->iv[1]<<1)| (inputBlock[j/32]>>(31-(j%32)) & 0x00000001);
				
			}
		else if(nbitshift == 8){  
				tempBlocks[j]= (UInt8) (work[0]>>24); 
				context->iv[0] = (context->iv[0]<<8)| ((context->iv[1] >> 24) & 0x000000FF);
			   	if(context->encrypt==ENCRYPT) 
			   		context->iv[1] = (context->iv[1]<<8)| (((work[0] >> 24) ^ (inputBlock[j/4]>>(24-(j%4)*8))) & 0x000000FF);
				else 
					context->iv[1] = (context->iv[1]<<8)| (inputBlock[j/4]>>(24-(j%4)*8) & 0x000000FF);
				}
		else if (nbitshift == 16){
				tempBlocks[2*j]= (UInt8) (work[0]>>24); 
				tempBlocks[2*j+1]= (UInt8) ((work[0]>>16)&0x000000FF);
				
				context->iv[0] = (context->iv[0]<<16)| ((context->iv[1] >> 16) & 0x0000FFFF);
			   	context->iv[1] = (context->iv[1]<<16)| ((work[0] >> 16) & 0x0000FFFF);
			   	if(context->encrypt==ENCRYPT) 
			   		context->iv[1] = (context->iv[1]<<16)| (((work[0] >> 16) ^ (inputBlock[j/2]>>(16-(j%2)*16))) & 0x0000FFFF);
				else 
					context->iv[1] = (context->iv[1]<<16)| (inputBlock[j/2]>>(16-(j%2)*16) & 0x0000FFFF);
				}
		else if (nbitshift == 32){
				tempBlocks[4*j]= (UInt8) 	(work[0]>>24); 
				tempBlocks[4*j+1]= (UInt8) ((work[0]>>16)&0x000000FF);
				tempBlocks[4*j+2]= (UInt8) ((work[0]>>8)&0x000000FF); 
				tempBlocks[4*j+3]= (UInt8) (work[0]&0x000000FF);
				context->iv[0] = context->iv[1];
			   	if(context->encrypt==ENCRYPT)
				   	context->iv[1] = work[0] ^ inputBlock[j%2];
				else context->iv[1] = inputBlock[j%2];		   	
			   	}
		else {
				tempBlocks[0]= (UInt8) 	(work[0]>>24); 
				tempBlocks[1]= (UInt8) ((work[0]>>16)&0x000000FF);
				tempBlocks[2]= (UInt8) ((work[0]>>8)&0x000000FF); 
				tempBlocks[3]= (UInt8) (work[0]&0x000000FF);
				tempBlocks[4]= (UInt8) 	(work[1]>>24); 
				tempBlocks[5]= (UInt8) ((work[1]>>16)&0x000000FF);
				tempBlocks[6]= (UInt8) ((work[1]>>8)&0x000000FF); 
				tempBlocks[7]= (UInt8) (work[1]&0x000000FF);
				if(context->encrypt==ENCRYPT){
				context->iv[0] = work[0] ^ inputBlock[0];
			   	context->iv[1] = work[1] ^ inputBlock[1];
			   	}
			   	else
			   	{
			   	context->iv[0] = inputBlock[0];
			   	context->iv[1] = inputBlock[1];
			   	}
				}
		}
   	Pack (outputBlocks, &tempBlocks[0]);
   	inputBlock[0]^=outputBlocks[0];
   	inputBlock[1]^=outputBlocks[1];
    Unpack (&output[8*i], inputBlock);

  
  }
  
  /* Zeroize sensitive information.
  R_memset ((POINTER)inputBlock, 0, sizeof (inputBlock));
  R_memset ((POINTER)work, 0, sizeof (work));
  */
  return (0);
  }
  

  else return RE_LEN;
}

/***********************************************************************
 *
 * FUNCTION:    DES_OFBISOUpdate
 *
 * DESCRIPTION: DES-OFB block update operation. Continues a DES-OFB encryption
 *  			operation.  Note:  If n is not equal to 1, 8, 16, 32, or 64
 *				an error will be returned.
 *
 * PARAMETERS: 
 *				DES_CTX *context: 	context 
 *				unsigned char *output: 	output block 
 *				unsigned char *input: 	input block 
 *				unsigned int len: 		length of input and output blocks 
 *
 *
 * RETURNED:    nothing
 *
 * REVISION HISTORY:
 *			Name	Date		Description
 *			----	----		-----------
 *			
 *
 ***********************************************************************/
int DES_OFBISOUpdate (DES_CTX *context, unsigned char *output, unsigned char *input, unsigned long len)
{
  UInt32 inputBlock[2], work[2], outputBlocks[2];
  int i,j, rounds, maxlen, nbitshift;
  UInt8 tempBlocks[8];
  
  maxlen=len/8;
  rounds = 64/context->n;
  nbitshift = context->n;
  
  if ((nbitshift == 8) || (nbitshift == 16) || (nbitshift == 32) || (nbitshift == 64) || (nbitshift == 1)){
    
  for (i = 0; i < maxlen; i++) {
   
    Pack (inputBlock, &input[8*i]);
    
    for(j=0;j<8;j++) tempBlocks[j]=0;
    outputBlocks[0]=0;
    outputBlocks[1]=0;
   
    for(j=0; j < rounds ; j++){    
   		work[0] = context->iv[0];
   		work[1] = context->iv[1];
			
	    DESFunction(work, context->subkeys[0]);
		
	   	context->iv[0] = work[0];
	   	context->iv[1] = work[1];
		
		if(nbitshift==1){
				if(j<8) tempBlocks[0] =  tempBlocks[0] | (((UInt8) (work[0]>>31) &0x00000001) << (7-j)); 
				else if (j<16) tempBlocks[1] =  tempBlocks[1] | (((UInt8) (work[0]>>31) &0x00000001) <<(15-j)); 
				else if (j<24) tempBlocks[2] =  tempBlocks[2] | (((UInt8) (work[0]>>31) &0x00000001) <<(23-j)); 
				else if (j<32) tempBlocks[3] =  tempBlocks[3] | (((UInt8) (work[0]>>31) &0x00000001) <<(31-j));
				else if (j<40) tempBlocks[4] =  tempBlocks[4] | (((UInt8) (work[0]>>31) &0x00000001) <<(39-j));
				else if (j<48) tempBlocks[5] =  tempBlocks[5] | (((UInt8) (work[0]>>31) &0x00000001) <<(47-j));
				else if (j<56) tempBlocks[6] =  tempBlocks[6] | (((UInt8) (work[0]>>31) &0x00000001) <<(55-j)); 
				else tempBlocks[7] =  tempBlocks[7] | (((UInt8) (work[0]>>31) &0x00000001) <<(61-j));
			}
		else if(nbitshift == 8){  
				tempBlocks[j]= (UInt8) (work[0]>>24); 
				}
		else if (nbitshift == 16){
				tempBlocks[2*j]= (UInt8) (work[0]>>24); 
				tempBlocks[2*j+1]= (UInt8) ((work[0]>>16)&0x000000FF);
				}
		else if (nbitshift == 32){
				tempBlocks[4*j]= (UInt8) 	(work[0]>>24); 
				tempBlocks[4*j+1]= (UInt8) ((work[0]>>16)&0x000000FF);
				tempBlocks[4*j+2]= (UInt8) ((work[0]>>8)&0x000000FF); 
				tempBlocks[4*j+3]= (UInt8) (work[0]&0x000000FF);
				}
		else {
				tempBlocks[0]= (UInt8) 	(work[0]>>24); 
				tempBlocks[1]= (UInt8) ((work[0]>>16)&0x000000FF);
				tempBlocks[2]= (UInt8) ((work[0]>>8)&0x000000FF); 
				tempBlocks[3]= (UInt8) (work[0]&0x000000FF);
				tempBlocks[4]= (UInt8) 	(work[1]>>24); 
				tempBlocks[5]= (UInt8) ((work[1]>>16)&0x000000FF);
				tempBlocks[6]= (UInt8) ((work[1]>>8)&0x000000FF); 
				tempBlocks[7]= (UInt8) (work[1]&0x000000FF);
				}
		}
   	Pack (outputBlocks, &tempBlocks[0]);
   	inputBlock[0]^=outputBlocks[0];
   	inputBlock[1]^=outputBlocks[1];
    Unpack (&output[8*i], inputBlock);
  
  }
  
  /* Zeroize sensitive information.
  R_memset ((POINTER)inputBlock, 0, sizeof (inputBlock));
  R_memset ((POINTER)work, 0, sizeof (work));
  */
  return (0);
  }
  

  else return RE_LEN;
}

/***********************************************************************
 *
 * FUNCTION:    DES_OFBFIPS81Update
 *
 * DESCRIPTION: DES-OFB block update operation. Continues a DES-OFB encryption
 *  			operation.  Note:  If n is not equal to 1, 8, 16, 32, or 64
 *				an error will be returned.
 *
 * PARAMETERS: 
 *				DES_CTX *context: 	context 
 *				unsigned char *output: 	output block 
 *				unsigned char *input: 	input block 
 *				unsigned int len: 		length of input and output blocks 
 *
 *
 * RETURNED:    nothing
 *
 * REVISION HISTORY:
 *			Name	Date		Description
 *			----	----		-----------
 *			
 *
 ***********************************************************************/
int DES_OFBFIPS81Update (DES_CTX *context, unsigned char *output, unsigned char *input, unsigned long len)
{
  UInt32 inputBlock[2], work[2], outputBlocks[2];
  int i,j, rounds, maxlen, nbitshift;
  UInt8 tempBlocks[8];
  
  maxlen=len/8;
  rounds = 64/context->n;
  nbitshift = context->n;
  
  if ((nbitshift == 8) || (nbitshift == 16) || (nbitshift == 32) || (nbitshift == 64) || (nbitshift == 1)){
    
  for (i = 0; i < maxlen; i++) {
   
    Pack (inputBlock, &input[8*i]);
    
    for(j=0;j<8;j++) tempBlocks[j]=0;
    outputBlocks[0]=0;
    outputBlocks[1]=0;
   
    for(j=0; j < rounds ; j++){    
   		work[0] = context->iv[0];
   		work[1] = context->iv[1];
			
	    DESFunction(work, context->subkeys[0]);
		
	   	
		
		if(nbitshift==1){
				if(j<8) tempBlocks[0] =  tempBlocks[0] | (((UInt8) (work[0]>>31) &0x00000001) << (7-j)); 
				else if (j<16) tempBlocks[1] =  tempBlocks[1] | (((UInt8) (work[0]>>31) &0x00000001) <<(15-j)); 
				else if (j<24) tempBlocks[2] =  tempBlocks[2] | (((UInt8) (work[0]>>31) &0x00000001) <<(23-j)); 
				else if (j<32) tempBlocks[3] =  tempBlocks[3] | (((UInt8) (work[0]>>31) &0x00000001) <<(31-j));
				else if (j<40) tempBlocks[4] =  tempBlocks[4] | (((UInt8) (work[0]>>31) &0x00000001) <<(39-j));
				else if (j<48) tempBlocks[5] =  tempBlocks[5] | (((UInt8) (work[0]>>31) &0x00000001) <<(47-j));
				else if (j<56) tempBlocks[6] =  tempBlocks[6] | (((UInt8) (work[0]>>31) &0x00000001) <<(55-j)); 
				else tempBlocks[7] =  tempBlocks[7] | (((UInt8) (work[0]>>31) &0x00000001) <<(61-j));
				context->iv[0] = (context->iv[0]<<1)| ((context->iv[1] >> 31) & 0x00000001);
			   	context->iv[1] = (context->iv[1]<<1)| ((work[0] >> 31) & 0x00000001);
			}
		else if(nbitshift == 8){  
				tempBlocks[j]= (UInt8) (work[0]>>24); 
				context->iv[0] = (context->iv[0]<<8)| ((context->iv[1] >> 24) & 0x000000FF);
			   	context->iv[1] = (context->iv[1]<<8)| ((work[0] >> 24) & 0x000000FF);
				}
		else if (nbitshift == 16){
				tempBlocks[2*j]= (UInt8) (work[0]>>24); 
				tempBlocks[2*j+1]= (UInt8) ((work[0]>>16)&0x000000FF);
				context->iv[0] = (context->iv[0]<<16)| ((context->iv[1] >> 16) & 0x0000FFFF);
			   	context->iv[1] = (context->iv[1]<<16)| ((work[0] >> 16) & 0x0000FFFF);
				}
		else if (nbitshift == 32){
				tempBlocks[4*j]= (UInt8) 	(work[0]>>24); 
				tempBlocks[4*j+1]= (UInt8) ((work[0]>>16)&0x000000FF);
				tempBlocks[4*j+2]= (UInt8) ((work[0]>>8)&0x000000FF); 
				tempBlocks[4*j+3]= (UInt8) (work[0]&0x000000FF);
				context->iv[0] = context->iv[1];
			   	context->iv[1] = work[0];
				}
		else {
				tempBlocks[0]= (UInt8) 	(work[0]>>24); 
				tempBlocks[1]= (UInt8) ((work[0]>>16)&0x000000FF);
				tempBlocks[2]= (UInt8) ((work[0]>>8)&0x000000FF); 
				tempBlocks[3]= (UInt8) (work[0]&0x000000FF);
				tempBlocks[4]= (UInt8) 	(work[1]>>24); 
				tempBlocks[5]= (UInt8) ((work[1]>>16)&0x000000FF);
				tempBlocks[6]= (UInt8) ((work[1]>>8)&0x000000FF); 
				tempBlocks[7]= (UInt8) (work[1]&0x000000FF);
				context->iv[0] = work[0];
			   	context->iv[1] = work[1];
				}
		}
   	Pack (outputBlocks, &tempBlocks[0]);
   	inputBlock[0]^=outputBlocks[0];
   	inputBlock[1]^=outputBlocks[1];
    Unpack (&output[8*i], inputBlock);

  
  }
  
  /* Zeroize sensitive information.
  R_memset ((POINTER)inputBlock, 0, sizeof (inputBlock));
  R_memset ((POINTER)work, 0, sizeof (work));
  */
  return (0);
  }
  

  else return RE_LEN;
}
/***********************************************************************
 *
 * FUNCTION:    DES_CBCRestart
 *
 * DESCRIPTION: DES-CBC block Restart Operation.
 *
 * PARAMETERS: 
 *				DES_CBC_CTX *context: 	context 
 *				
 *
 * RETURNED:    nothing
 *
 * REVISION HISTORY:
 *			Name	Date		Description
 *			----	----		-----------
 *			
 *
 ***********************************************************************/
void DES_Restart (DES_CTX *context)
{
  /* Reset to the original IV */
  context->iv[0] = context->originalIV[0];
  context->iv[1] = context->originalIV[1];
}

/***********************************************************************
 *
 * FUNCTION:    DESX_Init
 *
 * DESCRIPTION: 	Initialize context.  Caller must zeroize the context when finished.
 *				  	The key has the DES key, input whitener and output whitener concatenated.
 *
 * PARAMETERS:
 *				DESX_CTX *context: 		context;
 *				unsigned char key[]:	DES key and whiteners
 *				unsigned char iv[]:		DES initializing vector
 *				int encrypt:			encrypt flag (1 = encrypt, 0 = decrypt)
 *
 *
 * RETURNED:    nothing
 *
 * REVISION HISTORY:
 *			Name	Date		Description
 *			----	----		-----------
 *			
 *
 ***********************************************************************/ 
void DESX_Init (DES_CTX *context, unsigned char key[], unsigned char iv[], int encrypt)
{  
  /* Copy encrypt flag to context.
   */
  context->encrypt = encrypt;

  /* Pack initializing vector and whiteners into context.
   */
  Pack (context->iv, iv);
  Pack (context->inputWhitener, key + 8);
  Pack (context->outputWhitener, key + 16);

  /* Save the IV for use in Restart */
  context->originalIV[0] = context->iv[0];
  context->originalIV[1] = context->iv[1];

  /* Precompute key schedule.
   */
   if(context->desmode == OFBISO || context->desmode == OFBFIPS81 || context->desmode == CFB)
   		DESKey (context->subkeys[0], key, ENCRYPT);
   else DESKey (context->subkeys[0], key, context->encrypt);
   
}


/***********************************************************************
 *
 * FUNCTION:    DESX_ECBpdate
 *
 * DESCRIPTION: DESX-ECB block update operation. Continues a DESX-ECB encryption
 *  			operation, processing eight-byte message blocks, and updating
 *  			the context.
 *
 * PARAMETERS: 
 *				DES_CTX *context: 	context 
 *				unsigned char *output: 	output block 
 *				unsigned char *input: 	input block 
 *				unsigned int len: 		length of input and output blocks 
 *
 *
 * RETURNED:    nothing
 *
 * REVISION HISTORY:
 *			Name	Date		Description
 *			----	----		-----------
 *			
 *
 ***********************************************************************/
int DESX_ECBUpdate (DES_CTX *context, unsigned char *output, unsigned char *input, unsigned long len)
{
  UInt32 inputBlock[2], work[2];
  int i;
  
  if (len % 8)
    return (RE_LEN);

  for (i = 0; i < len/8; i++) {
    Pack (inputBlock, &input[8*i]);
  
  if(context->encrypt==ENCRYPT){      
  	work[0] = inputBlock[0] ^ context->inputWhitener[0];
	work[1] = inputBlock[1] ^ context->inputWhitener[1];         
	}
  else{
  	work[0] = inputBlock[0] ^ context->outputWhitener[0];
	work[1] = inputBlock[1] ^ context->outputWhitener[1];
  }
  DESFunction(work, context->subkeys[0]);
  
  if(context->encrypt==ENCRYPT){  
  	work[0] ^=  context->outputWhitener[0];
  	work[1] ^=  context->outputWhitener[1];
  	}
  else{
  	work[0] ^=  context->inputWhitener[0];
  	work[1] ^=  context->inputWhitener[1];
  }
  Unpack (&output[8*i], work);
  }
  
  /* Zeroize sensitive information.
  R_memset ((POINTER)inputBlock, 0, sizeof (inputBlock));
  R_memset ((POINTER)work, 0, sizeof (work));
  */
  return (0);
}

 /***********************************************************************
 *
 * FUNCTION:    DESX_CBCUpdate
 *
 * DESCRIPTION: 	DESX-CBC block update operation. Continues a DESX-CBC encryption
 *  				operation, processing eight-byte message blocks, and updating
 *  				the context.
 *
 * PARAMETERS:
 *				DESX_CBC_CTX *context:	context 
 *				unsigned char *output:  output block 
 *				unsigned char *input:	input block 
 *				unsigned int len:		length of input and output blocks 
 *
 *
 * RETURNED:    0 if there is no problem
 *
 * REVISION HISTORY:
 *			Name	Date		Description
 *			----	----		-----------
 *			
 *
 ***********************************************************************/ 
int DESX_CBCUpdate (DES_CTX *context, unsigned char *output, unsigned char *input, unsigned long len)
{
  UInt32 inputBlock[2], work[2];
  unsigned long i;
  
  if (len % 8)
    return (RE_LEN);

  for (i = 0; i < len/8; i++)  {
    Pack (inputBlock, &input[8*i]);
        
    /* Chain if encrypting, and xor with whitener.
     */
    if (context->encrypt) {
      work[0] =
        inputBlock[0] ^ context->iv[0] ^ context->inputWhitener[0];
      work[1] =
        inputBlock[1] ^ context->iv[1] ^ context->inputWhitener[1];
    }
    else {
      work[0] = inputBlock[0] ^ context->outputWhitener[0];
      work[1] = inputBlock[1] ^ context->outputWhitener[1];         
    }

    DESFunction (work, context->subkeys[0]);

    /* Xor with whitener, chain if decrypting, then update IV.
     */
    if (context->encrypt) {
      work[0] ^= context->outputWhitener[0];
      work[1] ^= context->outputWhitener[1];
      context->iv[0] = work[0];
      context->iv[1] = work[1];
    }
    else {
      work[0] ^= context->iv[0] ^ context->inputWhitener[0];
      work[1] ^= context->iv[1] ^ context->inputWhitener[1];
      context->iv[0] = inputBlock[0];
      context->iv[1] = inputBlock[1];
    }
    Unpack (&output[8*i], work);
  }
  
  /* Zeroize sensitive information.
  R_memset ((POINTER)inputBlock, 0, sizeof (inputBlock));
  R_memset ((POINTER)work, 0, sizeof (work));
  */
  return (0);
}

/***********************************************************************
 *
 * FUNCTION:    DESX_CFBUpdate
 *
 * DESCRIPTION: DESX-CFB block update operation. Continues a DESX-CFB encryption
 *  			operation, processing eight-byte message blocks, and updating
 *  			the context.
 *
 * PARAMETERS: 
 *				DES_CTX *context: 	context 
 *				unsigned char *output: 	output block 
 *				unsigned char *input: 	input block 
 *				unsigned int len: 		length of input and output blocks 
 *
 *
 * RETURNED:    nothing
 *
 * REVISION HISTORY:
 *			Name	Date		Description
 *			----	----		-----------
 *			
 *
 ***********************************************************************/
int DESX_CFBUpdate (DES_CTX *context, unsigned char *output, unsigned char *input, unsigned long len)
{
  UInt32 inputBlock[2], work[2], outputBlocks[2];
  int i,j, rounds, maxlen, nbitshift;
  UInt8 tempBlocks[8];
  
  maxlen=len/8;
  rounds = 64/context->n;
  nbitshift = context->n;
  
  if ((nbitshift == 8) || (nbitshift == 16) || (nbitshift == 32) || (nbitshift == 64) || (nbitshift == 1)){
    
  for (i = 0; i < maxlen; i++) {
   
    Pack (inputBlock, &input[8*i]);
    
    for(j=0;j<8;j++) tempBlocks[j]=0;
    outputBlocks[0]=0;
    outputBlocks[1]=0;
   
    for(j=0; j < rounds ; j++){    
   		work[0] = context->iv[0] ^ context->inputWhitener[0];
   		work[1] = context->iv[1] ^ context->inputWhitener[1];
			
	    DESFunction(work, context->subkeys[0]);
		
	   	work[0] ^= context->outputWhitener[0];
   		work[1] ^= context->outputWhitener[1];
		
		if(nbitshift==1){
				if(j<8) tempBlocks[0] =  tempBlocks[0] | (((UInt8) (work[0]>>31) &0x00000001) << (7-j)); 
				else if (j<16) tempBlocks[1] =  tempBlocks[1] | (((UInt8) (work[0]>>31) &0x00000001) <<(15-j)); 
				else if (j<24) tempBlocks[2] =  tempBlocks[2] | (((UInt8) (work[0]>>31) &0x00000001) <<(23-j)); 
				else if (j<32) tempBlocks[3] =  tempBlocks[3] | (((UInt8) (work[0]>>31) &0x00000001) <<(31-j));
				else if (j<40) tempBlocks[4] =  tempBlocks[4] | (((UInt8) (work[0]>>31) &0x00000001) <<(39-j));
				else if (j<48) tempBlocks[5] =  tempBlocks[5] | (((UInt8) (work[0]>>31) &0x00000001) <<(47-j));
				else if (j<56) tempBlocks[6] =  tempBlocks[6] | (((UInt8) (work[0]>>31) &0x00000001) <<(55-j)); 
				else tempBlocks[7] =  tempBlocks[7] | (((UInt8) (work[0]>>31) &0x00000001) <<(61-j));
				context->iv[0] = (context->iv[0]<<1)| ((context->iv[1] >> 31) & 0x00000001);
			   
				if(context->encrypt==ENCRYPT) 
			   		context->iv[1] = (context->iv[1]<<1)| (((work[0] >> 31) ^ (inputBlock[j/32]>>(31-(j%32)))) & 0x00000001);
				else 
					context->iv[1] = (context->iv[1]<<1)| (inputBlock[j/32]>>(31-(j%32)) & 0x00000001);
				
			}
		else if(nbitshift == 8){  
				tempBlocks[j]= (UInt8) (work[0]>>24); 
				context->iv[0] = (context->iv[0]<<8)| ((context->iv[1] >> 24) & 0x000000FF);
			   	if(context->encrypt==ENCRYPT) 
			   		context->iv[1] = (context->iv[1]<<8)| (((work[0] >> 24) ^ (inputBlock[j/4]>>(24-(j%4)*8))) & 0x000000FF);
				else 
					context->iv[1] = (context->iv[1]<<8)| (inputBlock[j/4]>>(24-(j%4)*8) & 0x000000FF);
				}
		else if (nbitshift == 16){
				tempBlocks[2*j]= (UInt8) (work[0]>>24); 
				tempBlocks[2*j+1]= (UInt8) ((work[0]>>16)&0x000000FF);
				
				context->iv[0] = (context->iv[0]<<16)| ((context->iv[1] >> 16) & 0x0000FFFF);
			   	context->iv[1] = (context->iv[1]<<16)| ((work[0] >> 16) & 0x0000FFFF);
			   	if(context->encrypt==ENCRYPT) 
			   		context->iv[1] = (context->iv[1]<<16)| (((work[0] >> 16) ^ (inputBlock[j/2]>>(16-(j%2)*16))) & 0x0000FFFF);
				else 
					context->iv[1] = (context->iv[1]<<16)| (inputBlock[j/2]>>(16-(j%2)*16) & 0x0000FFFF);
				}
		else if (nbitshift == 32){
				tempBlocks[4*j]= (UInt8) 	(work[0]>>24); 
				tempBlocks[4*j+1]= (UInt8) ((work[0]>>16)&0x000000FF);
				tempBlocks[4*j+2]= (UInt8) ((work[0]>>8)&0x000000FF); 
				tempBlocks[4*j+3]= (UInt8) (work[0]&0x000000FF);
				context->iv[0] = context->iv[1];
			   	if(context->encrypt==ENCRYPT)
				   	context->iv[1] = work[0] ^ inputBlock[j%2];
				else context->iv[1] = inputBlock[j%2];		   	
			   	}
		else {
				tempBlocks[0]= (UInt8) 	(work[0]>>24); 
				tempBlocks[1]= (UInt8) ((work[0]>>16)&0x000000FF);
				tempBlocks[2]= (UInt8) ((work[0]>>8)&0x000000FF); 
				tempBlocks[3]= (UInt8) (work[0]&0x000000FF);
				tempBlocks[4]= (UInt8) 	(work[1]>>24); 
				tempBlocks[5]= (UInt8) ((work[1]>>16)&0x000000FF);
				tempBlocks[6]= (UInt8) ((work[1]>>8)&0x000000FF); 
				tempBlocks[7]= (UInt8) (work[1]&0x000000FF);
				if(context->encrypt==ENCRYPT){
				context->iv[0] = work[0] ^ inputBlock[0];
			   	context->iv[1] = work[1] ^ inputBlock[1];
			   	}
			   	else
			   	{
			   	context->iv[0] = inputBlock[0];
			   	context->iv[1] = inputBlock[1];
			   	}
				}
		}
   	Pack (outputBlocks, &tempBlocks[0]);
   	inputBlock[0]^=outputBlocks[0];
   	inputBlock[1]^=outputBlocks[1];
    Unpack (&output[8*i], inputBlock);

  
  }
  
  /* Zeroize sensitive information.
  R_memset ((POINTER)inputBlock, 0, sizeof (inputBlock));
  R_memset ((POINTER)work, 0, sizeof (work));
  */
  return (0);
  }
  

  else return RE_LEN;
}

/***********************************************************************
 *
 * FUNCTION:    DESX_OFBISOUpdate
 *
 * DESCRIPTION: DESX-OFB block update operation. Continues a DESX-OFB encryption
 *  			operation.  Note:  If n is not equal to 1, 8, 16, 32, or 64
 *				an error will be returned.
 *
 * PARAMETERS: 
 *				DES_CTX *context: 	context 
 *				unsigned char *output: 	output block 
 *				unsigned char *input: 	input block 
 *				unsigned int len: 		length of input and output blocks 
 *
 *
 * RETURNED:    nothing
 *
 * REVISION HISTORY:
 *			Name	Date		Description
 *			----	----		-----------
 *			
 *
 ***********************************************************************/
int DESX_OFBISOUpdate (DES_CTX *context, unsigned char *output, unsigned char *input, unsigned long len)
{
  UInt32 inputBlock[2], work[2], outputBlocks[2];
  int i,j, rounds, maxlen, nbitshift;
  UInt8 tempBlocks[8];
  
  maxlen=len/8;
  rounds = 64/context->n;
  nbitshift = context->n;
  
  if ((nbitshift == 8) || (nbitshift == 16) || (nbitshift == 32) || (nbitshift == 64) || (nbitshift == 1)){
    
  for (i = 0; i < maxlen; i++) {
   
    Pack (inputBlock, &input[8*i]);
    
    for(j=0;j<8;j++) tempBlocks[j]=0;
    outputBlocks[0]=0;
    outputBlocks[1]=0;
   
    for(j=0; j < rounds ; j++){    
   		work[0] = context->iv[0] ^ context->inputWhitener[0];
   		work[1] = context->iv[1] ^ context->inputWhitener[0];
			
	    DESFunction(work, context->subkeys[0]);
		
	   	context->iv[0] = work[0] ^ context->outputWhitener[0];
	   	context->iv[1] = work[1] ^ context->outputWhitener[1];
		
		if(nbitshift==1){
				if(j<8) tempBlocks[0] =  tempBlocks[0] | (((UInt8) (work[0]>>31) &0x00000001) << (7-j)); 
				else if (j<16) tempBlocks[1] =  tempBlocks[1] | (((UInt8) (work[0]>>31) &0x00000001) <<(15-j)); 
				else if (j<24) tempBlocks[2] =  tempBlocks[2] | (((UInt8) (work[0]>>31) &0x00000001) <<(23-j)); 
				else if (j<32) tempBlocks[3] =  tempBlocks[3] | (((UInt8) (work[0]>>31) &0x00000001) <<(31-j));
				else if (j<40) tempBlocks[4] =  tempBlocks[4] | (((UInt8) (work[0]>>31) &0x00000001) <<(39-j));
				else if (j<48) tempBlocks[5] =  tempBlocks[5] | (((UInt8) (work[0]>>31) &0x00000001) <<(47-j));
				else if (j<56) tempBlocks[6] =  tempBlocks[6] | (((UInt8) (work[0]>>31) &0x00000001) <<(55-j)); 
				else tempBlocks[7] =  tempBlocks[7] | (((UInt8) (work[0]>>31) &0x00000001) <<(61-j));
			}
		else if(nbitshift == 8){  
				tempBlocks[j]= (UInt8) (work[0]>>24); 
				}
		else if (nbitshift == 16){
				tempBlocks[2*j]= (UInt8) (work[0]>>24); 
				tempBlocks[2*j+1]= (UInt8) ((work[0]>>16)&0x000000FF);
				}
		else if (nbitshift == 32){
				tempBlocks[4*j]= (UInt8) 	(work[0]>>24); 
				tempBlocks[4*j+1]= (UInt8) ((work[0]>>16)&0x000000FF);
				tempBlocks[4*j+2]= (UInt8) ((work[0]>>8)&0x000000FF); 
				tempBlocks[4*j+3]= (UInt8) (work[0]&0x000000FF);
				}
		else {
				tempBlocks[0]= (UInt8) 	(work[0]>>24); 
				tempBlocks[1]= (UInt8) ((work[0]>>16)&0x000000FF);
				tempBlocks[2]= (UInt8) ((work[0]>>8)&0x000000FF); 
				tempBlocks[3]= (UInt8) (work[0]&0x000000FF);
				tempBlocks[4]= (UInt8) 	(work[1]>>24); 
				tempBlocks[5]= (UInt8) ((work[1]>>16)&0x000000FF);
				tempBlocks[6]= (UInt8) ((work[1]>>8)&0x000000FF); 
				tempBlocks[7]= (UInt8) (work[1]&0x000000FF);
				}
		}
   	Pack (outputBlocks, &tempBlocks[0]);
   	inputBlock[0]^=outputBlocks[0] ^ context->outputWhitener[0];;
   	inputBlock[1]^=outputBlocks[1] ^ context->outputWhitener[1];;
    Unpack (&output[8*i], inputBlock);
  
  }
  
  /* Zeroize sensitive information.
  R_memset ((POINTER)inputBlock, 0, sizeof (inputBlock));
  R_memset ((POINTER)work, 0, sizeof (work));
  */
  return (0);
  }
  

  else return RE_LEN;
}

/***********************************************************************
 *
 * FUNCTION:    DES_OFBFIPS81Update
 *
 * DESCRIPTION: DES-OFB block update operation. Continues a DES-OFB encryption
 *  			operation.  Note:  If n is not equal to 1, 8, 16, 32, or 64
 *				an error will be returned.
 *
 * PARAMETERS: 
 *				DES_CTX *context: 	context 
 *				unsigned char *output: 	output block 
 *				unsigned char *input: 	input block 
 *				unsigned int len: 		length of input and output blocks 
 *
 *
 * RETURNED:    nothing
 *
 * REVISION HISTORY:
 *			Name	Date		Description
 *			----	----		-----------
 *			
 *
 ***********************************************************************/
int DESX_OFBFIPS81Update (DES_CTX *context, unsigned char *output, unsigned char *input, unsigned long len)
{
  UInt32 inputBlock[2], work[2], outputBlocks[2];
  int i,j, rounds, maxlen, nbitshift;
  UInt8 tempBlocks[8];
  
  maxlen=len/8;
  rounds = 64/context->n;
  nbitshift = context->n;
  
  if ((nbitshift == 8) || (nbitshift == 16) || (nbitshift == 32) || (nbitshift == 64) || (nbitshift == 1)){
    
  for (i = 0; i < maxlen; i++) {
   
    Pack (inputBlock, &input[8*i]);
    
    for(j=0;j<8;j++) tempBlocks[j]=0;
    outputBlocks[0]=0;
    outputBlocks[1]=0;
   
    for(j=0; j < rounds ; j++){    
   		work[0] = context->iv[0] ^ context->inputWhitener[0];
   		work[1] = context->iv[1] ^ context->inputWhitener[1];
			
	    DESFunction(work, context->subkeys[0]);
		
	   	work[0] ^= context->outputWhitener[0];
		work[1] ^= context->outputWhitener[1];
		
		if(nbitshift==1){
				if(j<8) tempBlocks[0] =  tempBlocks[0] | (((UInt8) (work[0]>>31) &0x00000001) << (7-j)); 
				else if (j<16) tempBlocks[1] =  tempBlocks[1] | (((UInt8) (work[0]>>31) &0x00000001) <<(15-j)); 
				else if (j<24) tempBlocks[2] =  tempBlocks[2] | (((UInt8) (work[0]>>31) &0x00000001) <<(23-j)); 
				else if (j<32) tempBlocks[3] =  tempBlocks[3] | (((UInt8) (work[0]>>31) &0x00000001) <<(31-j));
				else if (j<40) tempBlocks[4] =  tempBlocks[4] | (((UInt8) (work[0]>>31) &0x00000001) <<(39-j));
				else if (j<48) tempBlocks[5] =  tempBlocks[5] | (((UInt8) (work[0]>>31) &0x00000001) <<(47-j));
				else if (j<56) tempBlocks[6] =  tempBlocks[6] | (((UInt8) (work[0]>>31) &0x00000001) <<(55-j)); 
				else tempBlocks[7] =  tempBlocks[7] | (((UInt8) (work[0]>>31) &0x00000001) <<(61-j));
				context->iv[0] = (context->iv[0]<<1)| ((context->iv[1] >> 31) & 0x00000001);
			   	context->iv[1] = (context->iv[1]<<1)| ((work[0] >> 31) & 0x00000001);
			}
		else if(nbitshift == 8){  
				tempBlocks[j]= (UInt8) (work[0]>>24); 
				context->iv[0] = (context->iv[0]<<8)| ((context->iv[1] >> 24) & 0x000000FF);
			   	context->iv[1] = (context->iv[1]<<8)| ((work[0] >> 24) & 0x000000FF);
				}
		else if (nbitshift == 16){
				tempBlocks[2*j]= (UInt8) (work[0]>>24); 
				tempBlocks[2*j+1]= (UInt8) ((work[0]>>16)&0x000000FF);
				context->iv[0] = (context->iv[0]<<16)| ((context->iv[1] >> 16) & 0x0000FFFF);
			   	context->iv[1] = (context->iv[1]<<16)| ((work[0] >> 16) & 0x0000FFFF);
				}
		else if (nbitshift == 32){
				tempBlocks[4*j]= (UInt8) 	(work[0]>>24); 
				tempBlocks[4*j+1]= (UInt8) ((work[0]>>16)&0x000000FF);
				tempBlocks[4*j+2]= (UInt8) ((work[0]>>8)&0x000000FF); 
				tempBlocks[4*j+3]= (UInt8) (work[0]&0x000000FF);
				context->iv[0] = context->iv[1];
			   	context->iv[1] = work[0];
				}
		else {
				tempBlocks[0]= (UInt8) 	(work[0]>>24); 
				tempBlocks[1]= (UInt8) ((work[0]>>16)&0x000000FF);
				tempBlocks[2]= (UInt8) ((work[0]>>8)&0x000000FF); 
				tempBlocks[3]= (UInt8) (work[0]&0x000000FF);
				tempBlocks[4]= (UInt8) 	(work[1]>>24); 
				tempBlocks[5]= (UInt8) ((work[1]>>16)&0x000000FF);
				tempBlocks[6]= (UInt8) ((work[1]>>8)&0x000000FF); 
				tempBlocks[7]= (UInt8) (work[1]&0x000000FF);
				context->iv[0] = work[0];
			   	context->iv[1] = work[1];
				}
		}
   	Pack (outputBlocks, &tempBlocks[0]);
   	inputBlock[0]^=outputBlocks[0];
   	inputBlock[1]^=outputBlocks[1];
    Unpack (&output[8*i], inputBlock);

  
  }
  
  /* Zeroize sensitive information.
  R_memset ((POINTER)inputBlock, 0, sizeof (inputBlock));
  R_memset ((POINTER)work, 0, sizeof (work));
  */
  return (0);
  }
  

  else return RE_LEN;
}
/***********************************************************************
 *
 * FUNCTION:    DESX_CBCRestart
 *
 * DESCRIPTION: DES-CBC block Restart Operation.
 *
 * PARAMETERS: 
 *				DESX_CBC_CTX *context: 	context 
 *				
 *
 * RETURNED:    nothing
 *
 * REVISION HISTORY:
 *			Name	Date		Description
 *			----	----		-----------
 *			
 *
 ***********************************************************************/
void DESX_Restart (DES_CTX *context)
{
  /* Reset to the original IV */
  context->iv[0] = context->originalIV[0];
  context->iv[1] = context->originalIV[1];
}

/***********************************************************************
 *
 * FUNCTION:    DES3_CBCInit
 *
 * DESCRIPTION: Initialize context.  Caller must zeroize the context when finished.
 *
 * PARAMETERS:
 *				DES3_CTX *context: 	context;
 *				unsigned char key[]:	DES key and whiteners
 *				unsigned char iv[]:		DES initializing vector
 *				int encrypt:			encrypt flag (1 = encrypt, 0 = decrypt)
 *
 *
 * RETURNED:    nothing
 *
 * REVISION HISTORY:
 *			Name	Date		Description
 *			----	----		-----------
 *			
 *
 ***********************************************************************/ 
void DES3_Init(DES_CTX *context, unsigned char key[], unsigned char iv[], int encrypt)
{  
  /* Copy encrypt flag to context.
   */
	context->encrypt = encrypt;

  /* Pack initializing vector into context.
   */
  Pack (context->iv, iv);

  /* Save the IV for use in Restart */
  context->originalIV[0] = context->iv[0];
  context->originalIV[1] = context->iv[1];

  /* Precompute key schedules.
   */
  if((context->desmode == OFBISO) || (context->desmode == CFB)|| (context->desmode == OFBFIPS81)){
    DESKey (context->subkeys[0], encrypt ? key : &key[16], ENCRYPT);
  	DESKey (context->subkeys[1], &key[8], DECRYPT);
  	DESKey (context->subkeys[2], encrypt ? &key[16] : key, ENCRYPT);
  }
  else{
  DESKey (context->subkeys[0], encrypt ? key : &key[16], encrypt);
  DESKey (context->subkeys[1], &key[8], !encrypt);
  DESKey (context->subkeys[2], encrypt ? &key[16] : key, encrypt);
  }
}

/***********************************************************************
 *
 * FUNCTION:    DES3_ECBUpdate
 *
 * DESCRIPTION: 	DES3_ECB block update operation. Continues a DES3-ECB encryption
 *  				operation, processing eight-byte message blocks, and updating
 *  				the context.
 *
 * PARAMETERS:
 *				DES3_CTX *context:	context 
 *				unsigned char *output:  output block 
 *				unsigned char *input:	input block 
 *				unsigned int len:		length of input and output blocks 
 *
 *
 * RETURNED:    0 if there is no problem
 *
 * REVISION HISTORY:
 *			Name	Date		Description
 *			----	----		-----------
 *			
 *
 ***********************************************************************/ 
 int DES3_ECBUpdate (DES_CTX *context, unsigned char *output, unsigned char *input, unsigned long len)
{
  UInt32 inputBlock[2], work[2];
  int i;
  
  if (len % 8)
    return (RE_LEN);

  for (i = 0; i < len/8; i++) {
    Pack (inputBlock, &input[8*i]);
        
  work[0] = inputBlock[0];
  work[1] = inputBlock[1];         

  DESFunction (work, context->subkeys[0]);
  DESFunction (work, context->subkeys[1]);
  DESFunction (work, context->subkeys[2]);

  Unpack (&output[8*i], work);
  }
  
  /* Zeroize sensitive information.
  R_memset ((POINTER)inputBlock, 0, sizeof (inputBlock));
  R_memset ((POINTER)work, 0, sizeof (work));
  */
  return (0);
}


/***********************************************************************
 *
 * FUNCTION:    DES3_CBCUpdate
 *
 * DESCRIPTION: 	DES3_CBC block update operation. Continues a DES3-CBC encryption
 *  				operation, processing eight-byte message blocks, and updating
 *  				the context.
 *
 * PARAMETERS:
 *				DES3_CTX *context:	context 
 *				unsigned char *output:  output block 
 *				unsigned char *input:	input block 
 *				unsigned int len:		length of input and output blocks 
 *
 *
 * RETURNED:    0 if there is no problem
 *
 * REVISION HISTORY:
 *			Name	Date		Description
 *			----	----		-----------
 *			
 *
 ***********************************************************************/ 
int DES3_CBCUpdate (DES_CTX *context, unsigned char *output, unsigned char *input, unsigned long len)
{
  UInt32 inputBlock[2], work[2];
  unsigned long i;
  
  if (len % 8)
    return (RE_LEN);

  for (i = 0; i < len/8; i++) {
    Pack (inputBlock, &input[8*i]);
        
    /* Chain if encrypting.
     */
    if (context->encrypt) {
      work[0] = inputBlock[0] ^ context->iv[0];
      work[1] = inputBlock[1] ^ context->iv[1];
    }
    else {
      work[0] = inputBlock[0];
      work[1] = inputBlock[1];         
    }

    DESFunction (work, context->subkeys[0]);
    DESFunction (work, context->subkeys[1]);
    DESFunction (work, context->subkeys[2]);

    /* Chain if decrypting, then update IV.
     */
    if (context->encrypt) {
      context->iv[0] = work[0];
      context->iv[1] = work[1];
    }
    else {
      work[0] ^= context->iv[0];
      work[1] ^= context->iv[1];
      context->iv[0] = inputBlock[0];
      context->iv[1] = inputBlock[1];
    }
    Unpack (&output[8*i], work);
  }
  
  /* Zeroize sensitive information.
  R_memset ((POINTER)inputBlock, 0, sizeof (inputBlock));
  R_memset ((POINTER)work, 0, sizeof (work));
  */
  return (0);
}
/***********************************************************************
 *
 * FUNCTION:    DES3_CFBUpdate
 *
 * DESCRIPTION: DES3-CFB block update operation. Continues a 3DES-CFB encryption
 *  			operation, processing eight-byte message blocks, and updating
 *  			the context.
 *
 * PARAMETERS: 
 *				DES_CTX *context: 	context 
 *				unsigned char *output: 	output block 
 *				unsigned char *input: 	input block 
 *				unsigned int len: 		length of input and output blocks 
 *
 *
 * RETURNED:    nothing
 *
 * REVISION HISTORY:
 *			Name	Date		Description
 *			----	----		-----------
 *			
 *
 ***********************************************************************/
int DES3_CFBUpdate (DES_CTX *context, unsigned char *output, unsigned char *input, unsigned long len)
{
  UInt32 inputBlock[2], work[2], outputBlocks[2];
  int i,j, rounds, maxlen, nbitshift;
  UInt8 tempBlocks[8];
  
  maxlen=len/8;
  rounds = 64/context->n;
  nbitshift = context->n;
  
  if ((nbitshift == 8) || (nbitshift == 16) || (nbitshift == 32) || (nbitshift == 64) || (nbitshift == 1)){
    
  for (i = 0; i < maxlen; i++) {
   
    Pack (inputBlock, &input[8*i]);
    
    for(j=0;j<8;j++) tempBlocks[j]=0;
    outputBlocks[0]=0;
    outputBlocks[1]=0;
   
    for(j=0; j < rounds ; j++){    
   		work[0] = context->iv[0];
   		work[1] = context->iv[1];
			
	    DESFunction(work, context->subkeys[0]);
	    DESFunction(work, context->subkeys[1]);
	    DESFunction(work, context->subkeys[2]);
		
	   	
		
		if(nbitshift==1){
				if(j<8) tempBlocks[0] =  tempBlocks[0] | (((UInt8) (work[0]>>31) &0x00000001) << (7-j)); 
				else if (j<16) tempBlocks[1] =  tempBlocks[1] | (((UInt8) (work[0]>>31) &0x00000001) <<(15-j)); 
				else if (j<24) tempBlocks[2] =  tempBlocks[2] | (((UInt8) (work[0]>>31) &0x00000001) <<(23-j)); 
				else if (j<32) tempBlocks[3] =  tempBlocks[3] | (((UInt8) (work[0]>>31) &0x00000001) <<(31-j));
				else if (j<40) tempBlocks[4] =  tempBlocks[4] | (((UInt8) (work[0]>>31) &0x00000001) <<(39-j));
				else if (j<48) tempBlocks[5] =  tempBlocks[5] | (((UInt8) (work[0]>>31) &0x00000001) <<(47-j));
				else if (j<56) tempBlocks[6] =  tempBlocks[6] | (((UInt8) (work[0]>>31) &0x00000001) <<(55-j)); 
				else tempBlocks[7] =  tempBlocks[7] | (((UInt8) (work[0]>>31) &0x00000001) <<(61-j));
				context->iv[0] = (context->iv[0]<<1)| ((context->iv[1] >> 31) & 0x00000001);
			   
				if(context->encrypt==ENCRYPT) 
			   		context->iv[1] = (context->iv[1]<<1)| (((work[0] >> 31) ^ (inputBlock[j/32]>>(31-(j%32)))) & 0x00000001);
				else 
					context->iv[1] = (context->iv[1]<<1)| (inputBlock[j/32]>>(31-(j%32)) & 0x00000001);
				
			}
		else if(nbitshift == 8){  
				tempBlocks[j]= (UInt8) (work[0]>>24); 
				context->iv[0] = (context->iv[0]<<8)| ((context->iv[1] >> 24) & 0x000000FF);
			   	if(context->encrypt==ENCRYPT) 
			   		context->iv[1] = (context->iv[1]<<8)| (((work[0] >> 24) ^ (inputBlock[j/4]>>(24-(j%4)*8))) & 0x000000FF);
				else 
					context->iv[1] = (context->iv[1]<<8)| (inputBlock[j/4]>>(24-(j%4)*8) & 0x000000FF);
				}
		else if (nbitshift == 16){
				tempBlocks[2*j]= (UInt8) (work[0]>>24); 
				tempBlocks[2*j+1]= (UInt8) ((work[0]>>16)&0x000000FF);
				
				context->iv[0] = (context->iv[0]<<16)| ((context->iv[1] >> 16) & 0x0000FFFF);
			   	context->iv[1] = (context->iv[1]<<16)| ((work[0] >> 16) & 0x0000FFFF);
			   	if(context->encrypt==ENCRYPT) 
			   		context->iv[1] = (context->iv[1]<<16)| (((work[0] >> 16) ^ (inputBlock[j/2]>>(16-(j%2)*16))) & 0x0000FFFF);
				else 
					context->iv[1] = (context->iv[1]<<16)| (inputBlock[j/2]>>(16-(j%2)*16) & 0x0000FFFF);
				}
		else if (nbitshift == 32){
				tempBlocks[4*j]= (UInt8) 	(work[0]>>24); 
				tempBlocks[4*j+1]= (UInt8) ((work[0]>>16)&0x000000FF);
				tempBlocks[4*j+2]= (UInt8) ((work[0]>>8)&0x000000FF); 
				tempBlocks[4*j+3]= (UInt8) (work[0]&0x000000FF);
				context->iv[0] = context->iv[1];
			   	if(context->encrypt==ENCRYPT)
				   	context->iv[1] = work[0] ^ inputBlock[j%2];
				else context->iv[1] = inputBlock[j%2];		   	
			   	}
		else {
				tempBlocks[0]= (UInt8) 	(work[0]>>24); 
				tempBlocks[1]= (UInt8) ((work[0]>>16)&0x000000FF);
				tempBlocks[2]= (UInt8) ((work[0]>>8)&0x000000FF); 
				tempBlocks[3]= (UInt8) (work[0]&0x000000FF);
				tempBlocks[4]= (UInt8) 	(work[1]>>24); 
				tempBlocks[5]= (UInt8) ((work[1]>>16)&0x000000FF);
				tempBlocks[6]= (UInt8) ((work[1]>>8)&0x000000FF); 
				tempBlocks[7]= (UInt8) (work[1]&0x000000FF);
				if(context->encrypt==ENCRYPT){
				context->iv[0] = work[0] ^ inputBlock[0];
			   	context->iv[1] = work[1] ^ inputBlock[1];
			   	}
			   	else
			   	{
			   	context->iv[0] = inputBlock[0];
			   	context->iv[1] = inputBlock[1];
			   	}
				}
		}
   	Pack (outputBlocks, &tempBlocks[0]);
   	inputBlock[0]^=outputBlocks[0];
   	inputBlock[1]^=outputBlocks[1];
    Unpack (&output[8*i], inputBlock);

  
  }
  
  /* Zeroize sensitive information.
  R_memset ((POINTER)inputBlock, 0, sizeof (inputBlock));
  R_memset ((POINTER)work, 0, sizeof (work));
  */
  return (0);
  }
  

  else return RE_LEN;
}


/***********************************************************************
 *
 * FUNCTION:    DES3_OFBISOUpdate
 *
 * DESCRIPTION: 3DES-OFB block update operation. Continues a 3DES-OFB encryption
 *  			operation.  Note:  If n is not equal to 1, 8, 16, 32, or 64
 *				an error will be returned.
 *
 * PARAMETERS: 
 *				DES_CTX *context: 	context 
 *				unsigned char *output: 	output block 
 *				unsigned char *input: 	input block 
 *				unsigned int len: 		length of input and output blocks 
 *
 *
 * RETURNED:    nothing
 *
 * REVISION HISTORY:
 *			Name	Date		Description
 *			----	----		-----------
 *			
 *
 ***********************************************************************/
int DES3_OFBISOUpdate (DES_CTX *context, unsigned char *output, unsigned char *input, unsigned long len)
{
  UInt32 inputBlock[2], work[2], outputBlocks[2];
  int i,j, rounds, maxlen, nbitshift;
  UInt8 tempBlocks[8];
  
  maxlen=len/8;
  rounds = 64/context->n;
  nbitshift = context->n;
  
  if ((nbitshift == 8) || (nbitshift == 16) || (nbitshift == 32) || (nbitshift == 64) || (nbitshift == 1)){
    
  for (i = 0; i < maxlen; i++) {
   
    Pack (inputBlock, &input[8*i]);
    
    for(j=0;j<8;j++) tempBlocks[j]=0;
    outputBlocks[0]=0;
    outputBlocks[1]=0;
   
    for(j=0; j < rounds ; j++){    
   		work[0] = context->iv[0];
   		work[1] = context->iv[1];
			
	    DESFunction(work, context->subkeys[0]);
	    DESFunction(work, context->subkeys[1]);
	    DESFunction(work, context->subkeys[2]);
		
	   	context->iv[0] = work[0];
	   	context->iv[1] = work[1];
		
		if(nbitshift==1){
				if(j<8) tempBlocks[0] =  tempBlocks[0] | (((UInt8) (work[0]>>31) &0x00000001) << (7-j)); 
				else if (j<16) tempBlocks[1] =  tempBlocks[1] | (((UInt8) (work[0]>>31) &0x00000001) <<(15-j)); 
				else if (j<24) tempBlocks[2] =  tempBlocks[2] | (((UInt8) (work[0]>>31) &0x00000001) <<(23-j)); 
				else if (j<32) tempBlocks[3] =  tempBlocks[3] | (((UInt8) (work[0]>>31) &0x00000001) <<(31-j));
				else if (j<40) tempBlocks[4] =  tempBlocks[4] | (((UInt8) (work[0]>>31) &0x00000001) <<(39-j));
				else if (j<48) tempBlocks[5] =  tempBlocks[5] | (((UInt8) (work[0]>>31) &0x00000001) <<(47-j));
				else if (j<56) tempBlocks[6] =  tempBlocks[6] | (((UInt8) (work[0]>>31) &0x00000001) <<(55-j)); 
				else tempBlocks[7] =  tempBlocks[7] | (((UInt8) (work[0]>>31) &0x00000001) <<(61-j));
			}
		else if(nbitshift == 8){  
				tempBlocks[j]= (UInt8) (work[0]>>24); 
				}
		else if (nbitshift == 16){
				tempBlocks[2*j]= (UInt8) (work[0]>>24); 
				tempBlocks[2*j+1]= (UInt8) ((work[0]>>16)&0x000000FF);
				}
		else if (nbitshift == 32){
				tempBlocks[4*j]= (UInt8) 	(work[0]>>24); 
				tempBlocks[4*j+1]= (UInt8) ((work[0]>>16)&0x000000FF);
				tempBlocks[4*j+2]= (UInt8) ((work[0]>>8)&0x000000FF); 
				tempBlocks[4*j+3]= (UInt8) (work[0]&0x000000FF);
				}
		else {
				tempBlocks[0]= (UInt8) 	(work[0]>>24); 
				tempBlocks[1]= (UInt8) ((work[0]>>16)&0x000000FF);
				tempBlocks[2]= (UInt8) ((work[0]>>8)&0x000000FF); 
				tempBlocks[3]= (UInt8) (work[0]&0x000000FF);
				tempBlocks[4]= (UInt8) 	(work[1]>>24); 
				tempBlocks[5]= (UInt8) ((work[1]>>16)&0x000000FF);
				tempBlocks[6]= (UInt8) ((work[1]>>8)&0x000000FF); 
				tempBlocks[7]= (UInt8) (work[1]&0x000000FF);
				}
		}
   	Pack (outputBlocks, &tempBlocks[0]);
   	inputBlock[0]^=outputBlocks[0];
   	inputBlock[1]^=outputBlocks[1];
    Unpack (&output[8*i], inputBlock);
  
  }
  
  /* Zeroize sensitive information.
  R_memset ((POINTER)inputBlock, 0, sizeof (inputBlock));
  R_memset ((POINTER)work, 0, sizeof (work));
  */
  return (0);
  }
  

  else return RE_LEN;
}

/***********************************************************************
 *
 * FUNCTION:    DES3_OFBFIPS81Update
 *
 * DESCRIPTION: 	DES3_OFB block update operation. Continues a DES3-OFB encryption
 *  				operation, processing eight-byte message blocks, and updating
 *  				the context.  Note it only works with 1, 8, 16, 32 and 64 bit
 *					blocks.
 *
 * PARAMETERS:
 *				DES3_CTX *context:	context 
 *				unsigned char *output:  output block 
 *				unsigned char *input:	input block 
 *				unsigned int len:		length of input and output blocks 
 *
 *
 * RETURNED:    0 if there is no problem
 *
 * REVISION HISTORY:
 *			Name	Date		Description
 *			----	----		-----------
 *			
 *
 ***********************************************************************/ 
int DES3_OFBFIPS81Update (DES_CTX *context, unsigned char *output, unsigned char *input, unsigned long len)
{
  UInt32 inputBlock[2], work[2], outputBlocks[2];
  int i,j, rounds, maxlen, nbitshift;
  UInt8 tempBlocks[8];
  
  maxlen=len/8;
  rounds = 64/context->n;
  nbitshift = context->n;
  
  if ((nbitshift == 8) || (nbitshift == 16) || (nbitshift == 32) || (nbitshift == 64) || (nbitshift == 1)){
    
  for (i = 0; i < maxlen; i++) {
   
    Pack (inputBlock, &input[8*i]);
    
    for(j=0;j<8;j++) tempBlocks[j]=0;
    outputBlocks[0]=0;
    outputBlocks[1]=0;
   
    for(j=0; j < rounds ; j++){    
   		work[0] = context->iv[0];
   		work[1] = context->iv[1];
			
	    DESFunction (work, context->subkeys[0]);
	    DESFunction (work, context->subkeys[1]);
	    DESFunction (work, context->subkeys[2]);
		
	   	
		
		if(nbitshift==1){
				if(j<8) tempBlocks[0] =  tempBlocks[0] | (((UInt8) (work[0]>>31) &0x00000001) << (7-j)); 
				else if (j<16) tempBlocks[1] =  tempBlocks[1] | (((UInt8) (work[0]>>31) &0x00000001) <<(15-j)); 
				else if (j<24) tempBlocks[2] =  tempBlocks[2] | (((UInt8) (work[0]>>31) &0x00000001) <<(23-j)); 
				else if (j<32) tempBlocks[3] =  tempBlocks[3] | (((UInt8) (work[0]>>31) &0x00000001) <<(31-j));
				else if (j<40) tempBlocks[4] =  tempBlocks[4] | (((UInt8) (work[0]>>31) &0x00000001) <<(39-j));
				else if (j<48) tempBlocks[5] =  tempBlocks[5] | (((UInt8) (work[0]>>31) &0x00000001) <<(47-j));
				else if (j<56) tempBlocks[6] =  tempBlocks[6] | (((UInt8) (work[0]>>31) &0x00000001) <<(55-j)); 
				else tempBlocks[7] =  tempBlocks[7] | (((UInt8) (work[0]>>31) &0x00000001) <<(61-j));
				context->iv[0] = (context->iv[0]<<1)| ((context->iv[1] >> 31) & 0x00000001);
			   	context->iv[1] = (context->iv[1]<<1)| ((work[0] >> 31) & 0x00000001);
			}
		else if(nbitshift == 8){  
				tempBlocks[j]= (UInt8) (work[0]>>24); 
				context->iv[0] = (context->iv[0]<<8)| ((context->iv[1] >> 24) & 0x000000FF);
			   	context->iv[1] = (context->iv[1]<<8)| ((work[0] >> 24) & 0x000000FF);
				}
		else if (nbitshift == 16){
				tempBlocks[2*j]= (UInt8) (work[0]>>24); 
				tempBlocks[2*j+1]= (UInt8) ((work[0]>>16)&0x000000FF);
				context->iv[0] = (context->iv[0]<<16)| ((context->iv[1] >> 16) & 0x0000FFFF);
			   	context->iv[1] = (context->iv[1]<<16)| ((work[0] >> 16) & 0x0000FFFF);
				}
		else if (nbitshift == 32){
				tempBlocks[4*j]= (UInt8) 	(work[0]>>24); 
				tempBlocks[4*j+1]= (UInt8) ((work[0]>>16)&0x000000FF);
				tempBlocks[4*j+2]= (UInt8) ((work[0]>>8)&0x000000FF); 
				tempBlocks[4*j+3]= (UInt8) (work[0]&0x000000FF);
				context->iv[0] = context->iv[1];
			   	context->iv[1] = work[0];
				}
		else {
				tempBlocks[0]= (UInt8) 	(work[0]>>24); 
				tempBlocks[1]= (UInt8) ((work[0]>>16)&0x000000FF);
				tempBlocks[2]= (UInt8) ((work[0]>>8)&0x000000FF); 
				tempBlocks[3]= (UInt8) (work[0]&0x000000FF);
				tempBlocks[4]= (UInt8) 	(work[1]>>24); 
				tempBlocks[5]= (UInt8) ((work[1]>>16)&0x000000FF);
				tempBlocks[6]= (UInt8) ((work[1]>>8)&0x000000FF); 
				tempBlocks[7]= (UInt8) (work[1]&0x000000FF);
				context->iv[0] = work[0];
			   	context->iv[1] = work[1];
				}
		}
   	Pack (outputBlocks, &tempBlocks[0]);
   	inputBlock[0]^=outputBlocks[0];
   	inputBlock[1]^=outputBlocks[1];
    Unpack (&output[8*i], inputBlock);

  
  }
  
  /* Zeroize sensitive information.
  R_memset ((POINTER)inputBlock, 0, sizeof (inputBlock));
  R_memset ((POINTER)work, 0, sizeof (work));
  */
  return (0);
  }
  

  else return RE_LEN;
}
/***********************************************************************
 *
 * FUNCTION:    DES3_CBCRestart
 *
 * DESCRIPTION: DES-CBC block Restart Operation.
 *
 * PARAMETERS: 
 *				DES3_CBC_CTX *context: 	context 
 *				
 *
 * RETURNED:    nothing
 *
 * REVISION HISTORY:
 *			Name	Date		Description
 *			----	----		-----------
 *			
 *
 ***********************************************************************/
void DES3_Restart (DES_CTX *context)
{
  /* Reset to the original IV */
  context->iv[0] = context->originalIV[0];
  context->iv[1] = context->originalIV[1];
}

/***********************************************************************
 *
 * FUNCTION:    Pack
 *
 * DESCRIPTION: 
 *
 * PARAMETERS: 
 *				UInt32 *into, 
 *				unsigned char *outof 
 *				
 *
 * RETURNED:    nothing
 *
 * REVISION HISTORY:
 *			Name	Date		Description
 *			----	----		-----------
 *			
 *
 ***********************************************************************/
static void Pack (UInt32 *into, unsigned char *outof)
{
  *into    = (*outof++ & 0xffL) << 24;
  *into   |= (*outof++ & 0xffL) << 16;
  *into   |= (*outof++ & 0xffL) << 8;
  *into++ |= (*outof++ & 0xffL);
  *into    = (*outof++ & 0xffL) << 24;
  *into   |= (*outof++ & 0xffL) << 16;
  *into   |= (*outof++ & 0xffL) << 8;
  *into   |= (*outof   & 0xffL);
}

static void Unpack (unsigned char *into, UInt32 *outof)
{
  *into++ = (unsigned char)((*outof >> 24) & 0xffL);
  *into++ = (unsigned char)((*outof >> 16) & 0xffL);
  *into++ = (unsigned char)((*outof >>  8) & 0xffL);
  *into++ = (unsigned char)( *outof++      & 0xffL);
  *into++ = (unsigned char)((*outof >> 24) & 0xffL);
  *into++ = (unsigned char)((*outof >> 16) & 0xffL);
  *into++ = (unsigned char)((*outof >>  8) & 0xffL);
  *into   = (unsigned char)( *outof        & 0xffL);
}

static void DESKey (UInt32 subkeys[], unsigned char key[], int encrypt)
{
  UInt32 kn[32];
  int i, j, l, m, n;
  unsigned char pc1m[56], pcr[56];
  UInt16 BYTE_BIT[8] = {	0200, 0100, 040, 020, 010, 04, 02, 01};
  UInt32 BIG_BYTE[24] = { 	0x800000L, 0x400000L, 0x200000L, 0x100000L,
  							0x80000L,  0x40000L,  0x20000L,  0x10000L,
  							0x8000L,   0x4000L,   0x2000L,   0x1000L,
  							0x800L,    0x400L,    0x200L,    0x100L,
  							0x80L,     0x40L,     0x20L,     0x10L,
  							0x8L,      0x4L,      0x2L,      0x1L
						};
  unsigned char PC1[56] = {	56, 48, 40, 32, 24, 16,  8,      0, 57, 49, 41, 33, 25, 17,
   							9,  1, 58, 50, 42, 34, 26,     18, 10,  2, 59, 51, 43, 35,
  							62, 54, 46, 38, 30, 22, 14,      6, 61, 53, 45, 37, 29, 21,
  							13,  5, 60, 52, 44, 36, 28,     20, 12,  4, 27, 19, 11,  3
						};
  unsigned char TOTAL_ROTATIONS[16] = { 1, 2, 4, 6, 8, 10, 12, 14, 15, 17, 19, 21, 23, 25, 27, 28};
						
  unsigned char PC2[48] = {	13, 16, 10, 23,  0,  4,  2, 27, 14,  5, 20,  9,
  							22, 18, 11,  3, 25,  7, 15,  6, 26, 19, 12,  1,
 							40, 51, 30, 36, 46, 54, 29, 39, 50, 44, 32, 47,
  							43, 48, 38, 55, 33, 52, 45, 41, 49, 35, 28, 31
							};
								
														
  for (j = 0; j < 56; j++) {
    l = PC1[j];
    m = l & 07;
    pc1m[j] = (unsigned char)((key[l >> 3] & BYTE_BIT[m]) ? 1 : 0);
  }
  for (i = 0; i < 16; i++) {
    m = i << 1;
    n = m + 1;
    kn[m] = kn[n] = 0L;
    for (j = 0; j < 28; j++) {
      l = j + TOTAL_ROTATIONS[i];
      if (l < 28)
        pcr[j] = pc1m[l];
      else
        pcr[j] = pc1m[l - 28];
    }
    for (j = 28; j < 56; j++) {
      l = j + TOTAL_ROTATIONS[i];
      if (l < 56)
        pcr[j] = pc1m[l];
      else
        pcr[j] = pc1m[l - 28];
    }
    for (j = 0; j < 24; j++) {
      if (pcr[PC2[j]])
        kn[m] |= BIG_BYTE[j];
      if (pcr[PC2[j+24]])
        kn[n] |= BIG_BYTE[j];
    }
  }
  CookKey (subkeys, kn, encrypt);

  /* Zeroize sensitive information.
  R_memset ((POINTER)pc1m, 0, sizeof (pc1m));
  R_memset ((POINTER)pcr, 0, sizeof (pcr));
  R_memset ((POINTER)kn, 0, sizeof (kn));
  */
}

static void CookKey (UInt32 *subkeys, UInt32 *kn, int encrypt)
{
  UInt32 *cooked, *raw0, *raw1;
  int increment;
  unsigned int i;

  raw1 = kn;
  cooked = encrypt ? subkeys : &subkeys[30];
  increment = encrypt ? 1 : -3;

  for (i = 0; i < 16; i++, raw1++) {
    raw0 = raw1++;
    *cooked    = (*raw0 & 0x00fc0000L) << 6;
    *cooked   |= (*raw0 & 0x00000fc0L) << 10;
    *cooked   |= (*raw1 & 0x00fc0000L) >> 10;
    *cooked++ |= (*raw1 & 0x00000fc0L) >> 6;
    *cooked    = (*raw0 & 0x0003f000L) << 12;
    *cooked   |= (*raw0 & 0x0000003fL) << 16;
    *cooked   |= (*raw1 & 0x0003f000L) >> 4;
    *cooked   |= (*raw1 & 0x0000003fL);
    cooked += increment;
  }
}

static void DESFunction (UInt32 *block, UInt32 *subkeys)
{
  UInt32 fval, work, right, left;
  int round;
  
  UInt32 SP1[64] = {	0x01010400L, 0x00000000L, 0x00010000L, 0x01010404L,
					  	0x01010004L, 0x00010404L, 0x00000004L, 0x00010000L,
						0x00000400L, 0x01010400L, 0x01010404L, 0x00000400L,
						0x01000404L, 0x01010004L, 0x01000000L, 0x00000004L,
						0x00000404L, 0x01000400L, 0x01000400L, 0x00010400L,
						0x00010400L, 0x01010000L, 0x01010000L, 0x01000404L,
						0x00010004L, 0x01000004L, 0x01000004L, 0x00010004L,
						0x00000000L, 0x00000404L, 0x00010404L, 0x01000000L,
						0x00010000L, 0x01010404L, 0x00000004L, 0x01010000L,
						0x01010400L, 0x01000000L, 0x01000000L, 0x00000400L,
						0x01010004L, 0x00010000L, 0x00010400L, 0x01000004L,
						0x00000400L, 0x00000004L, 0x01000404L, 0x00010404L,
						0x01010404L, 0x00010004L, 0x01010000L, 0x01000404L,
						0x01000004L, 0x00000404L, 0x00010404L, 0x01010400L,
						0x00000404L, 0x01000400L, 0x01000400L, 0x00000000L,
						0x00010004L, 0x00010400L, 0x00000000L, 0x01010004L
};

  UInt32 SP2[64] = {	0x80108020L, 0x80008000L, 0x00008000L, 0x00108020L,
  						0x00100000L, 0x00000020L, 0x80100020L, 0x80008020L,
  						0x80000020L, 0x80108020L, 0x80108000L, 0x80000000L,
  						0x80008000L, 0x00100000L, 0x00000020L, 0x80100020L,
  						0x00108000L, 0x00100020L, 0x80008020L, 0x00000000L,
  						0x80000000L, 0x00008000L, 0x00108020L, 0x80100000L,
  						0x00100020L, 0x80000020L, 0x00000000L, 0x00108000L,
						0x00008020L, 0x80108000L, 0x80100000L, 0x00008020L,
						0x00000000L, 0x00108020L, 0x80100020L, 0x00100000L,
						0x80008020L, 0x80100000L, 0x80108000L, 0x00008000L,
						0x80100000L, 0x80008000L, 0x00000020L, 0x80108020L,
						0x00108020L, 0x00000020L, 0x00008000L, 0x80000000L,
						0x00008020L, 0x80108000L, 0x00100000L, 0x80000020L,
						0x00100020L, 0x80008020L, 0x80000020L, 0x00100020L,
						0x00108000L, 0x00000000L, 0x80008000L, 0x00008020L,
						0x80000000L, 0x80100020L, 0x80108020L, 0x00108000L
					};

  UInt32 SP3[64] = {	0x00000208L, 0x08020200L, 0x00000000L, 0x08020008L,
						0x08000200L, 0x00000000L, 0x00020208L, 0x08000200L,
						0x00020008L, 0x08000008L, 0x08000008L, 0x00020000L,
						0x08020208L, 0x00020008L, 0x08020000L, 0x00000208L,
						0x08000000L, 0x00000008L, 0x08020200L, 0x00000200L,
						0x00020200L, 0x08020000L, 0x08020008L, 0x00020208L,
						0x08000208L, 0x00020200L, 0x00020000L, 0x08000208L,
						0x00000008L, 0x08020208L, 0x00000200L, 0x08000000L,
						0x08020200L, 0x08000000L, 0x00020008L, 0x00000208L,
						0x00020000L, 0x08020200L, 0x08000200L, 0x00000000L,
						0x00000200L, 0x00020008L, 0x08020208L, 0x08000200L,
						0x08000008L, 0x00000200L, 0x00000000L, 0x08020008L,
						0x08000208L, 0x00020000L, 0x08000000L, 0x08020208L,
						0x00000008L, 0x00020208L, 0x00020200L, 0x08000008L,
						0x08020000L, 0x08000208L, 0x00000208L, 0x08020000L,
						0x00020208L, 0x00000008L, 0x08020008L, 0x00020200L
					};

  UInt32 SP4[64] = {	0x00802001L, 0x00002081L, 0x00002081L, 0x00000080L,
						0x00802080L, 0x00800081L, 0x00800001L, 0x00002001L,
						0x00000000L, 0x00802000L, 0x00802000L, 0x00802081L,
						0x00000081L, 0x00000000L, 0x00800080L, 0x00800001L,
						0x00000001L, 0x00002000L, 0x00800000L, 0x00802001L,
						0x00000080L, 0x00800000L, 0x00002001L, 0x00002080L,
						0x00800081L, 0x00000001L, 0x00002080L, 0x00800080L,
						0x00002000L, 0x00802080L, 0x00802081L, 0x00000081L,
						0x00800080L, 0x00800001L, 0x00802000L, 0x00802081L,
						0x00000081L, 0x00000000L, 0x00000000L, 0x00802000L,
						0x00002080L, 0x00800080L, 0x00800081L, 0x00000001L,
						0x00802001L, 0x00002081L, 0x00002081L, 0x00000080L,
						0x00802081L, 0x00000081L, 0x00000001L, 0x00002000L,
						0x00800001L, 0x00002001L, 0x00802080L, 0x00800081L,
						0x00002001L, 0x00002080L, 0x00800000L, 0x00802001L,
						0x00000080L, 0x00800000L, 0x00002000L, 0x00802080L
					};

  UInt32 SP5[64] = {	0x00000100L, 0x02080100L, 0x02080000L, 0x42000100L,
						0x00080000L, 0x00000100L, 0x40000000L, 0x02080000L,
						0x40080100L, 0x00080000L, 0x02000100L, 0x40080100L,
						0x42000100L, 0x42080000L, 0x00080100L, 0x40000000L,
						0x02000000L, 0x40080000L, 0x40080000L, 0x00000000L,
						0x40000100L, 0x42080100L, 0x42080100L, 0x02000100L,
						0x42080000L, 0x40000100L, 0x00000000L, 0x42000000L,
						0x02080100L, 0x02000000L, 0x42000000L, 0x00080100L,
						0x00080000L, 0x42000100L, 0x00000100L, 0x02000000L,
						0x40000000L, 0x02080000L, 0x42000100L, 0x40080100L,
						0x02000100L, 0x40000000L, 0x42080000L, 0x02080100L,
						0x40080100L, 0x00000100L, 0x02000000L, 0x42080000L,
						0x42080100L, 0x00080100L, 0x42000000L, 0x42080100L,
						0x02080000L, 0x00000000L, 0x40080000L, 0x42000000L,
						0x00080100L, 0x02000100L, 0x40000100L, 0x00080000L,
						0x00000000L, 0x40080000L, 0x02080100L, 0x40000100L
};

  UInt32 SP6[64] = {	0x20000010L, 0x20400000L, 0x00004000L, 0x20404010L,
						0x20400000L, 0x00000010L, 0x20404010L, 0x00400000L,
						0x20004000L, 0x00404010L, 0x00400000L, 0x20000010L,
						0x00400010L, 0x20004000L, 0x20000000L, 0x00004010L,
						0x00000000L, 0x00400010L, 0x20004010L, 0x00004000L,
						0x00404000L, 0x20004010L, 0x00000010L, 0x20400010L,
						0x20400010L, 0x00000000L, 0x00404010L, 0x20404000L,
						0x00004010L, 0x00404000L, 0x20404000L, 0x20000000L,
						0x20004000L, 0x00000010L, 0x20400010L, 0x00404000L,
						0x20404010L, 0x00400000L, 0x00004010L, 0x20000010L,
						0x00400000L, 0x20004000L, 0x20000000L, 0x00004010L,
						0x20000010L, 0x20404010L, 0x00404000L, 0x20400000L,
						0x00404010L, 0x20404000L, 0x00000000L, 0x20400010L,
						0x00000010L, 0x00004000L, 0x20400000L, 0x00404010L,
						0x00004000L, 0x00400010L, 0x20004010L, 0x00000000L,
						0x20404000L, 0x20000000L, 0x00400010L, 0x20004010L
					};

  UInt32 SP7[64] = {	0x00200000L, 0x04200002L, 0x04000802L, 0x00000000L,
						0x00000800L, 0x04000802L, 0x00200802L, 0x04200800L,
						0x04200802L, 0x00200000L, 0x00000000L, 0x04000002L,
						0x00000002L, 0x04000000L, 0x04200002L, 0x00000802L,
						0x04000800L, 0x00200802L, 0x00200002L, 0x04000800L,
						0x04000002L, 0x04200000L, 0x04200800L, 0x00200002L,
						0x04200000L, 0x00000800L, 0x00000802L, 0x04200802L,
						0x00200800L, 0x00000002L, 0x04000000L, 0x00200800L,
						0x04000000L, 0x00200800L, 0x00200000L, 0x04000802L,
						0x04000802L, 0x04200002L, 0x04200002L, 0x00000002L,
						0x00200002L, 0x04000000L, 0x04000800L, 0x00200000L,
						0x04200800L, 0x00000802L, 0x00200802L, 0x04200800L,
						0x00000802L, 0x04000002L, 0x04200802L, 0x04200000L,
						0x00200800L, 0x00000000L, 0x00000002L, 0x04200802L,
						0x00000000L, 0x00200802L, 0x04200000L, 0x00000800L,
						0x04000002L, 0x04000800L, 0x00000800L, 0x00200002L
					};

  UInt32 SP8[64] = {	0x10001040L, 0x00001000L, 0x00040000L, 0x10041040L,
						0x10000000L, 0x10001040L, 0x00000040L, 0x10000000L,
						0x00040040L, 0x10040000L, 0x10041040L, 0x00041000L,
						0x10041000L, 0x00041040L, 0x00001000L, 0x00000040L,
						0x10040000L, 0x10000040L, 0x10001000L, 0x00001040L,
						0x00041000L, 0x00040040L, 0x10040040L, 0x10041000L,
						0x00001040L, 0x00000000L, 0x00000000L, 0x10040040L,
						0x10000040L, 0x10001000L, 0x00041040L, 0x00040000L,
						0x00041040L, 0x00040000L, 0x10041000L, 0x00001000L,
						0x00000040L, 0x10040040L, 0x00001000L, 0x00041040L,
						0x10001000L, 0x00000040L, 0x10000040L, 0x10040000L,
						0x10040040L, 0x10000000L, 0x00040000L, 0x10001040L,
						0x00000000L, 0x10041040L, 0x00040040L, 0x10000040L,
						0x10040000L, 0x10001000L, 0x10001040L, 0x00000000L,
						0x10041040L, 0x00041000L, 0x00041000L, 0x00001040L,
						0x00001040L, 0x00040040L, 0x10000000L, 0x10041000L
					};
  
  left = block[0];
  right = block[1];
  work = ((left >> 4) ^ right) & 0x0f0f0f0fL;
  right ^= work;
  left ^= (work << 4);
  work = ((left >> 16) ^ right) & 0x0000ffffL;
  right ^= work;
  left ^= (work << 16);
  work = ((right >> 2) ^ left) & 0x33333333L;
  left ^= work;
  right ^= (work << 2);
  work = ((right >> 8) ^ left) & 0x00ff00ffL;
  left ^= work;
  right ^= (work << 8);
  right = ((right << 1) | ((right >> 31) & 1L)) & 0xffffffffL;
  work = (left ^ right) & 0xaaaaaaaaL;
  left ^= work;
  right ^= work;
  left = ((left << 1) | ((left >> 31) & 1L)) & 0xffffffffL;
  
  for (round = 0; round < 8; round++) {
    work  = (right << 28) | (right >> 4);
    work ^= *subkeys++;
    fval  = SP7[ work        & 0x3fL];
    fval |= SP5[(work >>  8) & 0x3fL];
    fval |= SP3[(work >> 16) & 0x3fL];
    fval |= SP1[(work >> 24) & 0x3fL];
    work  = right ^ *subkeys++;
    fval |= SP8[ work        & 0x3fL];
    fval |= SP6[(work >>  8) & 0x3fL];
    fval |= SP4[(work >> 16) & 0x3fL];
    fval |= SP2[(work >> 24) & 0x3fL];
    left ^= fval;
    work  = (left << 28) | (left >> 4);
    work ^= *subkeys++;
    fval  = SP7[ work        & 0x3fL];
    fval |= SP5[(work >>  8) & 0x3fL];
    fval |= SP3[(work >> 16) & 0x3fL];
    fval |= SP1[(work >> 24) & 0x3fL];
    work  = left ^ *subkeys++;
    fval |= SP8[ work        & 0x3fL];
    fval |= SP6[(work >>  8) & 0x3fL];
    fval |= SP4[(work >> 16) & 0x3fL];
    fval |= SP2[(work >> 24) & 0x3fL];
    right ^= fval;
  }
  
  right = (right << 31) | (right >> 1);
  work = (left ^ right) & 0xaaaaaaaaL;
  left ^= work;
  right ^= work;
  left = (left << 31) | (left >> 1);
  work = ((left >> 8) ^ right) & 0x00ff00ffL;
  right ^= work;
  left ^= (work << 8);
  work = ((left >> 2) ^ right) & 0x33333333L;
  right ^= work;
  left ^= (work << 2);
  work = ((right >> 16) ^ left) & 0x0000ffffL;
  left ^= work;
  right ^= (work << 16);
  work = ((right >> 4) ^ left) & 0x0f0f0f0fL;
  left ^= work;
  right ^= (work << 4);
  *block++ = right;
  *block = left;
}

int Initialize_DES(unsigned char * key, unsigned char * iv, int desmode, int destype, int encrypt, DES_CTX * context)
{
context->destype = destype;
context->desmode = desmode;
switch(destype){
				case DES:
						DES_Init(context, key, iv, encrypt);break;
				case DESX: 
						DESX_Init(context, key, iv, encrypt);break;
				case DES3: 
						DES3_Init(context, key, iv, encrypt);break;	
				}
			return 0;		
}

int Decrypt_DES(DES_CTX *context , unsigned char * in, unsigned char * out, unsigned long size){
switch(context->destype){
				case DES: 
					switch(context->desmode){
						case ECB : 		DES_ECBUpdate(context, out, in, size);break;
						case CBC : 		DES_CBCUpdate(context, out, in, size);break;
						case CFB : 		DES_CFBUpdate(context, out, in, size);break;
						case OFBFIPS81:	DES_OFBFIPS81Update(context, out, in, size);break;
						case OFBISO :	DES_OFBISOUpdate(context, out, in, size);break;
						}
					break;
				case DESX: 
					switch(context->desmode){
						case ECB :	DESX_ECBUpdate(context, out, in, size);break;
						case CBC :	DESX_CBCUpdate(context, out, in, size);break;
						case CFB :	DESX_CFBUpdate(context, out, in, size);break;
						case OFBFIPS81:	DESX_OFBFIPS81Update(context, out, in, size);break;
						case OFBISO :	DESX_OFBISOUpdate(context, out, in, size);break;
						}
					break;
				case DES3: 
					switch(context->desmode){
						case ECB :	DES3_ECBUpdate(context, out, in, size);break;
						case CBC :	DES3_CBCUpdate(context, out, in, size);break;
						case CFB :	DES3_CFBUpdate(context, out, in, size);break;
						case OFBFIPS81:	DES_OFBFIPS81Update(context, out, in, size);break;
						case OFBISO :	DES_OFBISOUpdate(context, out, in, size);break;
						}
					break;	
				}
			return 0;		
}

int Encrypt_DES(DES_CTX * context, unsigned char * in, unsigned char * out, unsigned long size)
{
switch(context->destype){
				case DES: 
					switch(context->desmode){
						case ECB : 	DES_ECBUpdate(context, out, in, size);break;
						case CBC : 	DES_CBCUpdate(context, out, in, size);break;
						case CFB : 	DES_CFBUpdate(context, out, in, size);break;
						case OFBFIPS81:	DES_OFBFIPS81Update(context, out, in, size);break;
						case OFBISO :	DES_OFBISOUpdate(context, out, in, size);break;
						}
					break;
				case DESX: 
					switch(context->desmode){
						case ECB :	DESX_ECBUpdate(context, out, in, size);break;
						case CBC :	DESX_CBCUpdate(context, out, in, size);break;
						case CFB :	DESX_CFBUpdate(context, out, in, size);break;
						case OFBFIPS81:	DESX_OFBFIPS81Update(context, out, in, size);break;
						case OFBISO :	DESX_OFBISOUpdate(context, out, in, size);break;
						}
					break;
				case DES3: 
					switch(context->desmode){
						case ECB :	DES3_ECBUpdate(context, out, in, size);break;
						case CBC :	DES3_CBCUpdate(context, out, in, size);break;
						case CFB :	DES3_CFBUpdate(context, out, in, size);break;
						case OFBFIPS81:	DES_OFBFIPS81Update(context, out, in, size);break;
						case OFBISO :	DES_OFBISOUpdate(context, out, in, size);break;
						}
					break;	
				}
			return 0;	
			}