// *****
// * PROJECT:		DESLib (DES)
// * FILENAME: 		DESLib.h
// * AUTHOR:		Hector Ho Fuentes
// * Version:   0.1
// *
// *				DES created by International Business Machines Corporation
// * 
// * DESCRIPTION:	DES Shared library functionality interface definition
// *
// *
// * HISTORY:		Hector Ho Fuentes 4/4/2001
// *
// *
// * COPYRIGHT:		
// *
// *****

// *****
// * PROJECT:		MySharedLib (MSL)
// * FILENAME: 		MySharedLib.h
// * AUTHOR:		Jeff Ishaq 05/21/99
// * 
// * DESCRIPTION:	Shared library functionality interface definition
// *
// * COPYRIGHT:		As long as this 'copyright' is intact, this code is freely modifiable
// *				and distributable.
// *****
#pragma once

// Use this for SysLibFind calls.  This is what we 'name' our dispatch table, too:
#define DES_LIB_NAME	"DESLibrary"
#define DES_LIB_CREATOR	'HDES'		 						// Register this with Palm

// DES Types
#define DES  	1		//DES
#define DESX 	2		//DESX
#define DES3 	3		//Triple DES

//DES Modes
#define ECB			1		//ELECTRONIC CODEBOOK MODE
#define CBC			2		//CIPHER BLOCK CHAINING MODE
#define CFB			3		//CIPHER FEEDBACK MODE FIPS PUB 81 for only 1, 8, 16, 32 and 64 bits
#define OFBISO		4		//OUTPUT FEEDBACK MODE ISO 10116 for only 1, 8, 16, 32 and 64 bits
#define OFBFIPS81	5		//OUTPUT FEEDBACK MODE FIPS PUB 81 for only 1, 8, 16, 32 and 64 bits.
#define ENCRYPT 1
#define DECRYPT 0

// These are possible error types that DES might return:
typedef enum tagDESErrEnum
{
	DESErrNone 			= 0,			
	DESErrParam			= -1,
	DESErrNoGlobals		= -2,

	/////
	// Your custom return codes go here...
	/////
	DESErrKeySize			= -3
	
} DESErr;

// These are DES's trap identifiers.  The PalmOS constant 'sysLibTrapCustom' is
// the first trap number we can use after open, close, sleep, and wake.
typedef enum tagDESTrapNumEnum
{
	/////
	// - Trap modification checklist -
	// 
	// If you add or remove or otherwise modify something here, be sure you've
	// also done all of the following steps!
	//
	// 0) All trap identifiers must always run sequentially; no gaps!
	// 1) Modify the DESTrapNumEnum in MySharedLib.h
	// 2) Modify the DC.W to DES_DispatchTable() in MySharedLibDispatch.c (no gaps!)
	// 3) Modify the JMP in DES_DispatchTable() in MySharedLibDispatch.c (no gaps!)
	// 4) ** Update NUMBER_OF_FUNCTIONS in MySharedLibDispatch.c ** (0-based)
	// 5) Add or remove an "extern MyFunc(...) SYS_TRAP(DESTrapMyFunc)" prototype somewhere
	//
	/////

	DESTrapDESInitialize = sysLibTrapCustom,		// libDispatchEntry(4)
	DESTrapDESEncrypt,								// libDispatchEntry(5)
	DESTrapDESDecrypt								// libDispatchEntry(6)
} DESTrapNumEnum;

typedef struct{
	int desmode;										 /* ECB, CBC, CFB, OFB */	
	int destype;											/* DES, DESX, DES3 */
	int n;								/*a number between 1 and 64 for OFB and  between 1 and 63 for CFB*/ 	
	UInt32 subkeys[3][32];                            /* 3 subkeys due to DES3 */
  UInt32 iv[2];                                       /* initializing vector */
  UInt32 inputWhitener[2];                                 /* input whitener */
  UInt32 outputWhitener[2];                               /* output whitener */
  UInt32 originalIV[2];                        /* for restarting the context */
  int encrypt; 
}DES_CTX;

#ifdef __cplusplus
extern "C" {
#endif

// These are the four required entry points:
extern DESErr	DESOpen	( UInt16 uRefNum )						SYS_TRAP ( sysLibTrapOpen);
extern DESErr	DESClose( UInt16 uRefNum, UInt32* dwRefCountP )	SYS_TRAP ( sysLibTrapClose);
extern Err		DESSleep( UInt16 uRefNum )						SYS_TRAP ( sysLibTrapSleep);
extern Err		DESWake	( UInt16 uRefNum )						SYS_TRAP ( sysLibTrapWake	);

// Here are the actual functions we want the library to extend to callers.
extern DESErr	DESInitialize(UInt16 refNum, unsigned char *keystring, unsigned char *iv, int desmode, int destype, int encrypt, DES_CTX *key) 
				SYS_TRAP(DESTrapDESInitialize);
				
extern Int16	DESEncrypt(UInt16 refNum, DES_CTX * key, unsigned char * in, unsigned char * out, unsigned long size) 
				SYS_TRAP(DESTrapDESEncrypt);
				
extern Int16 	DESDecrypt(UInt16 refNum, DES_CTX * key, unsigned char * in, unsigned char * out, unsigned long size) 
				SYS_TRAP(DESTrapDESDecrypt);
				
#ifdef __cplusplus
}
#endif
