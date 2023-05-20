// *****
// * PROJECT:		DESLib (DES)
// * FILENAME: 		DESLibPrv.h
// * AUTHOR:		Hector Ho Fuentes
// *
// *				
// * 
// * DESCRIPTION:	Shared library functionality interface definition for PRIVATE
// *				functions.  These should be used to build a library, but should
// *				not be distributed with that library; instead, just distribute
// *				MySharedLib.h
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
// * FILENAME: 		MySharedLibPrv.h
// * AUTHOR:		Jeff Ishaq 05/21/99
// * 
// * DESCRIPTION:	Shared library functionality interface definition for PRIVATE
// *				functions.  These should be used to build a library, but should
// *				not be distributed with that library; instead, just distribute
// *				MySharedLib.h
// *
// * COPYRIGHT:		As long as this 'copyright' is intact, this code is freely modifiable
// *				and distributable.
// *****

#pragma once

// This is the Globals struct that we use throughout our library.
typedef struct tagDESGlobalsType
{
	Int16		iOpenCount;				// Our internal open-count of the lib
	
	/////
	// Your globals go here...
	/////

} DESGlobalsType;

typedef DESGlobalsType*	DESGlobalsTypePtr;

// These are some utility functions.  We don't actually use these in our dispatch
// table, so we don't need to define traps for them nor extern them.
DESGlobalsTypePtr	DESAllocGlobals	( UInt16 uRefNum );
DESGlobalsTypePtr	DESLockGlobals	( UInt16 uRefNum );
Err 				DESFreeGlobals	( UInt16 uRefNum );
Err					DESUnlockGlobals( DESGlobalsTypePtr gP );

// *****
// * DES functions:	
// *
// *****

void DES_Init(DES_CTX *, unsigned char *, unsigned char *, int);

int DES_ECBUpdate(DES_CTX *, unsigned char *, unsigned char *, unsigned long);

int DES_CBCUpdate(DES_CTX *, unsigned char *, unsigned char *, unsigned long);

int DES_CFBUpdate(DES_CTX *, unsigned char *, unsigned char *, unsigned long);

int DES_OFBFIPS81Update(DES_CTX *, unsigned char *, unsigned char *, unsigned long);

int DES_OFBISOUpdate(DES_CTX *, unsigned char *, unsigned char *, unsigned long);

void DES_Restart(DES_CTX *);

void DESX_Init(DES_CTX *, unsigned char *, unsigned char *, int);

int DESX_ECBUpdate(DES_CTX *, unsigned char *, unsigned char *, unsigned long);

int DESX_CBCUpdate(DES_CTX *, unsigned char *, unsigned char *, unsigned long);

int DESX_CFBUpdate(DES_CTX *, unsigned char *, unsigned char *, unsigned long);

int DESX_OFBISOUpdate(DES_CTX *, unsigned char *, unsigned char *, unsigned long);

int DESX_OFBFIPS81Update(DES_CTX *, unsigned char *, unsigned char *, unsigned long);

void DESX_Restart(DES_CTX *);

void DES3_Init(DES_CTX *, unsigned char *, unsigned char *, int);

int DES3_ECBUpdate(DES_CTX *, unsigned char *, unsigned char *, unsigned long);

int DES3_CBCUpdate(DES_CTX *, unsigned char *, unsigned char *, unsigned long);

int DES3_CFBUpdate(DES_CTX *, unsigned char *, unsigned char *, unsigned long);

int DES3_OFBFIPS81Update(DES_CTX *, unsigned char *, unsigned char *, unsigned long);

int DES3_OFBISOUpdate(DES_CTX *, unsigned char *, unsigned char *, unsigned long);

void DES3_Restart(DES_CTX *);

int Initialize_DES(unsigned char * keystring, unsigned char * iv, int desmode, int destype, int encrypt, DES_CTX * key);

int Encrypt_DES(DES_CTX *, unsigned char *, unsigned char *, unsigned long);

int Decrypt_DES(DES_CTX *, unsigned char *, unsigned char *, unsigned long);

