// *****
// * PROJECT:		SSC2Lib (SSC2)
// * FILENAME: 		SSC2Lib.c
// * AUTHOR:		Hector Ho Fuentes
// * 
// * DESCRIPTION:	SSC2 library functionality implementation.  
// *
// *
// * HISTORY:		Hector Ho Fuentes 1/23/2001
// *
// *
// * COPYRIGHT:		
// *
// *****


// *****
// * PROJECT:		MySharedLib (MSL)
// * FILENAME: 		MySharedLib.c
// * AUTHOR:		Jeff Ishaq 05/21/99
// * 
// * DESCRIPTION:	Shared library functionality implementation.  This code is influenced
// *				by the design outlined in Palm's "Shared Libraries and Other Advanced 
// *				Project Types" white paper, article #1143.  This can be found on Palm's
// *				knowledge base.
// *
// * COPYRIGHT:		As long as this 'copyright' is intact, this code is freely modifiable
// *				and distributable.
// *****

// Because we play with #defines that you're not normally expected to play with,
// we tend to run into cryptic link errors by including precompiled headers:

#ifndef PILOT_PRECOMPILED_HEADERS_OFF
	#define	PILOT_PRECOMPILED_HEADERS_OFF
#endif

#include <PalmOS.h>											// Standard Palm stuff
#include "DESLib.h"									// Our interface definition
#include "DESLibPrv.h"									// Private routiens (globals stuff)
 

#pragma mark - 
// Utility functions for globals structure access

// *****
// * FUNCTION: 		DESAllocGlobals
// * 
// * DESCRIPTION:	Allocate AND LOCK library globals ptr for a given RefNum
// *
// * PARAMETERS:	uRefNum		-		Lib refnum whose globals we'll create
// *			
// * RETURNED:		Ptr to new globals		-	success
// *				NULL					-	failure, MemHandleNew failed (!)
// *
// * POSTCONDITION:	Since this routine locks the handle it returns if successful, the
// *				caller is responsible for calling DESUnlockGlobals() when s/he is done.
// *				Remember, the sooner you do this, the more you prevent heap fragmentation.
// *
// * REVISION HISTORY:
// *	NAME	DATE		DESCRIPTION
// *    -------------------------------------------------------------------------------
// *	JeffI	05/18/99	Initial Implementation
// *****
DESGlobalsTypePtr DESAllocGlobals( UInt16 uRefNum )
{

	DESGlobalsTypePtr		gP = NULL;
	SysLibTblEntryPtr		sysLibEntryP;
	MemHandle				gH = NULL;
	
	ErrFatalDisplayIf(sysInvalidRefNum == uRefNum, "Invalid refnum.");

	// Fetch a ptr to our lib's table entry in the OS's array (refnum is index)
	sysLibEntryP = SysLibTblEntry( uRefNum );
	ErrFatalDisplayIf( NULL == sysLibEntryP, "Invalid refnum.");
	ErrFatalDisplayIf( sysLibEntryP->globalsP, "Lib globals ptr already exists.");
	
	gH = MemHandleNew( sizeof(DESGlobalsType) );				// Alloc mem for globals here
	if ( !gH )
		return ( NULL );
		
	sysLibEntryP->globalsP = (void*)gH;							// Store handle in lib entry
	
	gP = (DESGlobalsTypePtr) DESLockGlobals( uRefNum );			
	ErrFatalDisplayIf( !gP, "Unable to lock lib globals ptr.");

	// We need to set the owner of this chunk to 'system'.  If we don't do this, then
	// the memory manager will automatically free this when the first application to
	// call DESOpen() exits.  Since we intend this library (and its globals) to hang around
	// regardless of which app begins and exits, we need to do this:
	MemPtrSetOwner( gP, 0 );									// 0 == OS
	
	MemSet( gP, sizeof(DESGlobalsType), 0 );					// Clean it out

	// Globals should be initialized in your lib's Open entry point... see DESOpen()
	return ( gP );
}


// *****
// * FUNCTION: 		DESFreeGlobals
// * 
// * DESCRIPTION:	Deallocate a lib's globals ptr, given its RefNum.
// *
// * PARAMETERS:	uRefNum		-		Lib refnum whose globals we'll deallocate
// *			
// * RETURNED:		ErrNone					-	MemHandleNew success
// *				!0						-	failure, MemHandleNew failed 
// *
// * REVISION HISTORY:
// *	NAME	DATE		DESCRIPTION
// *    -------------------------------------------------------------------------------
// *	JeffI	05/18/99	Initial Implementation
// *****
Err DESFreeGlobals( UInt16 uRefNum )
{
	SysLibTblEntryPtr		sysLibEntryP;
	MemHandle				gH = NULL;
	
	ErrFatalDisplayIf( sysInvalidRefNum == uRefNum, "Invalid refnum.");
	
	sysLibEntryP = SysLibTblEntry( uRefNum );
	ErrFatalDisplayIf( NULL == sysLibEntryP, "Invalid refnum.");
	
	gH = (MemHandle) (sysLibEntryP->globalsP);					// Get our globals handle
	ErrFatalDisplayIf(!gH, "Lib globals ptr does not exist.");

	sysLibEntryP->globalsP = NULL;
	return( MemHandleFree(gH) );
}

// *****
// * FUNCTION: 		DESLockGlobals
// * 
// * DESCRIPTION:	Return a ptr to a particular lib's DESGlobalsType structure
// *
// * PARAMETERS:	uRefNum		-		Lib refnum whose globals we'll lock
// *			
// * RETURNED:		0			-		Caller needs to allocate them first with DESAllocGlobals()!
// *				Valid ptr	-		success
// *
// * POSTCONDITION:	If I return 0, the caller needs to DESAllocGlobals().
// *
// * REVISION HISTORY:
// *	NAME	DATE		DESCRIPTION
// *    -------------------------------------------------------------------------------
// *	JeffI	05/18/99	Initial Implementation
// *****
DESGlobalsTypePtr DESLockGlobals( UInt16 uRefNum )
{
	DESGlobalsTypePtr		gP 				= NULL;						// Necessary!
	SysLibTblEntryPtr		sysLibEntryP 	= NULL;
	MemHandle				gH				= NULL;
	
	ErrFatalDisplayIf( sysInvalidRefNum == uRefNum, "Invalid refnum.");
	
	sysLibEntryP = SysLibTblEntry( uRefNum );
	ErrFatalDisplayIf( NULL == sysLibEntryP, "Invalid refnum.");
	
	gH = (MemHandle) (sysLibEntryP->globalsP);

	// We don't ErrFatalDisplay here if !gH.  This is so the caller can check the return
	// value and if it's null, the caller knows s/he needs to DESAllocGlobals(), similar
	// to the behavior of SysLibFind() and SysLibLoad()ing something.
	if (gH)
	{
		gP = (DESGlobalsTypePtr)MemHandleLock( gH );
	}
	
	// Notice we want to return NULL if this handle hasn't yet been allocated!
	
	return gP;
}

// *****
// * FUNCTION: 		DESUnlockGlobals
// * 
// * DESCRIPTION:	Unlock a ptr to a DESGlobalsType structure
// *
// * PRECONDITION:	gP has been locked down by a call to DESLoclGlobals.
// *
// * PARAMETERS:	gP			-		Locked ptr to structure
// *			
// * RETURNED:		!0			-		MemPtrUnlock failure (!)
// *				ErrNone		-		MemPtrUnlock success
// *
// * REVISION HISTORY:
// *	NAME	DATE		DESCRIPTION
// *    -------------------------------------------------------------------------------
// *	JeffI	05/18/99	Initial Implementation
// *****
Err DESUnlockGlobals( DESGlobalsTypePtr gP )
{
	return( MemPtrUnlock(gP) );											// No magic here..
}



#pragma mark -
// OS-Required entry point implementations:

// *****
// * FUNCTION: 		DESOpen
// * 
// * DESCRIPTION:	Open DES; alloc globals if necessary
// *
// * PRECONDITION:	Caller has already done a SysLibFind and SysLibLoad to get refnum
// *
// * PARAMETERS:	uRefNum		-		Lib refnum 
// *			
// * RETURNED:		DESErrNone			-	success
// *				DESErrNoGlobals		-   unable to allocate globals
// *
// * POSTCONDITION:	Caller should DESClose() this lib as soon as s/he is done using it.
// *				Multiple DESOpens() are ok, but each one should always have a 
// *				correspoding DESClose() to balance it out.
// *
// * REVISION HISTORY:
// *	NAME	DATE		DESCRIPTION
// *    -------------------------------------------------------------------------------
// *	JeffI	05/19/99	Initial Implementation
// *****
DESErr DESOpen( UInt16 uRefNum )
{
	Err						err;
	DESGlobalsTypePtr		gP = NULL;
	
	// Allocate globals
	ErrFatalDisplayIf( sysInvalidRefNum == uRefNum, "Invalid refnum.");
	
	gP = DESLockGlobals( uRefNum );
	
	// If this returns NULL, that means we need to allocate the globals.  This also
	// implies that this is the first time we've opened this shared library.  
	if ( !gP )
	{
		gP = DESAllocGlobals( uRefNum );
		if ( !gP )
			return DESErrNoGlobals;
			
		// Initialize globals here:
		gP->iOpenCount = 1;

		// Dump diagnostic info, i.e. "DES ref# %d initially opened; globals initialized.\n", uRefNum
	}
	else
		gP->iOpenCount++;
		
	err = DESUnlockGlobals( gP );
	ErrFatalDisplayIf( err, "Unable to unlock lib globals.");			
	
	return DESErrNone;
}

// *****
// * FUNCTION: 		DESClose
// * 
// * DESCRIPTION:	Close DES; free globals if necessary
// *
// * PARAMETERS:	uRefNum			-				Lib refnum 
// *				dwRefCountP		- (Modified)	DWord into which we put the open count
// *			
// * RETURNED:		DESErrNone		-	success
// *				DESErrNoGlobals	-	Unable to lock down the globals, this is bad
// *
// * POSTCONDITION:	Caller should ALWAYS check dwRefCount upon successful return.  If it's
// *				zero, caller should SysLibRemove() this library as it's no longer in use.
// *
// * REVISION HISTORY:
// *	NAME	DATE		DESCRIPTION
// *    -------------------------------------------------------------------------------
// *	JeffI	05/19/99	Initial Implementation
// *****
DESErr DESClose( UInt16 uRefNum, UInt32* dwRefCountP )
{
	Err						err;
	DESGlobalsTypePtr		gP = NULL;
	
	ErrFatalDisplayIf( sysInvalidRefNum == uRefNum, "Invalid refnum.");
	
	if ( !dwRefCountP )														// Validate param
		return DESErrParam;
		
	gP = DESLockGlobals ( uRefNum );
	if ( !gP )
		return DESErrNoGlobals;
	
	gP->iOpenCount--;
	ErrNonFatalDisplayIf( gP->iOpenCount < 0, "Library globals underlock." );

	*dwRefCountP = gP->iOpenCount;
		
	DESUnlockGlobals( gP );

	if ( *dwRefCountP <= 0 )		// Use this instead of gP->iOpenCount, since we just
	{								// unlocked gp!
		// Dump diagnostic info i.e.  "DES ref# %d closed; globals freed.", uRefNum		
		err = DESFreeGlobals( uRefNum );								
		ErrFatalDisplayIf( err, "Unable to free lib globals.");
	}
	
	return DESErrNone;
}

// *****
// * FUNCTION: 		DESSleep
// * 
// * DESCRIPTION:	Called when device goes to sleep.  Since this routine can sometimes be
// *				called from an interrupt handler, you can never spend a lot of time in 
// *				this routine or else you'll make the system unstable and probably cause
// *				mysterious crashes.  In addition, this routine is called as a result of
// *				a battery pull situation; in that case, the Palm is running off of its
// *				super cap, which means there's about 1 ms of processor time remaining
// *				before there is no power.  To avoid catastrophic failure, you and any
// *				other installed shared libraries had better not take up too many cycles
// *				in their respective Sleep function!!
// *
// * PARAMETERS:	uRefNum		-		Lib refnum
// *			
// * RETURNS:		Always 0.  I don't know who uses this return value, or if it's needed.
// *
// * REVISION HISTORY:
// *	NAME	DATE		DESCRIPTION
// *    -------------------------------------------------------------------------------
// *	JeffI	05/19/99	Initial Implementation
// *****
Err DESSleep( UInt16 uRefNum )
{
	// If you were implementing custom hardware, you'd do something like
	// this to put it to sleep to conserve power, and to prevent it from
	// sapping the super cap in the event of a battery pull:

	#ifdef MY_HARDWARE_INSTALLED	// ... fictitious example #define ...
		// Tell MyHardware to power down, and then return ASAP!
		MyHardwareBaseAddr->pwrCtlReg |= SLEEP_MODE;
	#endif
	
	return 0;
}


// *****
// * FUNCTION: 		DESWake
// * 
// * DESCRIPTION:	Called when device wakes up from sleep.  Since this routine is sometimes
// *				called from an interrupt handler, you can never spend a lot of time in 
// *				this routine or else you'll make the system unstable and probably cause
// *				mysterious crashes.  If you have a time-consuming chore to do, consider
// *				using an interrupt-safe routine like EvtEnqueueKey() to set a flag.  In
// *				an EvtGetEvent hook, you can see this flag come through.  Since you're no
// *				longer in an intrreupt handler, you can do your time-consuming chore at 
// *				that time.
// *
// * PARAMETERS:	uRefNum		-		Lib refnum
// *
// * RETURNS:		Always 0.  I don't know why uses this return value, or if it's needed.
// *			
// * REVISION HISTORY:
// *	NAME	DATE		DESCRIPTION
// *    -------------------------------------------------------------------------------
// *	JeffI	05/19/99	Initial Implementation
// *****
Err DESWake( UInt16 uRefNum )
{
	// If you were implementing custom hardware, you'd do something like
	// this to wake your hardware back up:

	#ifdef MY_HARDWARE_INSTALLED	// ... fictitious example #define ...
		// Tell MyHardware to wake up from sleep mode
		MyHardwareBaseAddr->pwrCtlReg &= ~SLEEP_MODE;
	#endif
	
	return 0;
}


#pragma mark -
// Custom lib function implementation.  These are the extern'd functions.

/***********************************************************************
 *
 * FUNCTION:    DESInitialize
 *
 * DESCRIPTION: This routine Initializes DES.
 *
 * PARAMETERS: 
 *				UInt refNum:				A reference number 
 *				unsigned char * keystring:  A string that contains the key. 
 *				unsigned char * iv:			The Initialization Vector
 *				int desmode: 				EBC, CBC, CFB, OFB 
 *				int destype:				DES, DESX, DES3 (triple DES)
 *				int encrypt, 
 *				DES_CTX * key 
 * RETURNED:   .
 *
 *
 *
 * REVISION HISTORY:
 *			Name	Date		Description
 *			----	----		-----------
 *		
 *
 ***********************************************************************/
 
extern DESErr DESInitialize(UInt16 refNum, unsigned char * keystring, unsigned char * iv, int desmode, int destype, int encrypt, DES_CTX * key) 
{
	Initialize_DES(keystring, iv, desmode, destype, encrypt, key); 
	return DESErrNone;
}


/***********************************************************************
 *
 * FUNCTION:    DESEncryptDES
 *
 * DESCRIPTION: This routine encrypts a string using DES.
 *
 * PARAMETERS: 
 *				UInt refNum:  			A reference number 
 *				unsigned char * in:	 	pointer to plaintext
 *				unsigned char * out:	ciphertext
 *				unsigned long size: 	size of data in bytes.
 *
 * RETURNED:    error if found
 *
 * REVISION HISTORY:
 *			Name	Date		Description
 *			----	----		-----------
 *		
 *
 ***********************************************************************/

extern Int16	DESEncrypt
(UInt16 refNum, DES_CTX * key, unsigned char * in, unsigned char * out, unsigned long size)
{
	Encrypt_DES(key, in, out, size);
	return 1;
}	

/***********************************************************************
 *
 * FUNCTION:    DESDecryptDES
 *
 * DESCRIPTION: This routine Decrypts a string using DES.
 *
 * PARAMETERS: 
 *				UInt refNum:  			A reference number 
 *				unsigned char * in: 	pointer to data to cipertext
 *				unsigned char * out:	plaintext
 *				unsigned long size: 	size of data in bytes.
 *
 * RETURNED:    error if found
 *
 * REVISION HISTORY:
 *			Name	Date		Description
 *			----	----		-----------
 *		
 *
 ***********************************************************************/
extern Int16 DESDecrypt
	(UInt16 refNum, DES_CTX * key, unsigned char * in, unsigned char * out, unsigned long size)
{
	Decrypt_DES(key, in, out, size);
	return 1;
}	