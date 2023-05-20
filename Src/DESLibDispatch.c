// *****
// * PROJECT:		MySharedLib (MSL)
// * FILENAME: 		MySharedLibDispatch.c
// * AUTHOR:		Jeff Ishaq 05/21/99
// * 
// * DESCRIPTION:	Installation routine for shared library's dispatch table.
// *
// *
// * HISTORY:		Hector Ho Fuentes 1/23/2001
// *
// *
// * COPYRIGHT:		As long as this 'copyright' is intact, this code is freely modifiable
// *				and distributable.
// *****

// Because we play with #defines that you're not normally expected to play with,
// we tend to run into cryptic link errors by including precompiled headers:
#ifndef PILOT_PRECOMPILED_HEADERS_OFF
	#define	PILOT_PRECOMPILED_HEADERS_OFF
#endif

#define EMULATION_LEVEL		EMULATION_NONE		// Force this to no emulation:

#undef 		__PALMOS_TRAPS__					// To prevent a redeclaration error
#define 	__PALMOS_TRAPS__ 	0				// Now, define this ourselves
#define		USE_TRAPS 			0				// To _make_ traps, we need to turn this off

#include <PalmOS.h>
#include "DESLib.h"

Err __Startup__( UInt16 uRefNum, SysLibTblEntryPtr entryP );
static MemPtr	asm DES_DispatchTable(void);

// *****
// * FUNCTION: 		__Startup__
// * 
// * DESCRIPTION:	Called to install the library by SysLibLoad().  You mustn't change
// *				the function's signature.
// *
// * PARAMETERS:	uRefNum		-		Lib refnum
// *				entryP		-		Ptr to our entry in the OS's lib table
// *
// * RETURNS:		Always 0.  I don't know why uses this return value, or if it's needed.
// *			
// * REVISION HISTORY:
// *	NAME	DATE		DESCRIPTION
// *    -------------------------------------------------------------------------------
// *	JeffI	05/19/99	Initial Implementation
// *****
Err __Startup__( UInt16 uRefNum, SysLibTblEntryPtr entryP )
{
	// Stash our dispatch table's address into the OS's shared libaray
	// table ptr slot that corresponds to this uRefNum:
	entryP->dispatchTblP = (MemPtr*) DES_DispatchTable();
	
	// Zero the globals ptr so that our call to MSLAllocGlobals() does the
	// right thing:
	entryP->globalsP = 0;

	return 0;
}

#define prvJmpSize	4				// How many bytes a JMP instruction occupies
#define NUMBER_OF_FUNCTIONS	7		// Don't forget to update this if necessary!!

#define TABLE_OFFSET 			2 * (NUMBER_OF_FUNCTIONS + 1)

#define DES_DISPATCH_SLOT(i)	(TABLE_OFFSET + ( (i) * prvJmpSize))

// *****
// * FUNCTION: 		MSL_DispatchTable
// * 
// * DESCRIPTION:	The actual dispatch table.  The linker will run through here and
// *				put the addresses of the JMP'd-to functions.
// *
// * RETURNS:		(Ptr)This
// *			
// * REVISION HISTORY:
// *	NAME	DATE		DESCRIPTION
// *    -------------------------------------------------------------------------------
// *	JeffI	05/19/99	Initial Implementation
// *****
static MemPtr	asm	DES_DispatchTable( void )
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

	LEA	@TableStart, A0
	RTS
	
@TableStart:
	DC.W		@LibName
	
	DC.W		DES_DISPATCH_SLOT(0)						// DESOpen()
	DC.W		DES_DISPATCH_SLOT(1)						// DESClose()
	DC.W		DES_DISPATCH_SLOT(2)						// DESSleep()
	DC.W		DES_DISPATCH_SLOT(3)						// DESWake()
	DC.W		DES_DISPATCH_SLOT(4)						// DESInitilize
	DC.W		DES_DISPATCH_SLOT(5)						// DESTrapEncrypt
	DC.W		DES_DISPATCH_SLOT(6)						// DESTrapDecrypt
	
	
	JMP			DESOpen									// 0
	JMP			DESClose								// 1
	JMP 		DESSleep								// 2
	JMP			DESWake									// 3
	JMP			DESInitialize							// 4
	JMP			DESEncrypt								// 5
	JMP			DESDecrypt								// 6
	
	
@LibName:
	DC.B		DES_LIB_NAME								// SysLibFind()'s name key
}