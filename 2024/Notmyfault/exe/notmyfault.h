//======================================================================
//
// NotMyFault.h
//
// Copyright (C) 2002 Mark Russinovich
// Sysinternals - www.sysinternals.com
//
// Simple interface to myfault device driver.
// 
//======================================================================


#define	SYS_FILE			"MYFAULT.SYS"
#define	SYS_NAME			"MYFAULT"

#define MYFAULT_DRIVER_KEY	"System\\CurrentControlSet\\Services\\Myfault"

extern HANDLE		SysHandle;


BOOL LoadDeviceDriver( const char * Name, const char * Path, 
					  HANDLE * lphDevice, PDWORD Error );
BOOL UnloadDeviceDriver( const char * Name );
