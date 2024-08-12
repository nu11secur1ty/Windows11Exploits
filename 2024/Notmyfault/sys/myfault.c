//----------------------------------------------------------------------
//
// Myfault
// 
// Copyright (C) 2002 Mark Russinovich
// Sysinternals - www.sysinternals.com
//
// Crash demonstration driver.
//
// * buffer overflow
// * wild pointer
// * paged pool at high irql
// * deadlock
// * trash stack
// * set callback and then unload
//
//----------------------------------------------------------------------
#include "ntddk.h"
#include "..\exe\ioctlcmd.h"


//----------------------------------------------------------------------
//
// DeadLock
//
// Try to grab a fast mutext when we already own it so that there's a 
// deadlock. This can be debugged with CrashOnCtrlScroll and then 
// using the ~ debugger command to look at the thread stack on each CPU. 
// The XP Verifier's deadlock detection catches this.
//
//----------------------------------------------------------------------
FAST_MUTEX     Fmutex;

VOID
DeadLock(
    VOID 
    )
{
    KIRQL   prevIrql1, prevIrql2;

    ExInitializeFastMutex( &Fmutex );
    ExAcquireFastMutex( &Fmutex );
    ExAcquireFastMutex( &Fmutex );
}


//----------------------------------------------------------------------
//
// Hang
// 
// This causes the execution of a DPC that stalls the system
// by executing in an infinite loop at raised IRQL.
//
//----------------------------------------------------------------------
KDPC  HangDpc;

VOID
HangDpcRoutine(
    PKDPC Dpc,
    PVOID Context, 
    PVOID SystemArgument1,
    PVOID SystemArgument2
    )
{
    while( 1 );
}

VOID
Hang(
    VOID 
    )
{
    CCHAR  i;

#if AMD64
	for( i = 0; i < KeNumberProcessors; i++ ) {
#else
    for( i = 0; i < *KeNumberProcessors; i++ ) {
#endif


		KeInitializeDpc( &HangDpc, 
						 HangDpcRoutine, 
						 NULL );
		KeSetTargetProcessorDpc(&HangDpc, i );
			KeInsertQueueDpc( &HangDpc,
						  NULL, NULL );
    }
}

//----------------------------------------------------------------------
//
// HangIrp
//
// Never completes the IRP, resulting in an unkillable process.
//
//----------------------------------------------------------------------
VOID
HangIrp(
    VOID
    )
{
    //
    // This can't be on the stack because the stack is pageable
    // when the thread performs a user-mode wait
    //
    static KEVENT event;

    KeInitializeEvent( &event, SynchronizationEvent, FALSE );
    KeWaitForSingleObject( &event, UserRequest, UserMode, FALSE, NULL );
}


//----------------------------------------------------------------------
//
// PageFault
//
// Fault at high IRQL in user-mode. This is virtually impossible to
// debug, but Verifier with IRQL checking on XP catches it.
//
//----------------------------------------------------------------------
VOID
PageFault(
    VOID 
    )
{
    KIRQL  prevIrql;

    KeRaiseIrql( DISPATCH_LEVEL, &prevIrql );
}


//----------------------------------------------------------------------
//
// IrqlFault
//
// Fault at high IRQL. !analyze easily figures this one out.
//
//----------------------------------------------------------------------
VOID
IrqlFault(
    VOID 
    )
{
    KIRQL  prevIrql;
    PCHAR  memoryPtr;
    int    i = 0;
    volatile int data;

//
// Allocation size. Thist *must* be less than a page size minus a little
// (for verifier header info) for the Verifier to allocate it from
// special pool.
//
#define ALLOCATION_SIZE  2048


    //
    // Allocate and then free memory
    //
    memoryPtr = ExAllocatePool( PagedPool, ALLOCATION_SIZE );
    ExFreePool( memoryPtr );

    //
    // Dereference the freed area at high IRQL and keep going
    // on through pool touching at high IRQL.
    // 
    KeRaiseIrql( DISPATCH_LEVEL, &prevIrql );
    while( 1 ) {

        data = *((PULONG) (memoryPtr+i));
        i += 4096;
    }
    KeLowerIrql( prevIrql );
}



//----------------------------------------------------------------------
//
// TrashStack
//
// Just blast through the stack. The pending IRP on the current
// thread in the crash dump hints that this driver might be the cause,
// but otherwise there's no way to verify it.
//
//----------------------------------------------------------------------
VOID
TrashStack(
    VOID 
    )
{
    volatile CHAR  buffer[256];
    static int i;

    for( i = 0; i < sizeof(buffer)+32; i++ ) {

        buffer[i] = 0x0;
    }
}



//----------------------------------------------------------------------
//
// WildPointer
//
// Overwrite some code. This is very hard to catch without verifier 
// because the driver is not active when a crash occurs of 
// write-protection is off ( >= 128MB on Win2K, >= 256MB on XP).
// Force write protection on by setting 
// HKLM\System\CurrentControlSet\Session Manager\Memory Management\
// LargePageMinimum to 0xFFFFFFFF.
//
//----------------------------------------------------------------------
NTSYSAPI
NTSTATUS
NTAPI
NtReadFile(
    IN HANDLE FileHandle,
    IN HANDLE Event OPTIONAL,
    IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
    IN PVOID ApcContext OPTIONAL,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    OUT PVOID Buffer,
    IN ULONG Length,
    IN PLARGE_INTEGER ByteOffset OPTIONAL,
    IN PULONG Key OPTIONAL
    );

VOID
WildPointer( 
    VOID 
    )
{
    *(PCHAR) IoGetCurrentProcess = 0x24;
}


//----------------------------------------------------------------------
//
// BufferOverflow
//
// Write past the end of the buffer. Verifier will catch it, but
// without it the crash is impossible to diagnose.
//
//----------------------------------------------------------------------
VOID
BufferOverflow( 
    VOID 
    )
{
    PCHAR   buffer;
    int     i;
    CHAR    overflow[] = "OVERFLOW";

    //
    // Allocate a buffer and zip past the end of it
    //
    buffer = ExAllocatePool( NonPagedPool, ALLOCATION_SIZE );
    for( i = 0; i < ALLOCATION_SIZE+40; i ++ ) {

        strcpy( &buffer[i], overflow );
    }

    //
    // Leak the memory so that if we have to try again we 
    // get a fresh block of memory to overrun
    //
    // ExFreePool( buffer );
}




//----------------------------------------------------------------------
//
// PoolLeak
//
// Leak some pool.
//
//----------------------------------------------------------------------

ULONG_PTR	*PagedLeakedPoolHead = NULL;
ULONG_PTR	*NonPagedLeakedPoolHead = NULL;

PVOID
PoolLeak(
    POOL_TYPE PoolType,
	ULONG LeakSize
    )
{
	ULONG_PTR	*buffer;
	ULONG_PTR	*next;	

	if( LeakSize < sizeof(ULONG_PTR) ) LeakSize = sizeof(ULONG_PTR);

	buffer = (ULONG_PTR *) ExAllocatePoolWithTag( PoolType, LeakSize, 'kaeL' );
	if( buffer ) {

		if( PoolType == PagedPool )  {

			next = PagedLeakedPoolHead;
			*buffer = (ULONG_PTR) next;
			PagedLeakedPoolHead = buffer;

		} else {

			next = NonPagedLeakedPoolHead;
			*buffer = (ULONG_PTR) next;
			NonPagedLeakedPoolHead = buffer;
		}
	}
	return buffer;
}

void
FreePoolLeak( void )
{
	ULONG_PTR	next;

	while( NonPagedLeakedPoolHead ) {

		next = *NonPagedLeakedPoolHead;
		ExFreePool( NonPagedLeakedPoolHead );
		NonPagedLeakedPoolHead = (ULONG_PTR *) next;
	}
	while( PagedLeakedPoolHead ) {

		next = (ULONG_PTR) *PagedLeakedPoolHead;
		ExFreePool( PagedLeakedPoolHead );
		PagedLeakedPoolHead = (ULONG_PTR *) next;
	}
}


//----------------------------------------------------------------------
//
// MyfaultDeviceControl
//
//----------------------------------------------------------------------
NTSTATUS  
MyfaultDeviceControl( 
    IN PFILE_OBJECT FileObject, 
    IN BOOLEAN Wait,
    IN PVOID InputBuffer, 
    IN ULONG InputBufferLength, 
    OUT PVOID OutputBuffer, 
    IN ULONG OutputBufferLength, 
    IN ULONG IoControlCode, 
    OUT PIO_STATUS_BLOCK IoStatus, 
    IN PDEVICE_OBJECT DeviceObject 
    ) 
{
    IoStatus->Status = STATUS_SUCCESS;
	IoStatus->Information = 0;
	switch ( IoControlCode ) {

    case IOCTL_BUFFER_OVERFLOW: 
        
        BufferOverflow();
        break;

    case IOCTL_WILD_POINTER:
        
        WildPointer();
        break;

    case IOCTL_PAGE_FAULT:
        
        PageFault();
        break;

    case IOCTL_DEADLOCK:
        
        DeadLock();
        break;

    case IOCTL_HANG:
        
        Hang();
        break;

    case IOCTL_TRASH_STACK:

        TrashStack();
        break;

    case IOCTL_IRQL:

        IrqlFault();
        break;

    case IOCTL_LEAK_PAGED:

		if( InputBufferLength != sizeof(ULONG)) {

			IoStatus->Status = STATUS_INVALID_PARAMETER;
			break;
		}
		if( !PoolLeak( PagedPool, *(PULONG) InputBuffer )) {

			IoStatus->Status = STATUS_INSUFFICIENT_RESOURCES;
		}
        break;

    case IOCTL_LEAK_NONPAGED:

		if( InputBufferLength != sizeof(ULONG)) {

			IoStatus->Status = STATUS_INVALID_PARAMETER;
			break;
		}
		if( !PoolLeak( NonPagedPool, *(PULONG) InputBuffer )) {

			IoStatus->Status = STATUS_INSUFFICIENT_RESOURCES;
		}
        break;
	
	default: 

        IoStatus->Status = STATUS_NOT_SUPPORTED;
        break;
	}
	return IoStatus->Status;
}


//----------------------------------------------------------------------
//
// MyfaultDispatch
//
// In this routine we Myfault requests to our own device. The only 
// requests we care about handling explicitely are IOCTL commands that
// we will get from the GUI. We also expect to get Create and Close 
// commands when the GUI opens and closes communications with us.
//
//----------------------------------------------------------------------
NTSTATUS 
MyfaultDispatch( 
    IN PDEVICE_OBJECT DeviceObject, 
    IN PIRP Irp 
    )
{
	PIO_STACK_LOCATION      iosp;
	PVOID                   inputBuffer;
	PVOID                   outputBuffer;
	ULONG                   inputBufferLength;
	ULONG                   outputBufferLength;
	ULONG                   ioControlCode;
	NTSTATUS                status;

    //
    // Switch on the request type
    //
	iosp = IoGetCurrentIrpStackLocation (Irp);
	switch (iosp->MajorFunction) {

    case IRP_MJ_CREATE:
        status = STATUS_SUCCESS;
        break;

    case IRP_MJ_CLOSE:
        status = STATUS_SUCCESS;
		FreePoolLeak();
		break;

	case IRP_MJ_DEVICE_CONTROL:

        inputBuffer        = Irp->AssociatedIrp.SystemBuffer;
        inputBufferLength  = iosp->Parameters.DeviceIoControl.InputBufferLength;
        outputBuffer       = Irp->AssociatedIrp.SystemBuffer;
        outputBufferLength = iosp->Parameters.DeviceIoControl.OutputBufferLength;
        ioControlCode      = iosp->Parameters.DeviceIoControl.IoControlCode;

        //
        // Special case: handle the IRP hang so as not to complete the IRP
        //
        if( ioControlCode == IOCTL_HANG_IRP ) {
            
            HangIrp();
            return STATUS_PENDING;

        } else {

            status = MyfaultDeviceControl( iosp->FileObject, TRUE,
                                               inputBuffer, inputBufferLength, 
                                               outputBuffer, outputBufferLength,
                                               ioControlCode, &Irp->IoStatus, 
                                               DeviceObject );
        }
		break;

    default:

        status = STATUS_INVALID_DEVICE_REQUEST;
        break;        
	}

    //
    // Complete the request
    //
    Irp->IoStatus.Status = status;
	IoCompleteRequest( Irp, IO_NO_INCREMENT );
	return status;
}


//----------------------------------------------------------------------
//
// MyfaultUnload
//
// Our job is done - time to leave.
//
//----------------------------------------------------------------------
VOID 
MyfaultUnload( 
    IN PDRIVER_OBJECT DriverObject 
    )
{
	WCHAR                   deviceLinkBuffer[]  = L"\\DosDevices\\MyFault";
	UNICODE_STRING          deviceLinkUnicodeString;

    //
	// Delete the symbolic link for our device
    //
	RtlInitUnicodeString( &deviceLinkUnicodeString, deviceLinkBuffer );
	IoDeleteSymbolicLink( &deviceLinkUnicodeString );

    //
	// Delete the device object
    //
	IoDeleteDevice( DriverObject->DeviceObject );
}



//----------------------------------------------------------------------
//
// Tiner crash 
//
// This causes a crash during the boot process, after smss.exe
// has saved a boot log.
//
//----------------------------------------------------------------------
KDPC  TimerDpc;
KTIMER CrashTimer;
VOID
TimerDpcRoutine(
    PKDPC Dpc,
    PVOID Context, 
    PVOID SystemArgument1,
    PVOID SystemArgument2
    )
{
    IrqlFault();
}


//----------------------------------------------------------------------
//
// DriverEntry
//
// Installable driver initialization. Here we just set ourselves up.
//
//----------------------------------------------------------------------
NTSTATUS 
DriverEntry(
    IN PDRIVER_OBJECT DriverObject, 
    IN PUNICODE_STRING RegistryPath 
    )
{
    NTSTATUS                status;
    WCHAR                   deviceNameBuffer[]  = L"\\Device\\Myfault";
    UNICODE_STRING          deviceNameUnicodeString;
    WCHAR                   deviceLinkBuffer[]  = L"\\DosDevices\\Myfault";
    UNICODE_STRING          deviceLinkUnicodeString;  
    PDEVICE_OBJECT          interfaceDevice = NULL;
    ULONG                   startType, demandStart;
    RTL_QUERY_REGISTRY_TABLE paramTable[2]; 
    UNICODE_STRING          registryPath; 
    LARGE_INTEGER           crashTime;

    //
    // Create a named device object
    //
    RtlInitUnicodeString (&deviceNameUnicodeString,
                          deviceNameBuffer );
    status = IoCreateDevice ( DriverObject,
                                0,
                                &deviceNameUnicodeString,
                                FILE_DEVICE_MYFAULT,
                                0,
                                TRUE,
                                &interfaceDevice );
    if (NT_SUCCESS(status)) {

	   //
	   // Create a symbolic link that the GUI can specify to gain access
	   // to this driver/device
	   //
	   RtlInitUnicodeString (&deviceLinkUnicodeString,
							 deviceLinkBuffer );
	   status = IoCreateSymbolicLink (&deviceLinkUnicodeString,
										&deviceNameUnicodeString );

	   //
	   // Create dispatch points for all routines that must be Myfaultd
	   //
	   DriverObject->MajorFunction[IRP_MJ_CREATE]          =
       DriverObject->MajorFunction[IRP_MJ_CLOSE]           =
       DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]  = MyfaultDispatch;
	   DriverObject->DriverUnload                          = MyfaultUnload;
    }

    if (!NT_SUCCESS(status)) {
      
	   //
	   // Something went wrong, so clean up 
	   //
	   if( interfaceDevice ) {

           IoDeleteDevice( interfaceDevice );
       }
    }

    // 
    // Query our start type to see if we are supposed to monitor starting
    // at boot time
    //
    registryPath.Buffer = ExAllocatePool( PagedPool, 
                                          RegistryPath->Length + sizeof(UNICODE_NULL)); 
    if(!registryPath.Buffer) { 
 
        return STATUS_INSUFFICIENT_RESOURCES; 
    } 
 
    registryPath.Length = RegistryPath->Length + sizeof(UNICODE_NULL); 
    registryPath.MaximumLength = registryPath.Length; 

    RtlZeroMemory( registryPath.Buffer, registryPath.Length ); 
    RtlMoveMemory( registryPath.Buffer,  RegistryPath->Buffer, 
                   RegistryPath->Length  ); 

    demandStart = SERVICE_DEMAND_START;
    startType = demandStart;
    RtlZeroMemory( &paramTable[0], sizeof(paramTable)); 
    paramTable[0].Flags = RTL_QUERY_REGISTRY_DIRECT; 
    paramTable[0].Name = L"Start"; 
    paramTable[0].EntryContext = &startType;
    paramTable[0].DefaultType = REG_DWORD; 
    paramTable[0].DefaultData = &demandStart;
    paramTable[0].DefaultLength = sizeof(ULONG); 

    RtlQueryRegistryValues( RTL_REGISTRY_ABSOLUTE,
                            registryPath.Buffer, &paramTable[0], 
                            NULL, NULL  );

    if( startType != SERVICE_DEMAND_START ) {
        
        //
        // Crash here during the boot process
        //
        KeInitializeDpc( &TimerDpc, 
                         TimerDpcRoutine, 
                         NULL );
        
        KeInitializeTimer( &CrashTimer );

        //
        // Give SMSS 5 seconds to start
        //
        crashTime.QuadPart = 5 * -10000000;
        KeSetTimer( &CrashTimer,
                    crashTime,
                    &TimerDpc );
    }
    return status;
}
    


