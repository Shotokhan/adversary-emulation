pub type ZwAllocateVirtualMemory = extern "stdcall" fn(
    ProcessHandle:      crate::types::HANDLE,
    BaseAddress:        *mut crate::types::PVOID,
    ZeroBits:           crate::types::ULONG_PTR,
    RegionSize:         crate::types::PSIZE_T,
    AllocationType:     crate::types::ULONG,
    Protect:            crate::types::ULONG,
) -> crate::types::NTSTATUS;


pub type ZwCreateIoCompletion = extern "stdcall" fn(
    IoCompletionHandleReturn:   crate::types::PHANDLE,
    DesiredAccess:              crate::types::ACCESS_MASK,
    ObjectAttributes:           crate::structs::POBJECT_ATTRIBUTES,
    Flags:                      crate::types::ULONG,
) -> crate::types::NTSTATUS;


pub type ZwSetInformationWorkerFactory = extern "stdcall" fn(
    WorkerFactoryHandle:            crate::types::HANDLE,
    WorkerFactoryInformationClass:  crate::enums::WORKER_FACTORY_INFORMATION_CLASS,
    WorkerFactoryInformation:       crate::types::PVOID,
    WorkerFactoryInformationLength: crate::types::SIZE_T,
) -> crate::types::NTSTATUS;


pub type ZwCreateWorkerFactory = extern "stdcall" fn(
    WorkerFactoryHandleReturn:  crate::types::PHANDLE,
    DesiredAccess:              crate::types::ACCESS_MASK,
    ObjectAttributes:           crate::structs::POBJECT_ATTRIBUTES,
    CompletionPortHandle:       crate::types::HANDLE,
    WorkerProcessHandle:        crate::types::HANDLE,
    StartRoutine:               crate::types::PVOID,
    StartParameter:             crate::types::PVOID,
    MaxThreadCount:             crate::types::ULONG,
    StackReserve:               crate::types::SIZE_T,
    StackCommit:                crate::types::SIZE_T,
) -> crate::types::NTSTATUS;

// https://github.com/mic101/windows/blob/master/WRK-v1.2/base/ntos/ps/create.c#L966-L1014
pub type PspCreateProcess = extern "stdcall" fn(
    ProcessHandle:          crate::types::PHANDLE,  // out param
    DesiredAccess:          crate::types::ACCESS_MASK,
    ObjectAttributes:       crate::structs::POBJECT_ATTRIBUTES, // optional but used for argv
    ParentProcess:          crate::types::HANDLE, // optional
    Flags:                  crate::types::ULONG,
    SectionHandle:          crate::types::HANDLE, // optional but used for new process from scratch (not forked)
    DebugPort:              crate::types::HANDLE, // optional
    ExceptionPort:          crate::types::HANDLE, // optional
    JobMemberLevel:         crate::types::ULONG,
) -> crate::types::NTSTATUS;


pub type ZwCreateSection = extern "stdcall" fn(
    SectionHandle:          crate::types::PHANDLE,
    DesiredAccess:          crate::types::ACCESS_MASK,
    ObjectAttributes:       crate::structs::POBJECT_ATTRIBUTES,
    MaximumSize:            crate::structs::PLARGE_INTEGER,
    SectionPageProtection:  crate::types::ULONG,
    AllocationAttributes:   crate::types::ULONG,
    FileHandle:             crate::types::HANDLE,
) -> crate::types::NTSTATUS;


pub type ZwSetValueKey = extern "stdcall" fn(
    KeyHandle:              crate::types::HANDLE,
    ValueName:              crate::structs::PUNICODE_STRING,
    TitleIndex:             crate::types::ULONG,
    Type:                   crate::types::ULONG,
    Data:                   crate::types::PVOID,
    DataSize:               crate::types::ULONG,
) -> crate::types::NTSTATUS;


pub type ZwCreateKey = extern "stdcall" fn(
    KeyHandle:              crate::types::PHANDLE,
    DesiredAccess:          crate::types::ACCESS_MASK,
    ObjectAttributes:       crate::structs::POBJECT_ATTRIBUTES,
    TitleIndex:             crate::types::ULONG,
    Class:                  crate::structs::PUNICODE_STRING,
    CreateOptions:          crate::types::ULONG,
    Disposition:            crate::types::PULONG,
) -> crate::types::NTSTATUS;


pub type ZwQueryValueKey = extern "stdcall" fn(
    KeyHandle:                  crate::types::HANDLE,
    ValueName:                  crate::structs::PUNICODE_STRING,
    KeyValueInformationClass:   crate::types::KEY_VALUE_INFORMATION_CLASS,
    KeyValueInformation:        crate::types::PVOID,
    Length:                     crate::types::ULONG,
    ResultLength:               crate::types::PULONG,
) -> crate::types::NTSTATUS;


pub type ZwOpenKey = extern "stdcall" fn(
    KeyHandle:              crate::types::PHANDLE,
    DesiredAccess:          crate::types::ACCESS_MASK,
    ObjectAttributes:       crate::structs::POBJECT_ATTRIBUTES,
) -> crate::types::NTSTATUS;


pub type ZwReadFile = extern "stdcall" fn(
    FileHandle:             crate::types::HANDLE,
    Event:                  crate::types::HANDLE,
    ApcRoutine:             crate::types::PVOID,
    ApcContext:             crate::types::PVOID,
    IoStatusBlock:          crate::structs::PIO_STATUS_BLOCK,
    Buffer:                 crate::types::PVOID,
    Length:                 crate::types::ULONG,
    ByteOffset:             crate::structs::PLARGE_INTEGER,
    Key:                    crate::types::PULONG,
) -> crate::types::NTSTATUS;


pub type ZwWriteFile = extern "stdcall" fn(
    FileHandle:             crate::types::HANDLE,
    Event:                  crate::types::HANDLE,
    ApcRoutine:             crate::types::PVOID,
    ApcContext:             crate::types::PVOID,
    IoStatusBlock:          crate::structs::PIO_STATUS_BLOCK,
    Buffer:                 crate::types::PVOID,
    Length:                 crate::types::ULONG,
    ByteOffset:             crate::structs::PLARGE_INTEGER,
    Key:                    crate::types::PULONG,
) -> crate::types::NTSTATUS;


pub type PsTerminateSystemThread = extern "stdcall" fn(
    ExitStatus:             crate::types::NTSTATUS,
) -> ();


pub type PsCreateSystemThread = extern "stdcall" fn(
    ThreadHandle:           crate::types::PHANDLE,
    DesiredAccess:          crate::types::ULONG,
    ObjectAttributes:       crate::types::PVOID,
    ProcessHandle:          crate::types::HANDLE,
    ClientId:               crate::types::PVOID,
    StartRoutine:           crate::types::PVOID,
    StartContext:           crate::types::PVOID,
) -> crate::types::NTSTATUS;


pub type KeInitializeThreadedDpc = extern "stdcall" fn(
    Dpc:                    crate::types::PVOID,
    DeferredRoutine:        crate::types::PVOID,
    DeferredContext:        crate::types::PVOID,
) -> ();


pub type MmMapIoSpace = extern "stdcall" fn(
    PhysicalAddress:        crate::types::UINT64,
    NumberOfBytes:          crate::types::SIZE_T,
    CacheType:              crate::types::UINT32,
) -> crate::types::PVOID;


pub type MmAllocateContiguousMemory = extern "stdcall" fn(
    NumberOfBytes:              crate::types::SIZE_T,
    HighestAcceptableAddress:   crate::types::UINT64,
) -> crate::types::PVOID;


pub type ExTryToAcquireFastMutex = extern "stdcall" fn(
    FastMutex:              crate::types::PVOID,
) -> crate::types::BOOLEAN;


pub type ExInitializeFastMutex = extern "stdcall" fn(
    FastMutex:              crate::types::PVOID,
) -> ();


pub type KeSetTimerEx = extern "stdcall" fn(
    Timer:                  crate::types::PVOID,
    DueTime:                crate::types::LARGE_INTEGER,
    Period:                 crate::types::LONG,
    Dpc:                    crate::types::PVOID,
) -> crate::types::BOOLEAN;


pub type KeInitializeDpc = extern "stdcall" fn(
    Dpc:                    crate::types::PVOID,
    DeferredRoutine:        crate::types::PVOID,
    DeferredContext:        crate::types::PVOID,
) -> ();


pub type KeInitializeTimer = extern "stdcall" fn(
    Timer:                  crate::types::PVOID,
) -> ();


pub type ZwClose = extern "stdcall" fn(
    Handle:                 crate::types::HANDLE,
) -> ();


pub type ZwQueryDirectoryFile = extern "stdcall" fn(
    FileHandle:             crate::types::HANDLE,
    Event:                  crate::types::HANDLE,
    ApcRoutine:             crate::types::PVOID,
    ApcContext:             crate::types::PVOID,
    IoStatusBlock:          crate::structs::PIO_STATUS_BLOCK,
    FileInformation:        crate::types::PVOID,
    Length:                 crate::types::ULONG,
    FileInformationClass:   crate::types::FILE_INFORMATION_CLASS,
    ReturnSingleEntry:      crate::types::BOOLEAN,
    FileName:               crate::structs::PUNICODE_STRING,
    RestartScan:            crate::types::BOOLEAN
) -> crate::types::NTSTATUS;

pub type KeRaiseIrqlToDpcLevel = extern "stdcall" fn() -> crate::types::KIRQL;

pub type KeLowerIrql = extern "stdcall" fn(
    NewIrql:    crate::types::KIRQL
) -> ();


pub type ExAllocatePool = extern "stdcall" fn(
    pool_type:  crate::enums::POOL_TYPE,
    size:       crate::types::SIZE_T,
) -> crate::types::PVOID;

pub type ExFreePoolWithTag = extern "stdcall" fn(
    Buffer:     crate::types::PVOID,
    Tag:        crate::types::ULONG,
) -> ();

pub type ZwCreateFile = extern "stdcall" fn(
    FileHandle:         crate::types::PHANDLE,
    AccessMask:         crate::types::ACCESS_MASK,
    ObjectAttributes:   crate::structs::POBJECT_ATTRIBUTES,
    IoStatusBlock:      crate::structs::PIO_STATUS_BLOCK,
    AllocationSize:     crate::structs::PLARGE_INTEGER,
    FileAttributes:     crate::types::ULONG,
    ShareAccess:        crate::types::ULONG,
    CreateDisposition:  crate::types::ULONG,
    CreateOptions:      crate::types::ULONG,
    EaBuffer:           crate::types::PVOID,
    EaLength:           crate::types::ULONG,
) -> crate::types::NTSTATUS;

pub type ObReferenceObjectByHandle = extern "stdcall" fn(
    Handle:             crate::types::HANDLE,
    AccessMask:         crate::types::ACCESS_MASK,
    ObjectType:         crate::types::PVOID, // POBJECT_TYPE,
    AccessMode:         crate::enums::KPROCESSOR_MODE,
    Object:             *mut crate::types::PVOID, // PVOID*,
    HandleInformation:  crate::types::PVOID, // POBJECT_HANDLE_INFORMATION,
) -> crate::types::NTSTATUS;

pub type IoBuildDeviceIoControlRequest = extern "stdcall" fn(
    IoControlCode:              crate::types::ULONG,
    DeviceObject:               crate::structs::PDEVICE_OBJECT,
    InputBuffer:                crate::types::PVOID,
    InputBufferLength:          crate::types::ULONG,
    OutputBuffer:               crate::types::PVOID,
    OutputBufferLength:         crate::types::ULONG,
    InternalDeviceIoControl:    crate::types::BOOLEAN,
    Event:                      crate::structs::PKEVENT,
    IoStatusBlock:              crate::structs::PIO_STATUS_BLOCK,
) -> crate::structs::PIRP;

pub type IoGetRelatedDeviceObject = extern "stdcall" fn(
    FileObject: crate::structs::PFILE_OBJECT,
) -> crate::structs::PDEVICE_OBJECT;

pub type IofCallDriver = extern "fastcall" fn(
    DeviceObject:   crate::structs::PDEVICE_OBJECT,
    Irp:            crate::structs::PIRP,
) -> crate::types::NTSTATUS;

pub type KeInitializeEvent = extern "stdcall" fn(
    Event:      crate::structs::PKEVENT,
    Type:       crate::enums::EVENT_TYPE,
    State:      crate::types::BOOLEAN,
) -> ();

pub type KeWaitForSingleObject = extern "stdcall" fn(
    Object:         crate::types::PVOID,
    WaitReason:     crate::enums::KWAIT_REASON,
    WaitMode:       crate::enums::KPROCESSOR_MODE,
    Alertable:      crate::types::BOOLEAN,
    Timeout:        crate::structs::PLARGE_INTEGER,
) -> ();

pub type IoAllocateMdl = extern "stdcall" fn(
    VirtualAddress:     crate::types::PVOID,
    Length:             crate::types::ULONG,
    SecondaryBuffer:    crate::types::BOOLEAN,
    ChargeQuote:        crate::types::BOOLEAN,
    Irp:                crate::structs::PIRP,
) -> crate::structs::PMDL;

pub type IoFreeMdl = extern "stdcall" fn(
    Mdl:    crate::structs::PMDL,
) -> ();

pub type MmBuildMdlForNonPagedPool = extern "stdcall" fn(
    Mdl:    crate::structs::PMDL,
) -> ();

pub type MmProbeAndLockPages = extern "stdcall" fn(
    Mdl:        crate::structs::PMDL,
    AccessMove: crate::enums::KPROCESSOR_MODE,
    Operation:  crate::enums::LOCK_OPERATION,
) -> ();

pub type MmSecureVirtualMemory = extern "stdcall" fn(
    Address:        crate::types::PVOID,
    Size:           crate::types::SIZE_T,
    ProbeMode:      crate::types::ULONG,
) -> crate::types::HANDLE;


pub type MmUnsecureVirtualMemory = extern "stdcall" fn(
    SecureHandle:        crate::types::HANDLE,
) -> ();

pub type PsGetProcessImageFileName = extern "stdcall" fn(
    process:    crate::structs::PEPROCESS,
) -> crate::types::PCHAR;

pub type PsLookupProcessByProcessId  = extern "stdcall" fn(
    ProcessId:      crate::types::HANDLE,
    Process:        *mut crate::structs::PEPROCESS,
) -> crate::types::NTSTATUS;

pub type ObfDereferenceObject = extern "fastcall" fn(
    Object:     crate::types::PVOID,
) -> crate::types::ULONG_PTR;

pub type KeStackAttachProcess = extern "stdcall" fn(
    Process:     crate::structs::PRKPROCESS,
    ApcState:    crate::structs::PKAPC_STATE,
) -> ();

pub type KeUnstackDetachProcess = extern "stdcall" fn(
    ApcState:   crate::structs::PKAPC_STATE,
) -> ();

pub type ZwQueryVirtualMemory = extern "stdcall" fn(
    ProcessHandle:              crate::types::HANDLE,
    BaseAddress:                crate::types::PVOID,
    MemoryInformationClass:     crate::enums::MEMORY_INFORMATION_CLASS,
    MemoryInformation:          crate::types::PVOID,
    MemoryInformationLength:    crate::types::SIZE_T,
    ReturnLength:               crate::types::PSIZE_T,
) -> crate::types::NTSTATUS;

pub type RtlGetVersion = extern "stdcall" fn(
    lpVersionInformation: crate::structs::PRTL_OSVERSIONINFOW,
) -> crate::types::NTSTATUS;

pub type ZwQueryInformationProcess = extern "stdcall" fn(
    ProcessHandle:  crate::types::HANDLE,
    ProcessInformationClass:    crate::enums::PROCESSINFOCLASS,
    ProcessInformation:         crate::types::PVOID,
    ProcessInformationLength:   crate::types::ULONG,
    ReturnLength:               crate::types::PULONG,
) -> crate::types::NTSTATUS;