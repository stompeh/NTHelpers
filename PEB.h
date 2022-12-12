//Winver 10 -- 22H2 -- 19045.2251
//WinSDK 19041.685
//December 10, 2022


#include <Windows.h>

typedef struct _STRING
{
	USHORT Lenth;
	USHORT MaximumLength;
	PCHAR Buffer;

} STRING, *PSTRING;

typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;

} UNICODE_STRING, *PPUNICODE_STRING;

typedef struct _CURDIR
{
	UNICODE_STRING DosPath;
	HANDLE Handle;

} CURDIR, *PCURDIR;

typedef struct _PEB_LDR_DATA
{
	ULONG Length;
	BOOLEAN Initialized;
	HANDLE SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
	BOOLEAN ShutdownInProgress;
	PVOID ShutdownThreadId;

} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _RTL_DRIVE_LETTER_CURDIR
{
	USHORT FLAGS;
	USHORT LENGTH;
	ULONG TimeStamp;
	STRING DosPath;

} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS
{
	ULONG MaximumLength;
	ULONG Length;
	ULONG Flags;
	ULONG DebugFlags;
	HANDLE ConsoleHandle;
	ULONG ConsoleFlags;
	PVOID StandardInput;
	PVOID StandardOutput;
	PVOID StandardError;
	CURDIR CurrentDirectory;
	UNICODE_STRING DllPath;
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
	PVOID Environment;

	ULONG StartingX;
	ULONG StartingY;
	ULONG CountX;
	ULONG CountY;
	ULONG FillAttribute;
	ULONG WindowFlags;
	ULONG ShowWindowFlags;
	UNICODE_STRING WindowTitle;
	UNICODE_STRING DesktopInfo;
	UNICODE_STRING ShellInfo;
	UNICODE_STRING RuntimeData;

	RTL_DRIVE_LETTER_CURDIR CurrentDirectores[32];
	SIZE_T EnvironmentSize;
	SIZE_T EnvironmentVersion;
	PVOID PackageDependencyData;
	ULONG ProcessGroupId;
	ULONG LoaderThreads;
	UNICODE_STRING RedirectionDllName;
	UNICODE_STRING HeapPartitionName;
	PSIZE_T DefaultThreadpoolCpuSetMasks;
	ULONG DefaultThreadpoolCpuSetMaskCount;
	ULONG DefaultThreadpoolThreadMaximum;

}RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;


typedef struct _ACTIVATION_CONTEXT_DATA
{
	// Empty
} ACTIVATION_CONTEXT_DATA, *PACTIVATION_CONTEXT_DATA;

typedef struct _ASSEMBLY_STORAGE_MAP
{
	// Empty
} ASSEMBLY_STORAGE_MAP, *PASSEMBLY_STORAGE_MAP;

typedef struct _LEAP_SECOND_DATA
{
	BOOLEAN Enabled;
	ULONG Count;
	LARGE_INTEGER Data[1];

} LEAP_SECOND_DATA, *PLEAP_SECOND_DATA;

typedef struct _PEB
{
	BOOLEAN InheritedAddressSpace;
	BOOLEAN ReadImageFileExecOptions;
	BOOLEAN BeingDebugged;

	union
	{
		BOOLEAN BitField;
		struct
		{
			BOOLEAN ImageUsesLargePages : 1;
			BOOLEAN IsProtectedProcess : 1;
			BOOLEAN IsImageDynamicallyRelocated : 1;
			BOOLEAN SkipPatchingUser32Forwarders : 1;
			BOOLEAN IsPackagedProcess : 1;
			BOOLEAN IsAppContainer : 1;
			BOOLEAN IsProtectedProcessLight : 1;
			BOOLEAN IsLongPathAwareProcess : 1;
		}stProcessFlags;
	}unProcessFlags;

	UCHAR Padding0[4];

	HANDLE Mutant;
	PVOID ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	PVOID SubSystemData;
	HANDLE ProcessHeap;
	PRTL_CRITICAL_SECTION FastPebLock;
	PSLIST_HEADER AtlThunkSListPtr;
	PVOID IFEOKey;

	union
	{
		ULONG CrossProcessFlags;
		struct
		{
			ULONG ProcessInJob : 1;
			ULONG ProcessInitializing : 1;
			ULONG ProcessUsingVEH : 1;
			ULONG ProcessUsingVCH : 1;
			ULONG ProcessUsingFTH : 1;
			ULONG ProcessPreviouslyThrottled : 1;
			ULONG ProcessCurrentyThrottled : 1;
			ULONG ProcessImagesHotPatched : 1;
			ULONG ReservedBits0 : 24;
		}s2;
	}u2;

	UCHAR Padding1[4];

	union
	{
		PVOID KernelCallbackTable;
		PVOID UserSharedInfoPtr;
	}u3;

	ULONG SystemReserved;
	ULONG AtlThunkSListPtr32;
	PVOID ApiSetMap;
	ULONG TlsExpansionCounter;
	UCHAR Padding2[4];

	PVOID TlsBitmap;
	ULONG TlsBitmapBits[2];

	PVOID ReadOnlySharedMemoryBase;
	PVOID SharedData;
	PVOID* ReadOnlyStaticServerData;
	PVOID AnsiCodePageData;
	PVOID OemCodePageData;
	PVOID UnicodeCaseTableData;

	ULONG NumberOfProcessors;
	ULONG NtGlobalFlag;

	LARGE_INTEGER CriticalSectionTimeout;

	SIZE_T HeapSegmentReserve;
	SIZE_T HeapSegmentCommit;
	SIZE_T HeapDeCommitTotalFreeThreshold;
	SIZE_T HeapDecommitFreeBlockThreshold;

	ULONG NumberOfHeaps;
	ULONG MaximumNumberOfHeaps;
	PVOID* ProcessHeaps;

	PVOID GdiSharedHandleTable;
	PVOID ProcessStarterHelper;
	ULONG GdiDCAttributeList;
	UCHAR Padding3[4];

	PRTL_CRITICAL_SECTION LoaderLock;

	ULONG OSMajorVersion;
	ULONG OSMinorVersion;
	USHORT OSBuildNumber;
	USHORT OSCSDVersion;
	ULONG OSPlatformId;
	ULONG ImageSubsystem;
	ULONG ImageSubsystemMajorVersion;
	ULONG ImageSubsystemMinorVersion;
	UCHAR Padding4[4];

	SIZE_T ActiveProcessAffinityMask;
	ULONG GdiHandleBuffer[60];

	PVOID PostProcessInitRoutine;
	PVOID TlsExpansionBitmap;
	ULONG TlsExpansionBitmapBits[32];

	ULONG SessionId;
	UCHAR Padding5[4];

	ULARGE_INTEGER AppCompatFlags;
	ULARGE_INTEGER AppCompatFlagsUser;
	PVOID pShimData;
	PVOID AppCompatInfo;

	UNICODE_STRING CSDVersion;
	PACTIVATION_CONTEXT_DATA ActivationContextData;

	PASSEMBLY_STORAGE_MAP ProcessAssemblyStorageMap;
	PACTIVATION_CONTEXT_DATA SystemDefaultActivationContextData;
	PASSEMBLY_STORAGE_MAP SystemAssemblyStorageMap;
	SIZE_T MinimumStackCommit;

	PVOID SparePointers[4];
	ULONG SpareUlongs[5];

	PVOID WerRegistrationData;
	PVOID WerShipAssertPtr;

	PVOID pUnused;
	PVOID pImageHeaderHash;

	union
	{
		ULONG TracingFlags;
		struct
		{
			ULONG HeapTracingEnabled : 1;
			ULONG CritSecTracingEnabled : 1;
			ULONG LibLoaderTracingEnabled : 1;
			ULONG SpareTracingBits : 29;
		}s3;
	}u4;

	UCHAR Padding6[4];

	SIZE_T CsrServerReadOnlySharedMemoryBase;
	SIZE_T TppWorkerpListLock;
	LIST_ENTRY TppWorkerpList;
	PVOID WaitOnAddressHashTable[128];

	PVOID TelemetryCoverageHeader;
	ULONG CloudFileFlags;
	ULONG CloudFileDiagFlags;
	CHAR PlaceholderCompatibilityMode;
	CHAR PlaceholderCompatibilityModeReserved[7];

	PLEAP_SECOND_DATA LeapSecondData;

	union
	{
		ULONG LeapSecondFlag;
		struct
		{
			ULONG SixtySecondEnabled : 1;
			ULONG Reserved : 31;
		}s4;
	}u5;

	ULONG NtGlobalFlag2;

} PEB, *PPEB;
