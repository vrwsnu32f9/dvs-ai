#pragma once

#include <ntddk.h>

typedef struct _r {
    INT32 Security;
    INT32 ProcessId;
    ULONGLONG Address;
    ULONGLONG Buffer;
    ULONGLONG Size;
    BOOLEAN Write;
} r, * pr;

typedef struct _b {
    INT32 Security;
    INT32 ProcessId;
    ULONGLONG* Address;
} b, * pb;

//guarded region struct
typedef struct _gr {
    ULONGLONG* guarded;
} gr, * pgr;


typedef struct _SystemBigpoolEntry {
    PVOID VirtualAddress;
    ULONG_PTR NonPaged : 1;
    ULONG_PTR SizeInBytes;
    UCHAR Tag[4];
} SystemBigpoolEntry, * PSystemBigpoolEntry;

typedef struct _SystemBigpoolInformation {
    ULONG Count;
    SystemBigpoolEntry AllocatedInfo[1];
} SystemBigpoolInformation, * PSystemBigpoolInformation;

typedef enum _SystemInformationClass {
    SystemBigpoolInformationClass = 0x42,
} SystemInformationClass;

#define PageOffsetSize 12
static const UINT64 PageMask = (~0xfull << 8) & 0xfffffffffull;

//todo MouseRequest