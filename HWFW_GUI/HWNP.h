#pragma once

#ifndef _INC_STDDEF
#include <stddef.h>
#endif

#ifndef _STDINT
#include <stdint.h>
#endif

#ifndef SPECSTRINGS_H
#include <specstrings.h>
#endif

#ifndef _WINDEF_
#include <WinDef.h>
#endif

#ifndef _WINBASE_
#include <WinBase.h>
#endif

#include "uboot_image.h"

/*
References:
  http://blog.leexiaolan.tk/pwn-huawei-hg8120c-ont-via-maintenance-tool-part-2
  http://blog.leexiaolan.tk/pwn-huawei-hg8120c-ont-upgrade-pack-format-part-3
  https://github.com/LeeXiaolan/hwfw-tool
*/

#define CHK_FLAGS(v, f)                                     (((v) & (f)) == (f))
#define CHK_NOFLAGS(v, f)                                   (((v) & (f)) != (f))
#define HWNP_HEADER_MAGIC                                   0x504e5748                                                                      //HWNP
#define HWNP_HWHW_MAGIC                                     'hwhw'                                                                          //whwh header magic
#define CHK_OUT_OF_UBOUND(pointer, start, size)             ((size_t)(pointer) >= ((size_t)(start) + (size_t)(size)))                       //Check for superscript out of bounds
#define CHK_OUT_OF_UBOUND2(pointer, len, start, size)       (((size_t)(pointer) + (size_t)(len))  > ((size_t)(start) + (size_t)(size)))     //Check for superscript out of bounds

#define EndianSwap32(int32)                                 ((((uint32_t)(int32) & 0xff000000U) >> 24) | \
                                                            (((uint32_t)(int32) & 0x00ff0000U) >> 8) | \
                                                            (((uint32_t)(int32) & 0x0000ff00U) << 8) | \
                                                            (((uint32_t)(int32) & 0x000000ffU) << 24))

#define OffsetOf(TYPE, MEMBER)                              ((size_t) & ((TYPE *)0)->MEMBER )

#define MakePointer32(Ptr, Offset)                          ((void *)(((uint32_t)(Ptr)) + ((uint32_t)(Offset))))


//ItemInfo Flags
#define IIFLAG_ID                                           0x00000001U
#define IIFLAG_PATH                                         0x00000002U
#define IIFLAG_TYPE                                         0x00000004U
#define IIFLAG_VERSION                                      0x00000008U
#define IIFLAG_POLICY                                       0x00000010U
#define IIFLAG_RESERVED                                     0x00000020U
#define IIFLAG_ALL                                          (IIFLAG_ID | IIFLAG_PATH | IIFLAG_TYPE | IIFLAG_VERSION | IIFLAG_POLICY | IIFLAG_RESERVED)

//ItemData Type
#define IDT_WHWH                                            0x00000001U
#define IDT_UBOOT                                           0x00000002U



#define CHKCRC_OK                                           0
#define CHKCRC_FAILED                                       11
#define CHKCRC_FILECRCERR                                   191
#define CHKCRC_HEADERCRCERR                                 192
#define CHKCRC_ITEMCRCERR                                   200



/*
HuaWei Firmware structure

 ___________________________________
|                                   |
|              Header               |
|___________________________________|
|                                   |
|            ProductList            |
|___________________________________|
|                                   |
|            ItemInfo * N           |
|===================================|  <--- Usually continuous, but theoretically can be discontinuous
|                                   |
|         software RAW data         |
|___________________________________|



HW software data (data not aligned):
 ______________________________________________
|                                              |
|               HW Header (whwh)               |
| ____________________________________________ |
||                                            ||
||               uImage Header                ||
||          (0x27, 0x05, 0x19, 0x56)          ||
||____________________________________________||
||                                            ||
||                  Payload                   ||
||        (uboot, kernel, rootfs, ...)        ||
||____________________________________________||
 ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯

 
HW software data (Padding alignment):
 ______________________________________________
|                                              |
|               HW Header (whwh)               |
| ____________________________________________ |
||                                            ||
||   uImage Header (0x27, 0x05, 0x19, 0x56)   ||
||____________________________________________||
||                                            ||
||    Payload (uboot, kernel, rootfs, ...)    ||
||____________________________________________||
|                                              |
|          Padding data for alignment          |
|______________________________________________|


HW software data (Margin alignment):
 _____________________________________________
|                                             |
|               HW Header (whwh)              |
| ___________________________________________ |
||                                           ||
||  uImage Header (0x27, 0x05, 0x19, 0x56)   ||
||___________________________________________||
||                                           ||
||    Payload (uboot, kernel, rootfs, ...)   ||
||___________________________________________||
|¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯|
|         Padding data for alignment          |
|_____________________________________________|

*/

//Basic file header
typedef struct _HWNP_BasicFileHeader
{
  //Magic Word
  uint32_t                  u32Magic;

  //File size (calculated as .bin file size - 76)  big-endian
  __be32                    beu32FileSize;

  //CRC32 value from the beginning of HWNP_FILEHDR2 to the end of the file (including software data)
  uint32_t                  u32FileCRC32;
} HWNP_BASFILEHDR, *PHWNP_BASFILEHDR;

//File Header 2
typedef struct _HWNP_FileHeader2
{
  //Head size
  //There are two calculation formulas:
  //1:  sizeof(HWNP_HEADER) + Header.u16ProductListSize + Header.u32ItemCount * Header.u16ItemInfoSize
  //2:  Header.u16ProductListSize + Header.u32ItemCount * Header.u16ItemInfoSize
  //The former has more file header size
  //The new version of the firmware is generally the first formula,
  //It seems that the V100 version of the firmware is the second calculation formula
  //This value is not the size used to calculate the header CRC32
  uint32_t                  u32HeaderSize;

  //CRC32 value from HWNP_PAKHDR to the end of N HWNP_ITEMINFO (excluding software data)
  uint32_t                  u32HeaderCRC32;
} HWNP_FILEHDR2, *PHWNP_FILEHDR2;

//Baotou
typedef struct _HWNP_PacketHeader
{
  uint32_t                  u32ItemCount;
  uint8_t                   u8PackTotal;
  uint8_t                   u8PackNum;
  uint16_t                  u16ProductListSize;

  union {
    uint16_t                u16ItemInfoSize;          //== sizeof(HWNP_ITEMINFO)
    uint32_t                _u32ItemInfoSize;         //== sizeof(HWNP_ITEMINFO)
  };
  
  uint32_t                  u32Reserved;
} HWNP_PAKHDR, *PHWNP_PAKHDR;

/*
HWNP: Hua Wei Network Packet ?
*/
typedef struct _HWNP_Header
{
  HWNP_BASFILEHDR           BasicFileHeader;
  //file crc32 start comupte
  HWNP_FILEHDR2             FileHeader2;
  //header crc32 start comupte
  HWNP_PAKHDR               PacketHeader;
} HWNP_HEADER, *PHWNP_HEADER;


typedef struct _HWNP_ItemInfo
{
  uint32_t                  u32Id;                //Initial Index
  uint32_t                  u32ItemCRC32;          
  uint32_t                  u32Offset;
  uint32_t                  u32Size;              //Initial Len
  char                      chItemPath[256];      //Initial Destination
  char                      chItemType[16];       //Initial Name
  char                      chItemVersion[64];
  uint32_t                  u32Policy;
  uint32_t                  u32Reserved;
} HWNP_ITEMINFO, *PHWNP_ITEMINFO;


enum HW_SubItemType : uint32_t
{
  hwType_Invalid = 0U,
  hwType_Kernel = 1U,
  hwType_RootFS,
  hwType_System,
  hwType_MiniSYS,
  hwType_UNK_5,
  hwType_UNK_6,
  hwType_L2Boot,
  hwType_UBoot,
  hwType_UNK_9,
  hwType_UNK_10,
  hwType_SignInfo,
  hwType_Limit
};

const char * const HW_SubItemType_Text[hwType_Limit] = {
  "?    Invalid",
  "1    Kernel",
  "2    RootFS",
  "3    System",
  "4    MiniSYS",
  "5    UNK_5",
  "6    UNK_6",
  "7    L2Boot",
  "8    UBoot",
  "9    UNK_9",
  "10   UNK_10",
  "11   SignInfo",
};


const WCHAR * const HW_ItemType_Text[] = {
  L"UPGRDCHECK",
  L"MODULE",
  L"FLASH_CONFIG",
  L"UBOOT",
  L"L2BOOT",
  L"MINISYS",
  L"KERNEL",
  L"ROOTFS",
  L"UPDATEFLAG",
  L"EFS",
  L"SIGNINFO",
  L"UNKNOWN",
  NULL
};

typedef struct _HW_Header
{
  //Magic Word
  uint32_t                  u32Magic;
  char                      chItemVersion[64];
  __time32_t                u32Time;
  HW_SubItemType            u32Type;
  uint32_t                  u32RearSize;
  uint32_t                  u32RearCRC;
} HW_HEADER, HW_HDR, *PHW_HEADER, *PHW_HDR;

//Whether the memory file has changed
BOOL          HWNP_IsChanged();

//Get the last error code
int           HWNP_GetLastError();

//Get status value: -1 means the firmware file has been opened correctly
int           HWNP_GetState();

//Get the calculation method of the head size
int           HWNP_GetHeaderSizeType();

//Set how the head size is calculated
int           HWNP_SetHeaderSizeType(__in int nNewType);

//Update information (CRC, item offset, item size, etc.)
void          HWNP_Update();

//Release all resources
void          HWNP_Release();

//Open the firmware file
int           HWNP_OpenFirmware(__in LPCWSTR lpFilePath);

//Get the number of items
int           HWNP_GetItemCount(__out uint32_t *lpu32Count);

//Get the software index by software ID
int           HWNP_GetItemIndexById(__in uint32_t u32Id, __out uint32_t *lpu32Index);

//Get software information
int           HWNP_GetItemInfoByIndex(__in uint32_t u32Index, __out PHWNP_ITEMINFO lpItemInfo);

//Get the item data size
int           HWNP_GetItemDataSizeByIndex(__in uint32_t u32Index, __out uint32_t *lpu32DataSize);

//Get software data (for access only, do not write)
int           HWNP_GetItemDataPointerByIndex(__in uint32_t u32Index, __out LPCVOID *lppDataPointer);

//Get software data type (whwh / uboot)
int           HWNP_GetItemDataTypeByIndex(__in uint32_t u32Index, __out LPDWORD lpDataType);

//Get the firmware header
int           HWNP_GetFirmwareHeader(__out PHWNP_HEADER lpHeader);

//Get the size of the product support list
int           HWNP_GetProductListSize(__out uint16_t *lpu16PLSize);

//Get product support list
int           HWNP_GetProductList(__inout LPCH lpchProdList, __in uint16_t u16PLSize);

//Set up product support list
int           HWNP_SetProductList(__in LPCCH lpchProdList, __in uint16_t u16PLSize);

//Setting up software data
int           HWNP_SetItemData(__in uint32_t u32Index, __in LPCVOID lpNewData, __in uint32_t u32DataSize);

//Set software information
int           HWNP_SetItemInfo(__in uint32_t u32Index, __in uint32_t u32Mask, __in uint32_t u32Id, __in LPCCH lpchPath, __in LPCCH lpchType, __in LPCCH lpchVersion, __in uint32_t u32Policy, __in uint32_t u32Reserved);

//Get the last ID of the software (unused ID)
uint32_t      HWNP_GetLastItemId();

//Check if there are duplicate IDs
BOOL          HWNP_CheckDuplicate();

//Check CRC (0: No problem, 191: File CRC incorrect, 192: Header CRC incorrect, 200+: software CRC incorrect)
uint32_t      HWNP_CheckCRC32();

//Reorder the software IDs in order
void          HWNP_SortItems(__in BOOL blUpdate);

//Add New Item
int           HWNP_AddItem(__in uint32_t u32Id, __in LPCVOID lpNewData, __in uint32_t u32DataSize, __in LPCCH lpchPath, __in LPCCH lpchType, __in LPCCH lpchVersion, __in uint32_t u32Policy, __in uint32_t u32Reserved);

//Deleting a software
int           HWNP_DeleteItem(__in uint32_t u32Index);

//Save to file
int           HWNP_Save();

//Save to another file
int           HWNP_SaveAs(__in LPCWSTR lpFilePath);

//Calibrate uImage Header CRC32
int           HWNP_CalibrationImageHeaderCrc32(__inout PUIMG_HDR lpImageHdr);
