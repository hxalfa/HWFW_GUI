#pragma once

#ifndef _STDINT
#include <stdint.h>
#endif

typedef uint32_t __be32;    //Big-endian unsigned int 32bits

/*
* (C) Copyright 2008 Semihalf
*
* (C) Copyright 2000-2005
* Wolfgang Denk, DENX Software Engineering, wd@denx.de.
*
* See file CREDITS for list of people who contributed to this
* project.
*
* This program is free software; you can redistribute it and/or
* modify it under the terms of the GNU General Public License as
* published by the Free Software Foundation; either version 2 of
* the License, or (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.   See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 59 Temple Place, Suite 330, Boston,
* MA 02111-1307 USA
*
********************************************************************
* NOTE: This header file defines an interface to U-Boot. Including
* this (unmodified) header file in another file is considered normal
* use of U-Boot, and does *not* fall under the heading of "derived
* work".
********************************************************************
*/


/*
* Operating System Codes
*
* The following are exposed to uImage header.
* Do not change values for backward compatibility.
*/
enum IH_OS : uint8_t {
  IH_OS_INVALID = 0,  /* Invalid OS  */
  IH_OS_OPENBSD,      /* OpenBSD  */
  IH_OS_NETBSD,      /* NetBSD  */
  IH_OS_FREEBSD,      /* FreeBSD  */
  IH_OS_4_4BSD,      /* 4.4BSD  */
  IH_OS_LINUX,      /* Linux  */
  IH_OS_SVR4,      /* SVR4    */
  IH_OS_ESIX,      /* Esix    */
  IH_OS_SOLARIS,      /* Solaris  */
  IH_OS_IRIX,      /* Irix    */
  IH_OS_SCO,      /* SCO    */
  IH_OS_DELL,      /* Dell    */
  IH_OS_NCR,      /* NCR    */
  IH_OS_LYNXOS,      /* LynxOS  */
  IH_OS_VXWORKS,      /* VxWorks  */
  IH_OS_PSOS,      /* pSOS    */
  IH_OS_QNX,      /* QNX    */
  IH_OS_U_BOOT,      /* Firmware  */
  IH_OS_RTEMS,      /* RTEMS  */
  IH_OS_ARTOS,      /* ARTOS  */
  IH_OS_UNITY,      /* Unity OS  */
  IH_OS_INTEGRITY,    /* INTEGRITY  */
  IH_OS_OSE,      /* OSE    */
  IH_OS_PLAN9,      /* Plan 9  */
  IH_OS_OPENRTOS,    /* OpenRTOS  */
  IH_OS_ARM_TRUSTED_FIRMWARE,     /* ARM Trusted Firmware */
  IH_OS_TEE,			/* Trusted Execution Environment */

  IH_OS_COUNT,
};

const char * const enum_IH_OS[IH_OS_COUNT] = {
  "Invalid",
  "OpenBSD",
  "NetBSD",
  "FreeBSD",
  "4.4BSD",
  "Linux",
  "SVR4",
  "ESIX",
  "Solaris",
  "Irix",
  "SCO",
  "Dell",
  "NCR",
  "LynxOS",
  "VxWorks",
  "pSOS",
  "QNX",
  "Firmware",
  "RTEMS",
  "ARTOS",
  "Unity OS",
  "INTEGRITY",
  "OSE",
  "Plan 9",
  "OpenRTOS",
  "ARM Trusted Firmware",
  "Trusted Execution Environment"
};

/*
* CPU Architecture Codes (supported by Linux)
*
* The following are exposed to uImage header.
* Do not change values for backward compatibility.
*/
enum IH_ARCH : uint8_t {
  IH_ARCH_INVALID = 0,  /* Invalid CPU  */
  IH_ARCH_ALPHA,      /* Alpha  */
  IH_ARCH_ARM,      /* ARM    */
  IH_ARCH_I386,      /* Intel x86  */
  IH_ARCH_IA64,      /* IA64    */
  IH_ARCH_MIPS,      /* MIPS    */
  IH_ARCH_MIPS64,      /* MIPS   64 Bit */
  IH_ARCH_PPC,      /* PowerPC  */
  IH_ARCH_S390,      /* IBM S390  */
  IH_ARCH_SH,      /* SuperH  */
  IH_ARCH_SPARC,      /* Sparc  */
  IH_ARCH_SPARC64,    /* Sparc 64 Bit */
  IH_ARCH_M68K,      /* M68K    */
  IH_ARCH_NIOS,      /* Nios-32  */
  IH_ARCH_MICROBLAZE,    /* MicroBlaze   */
  IH_ARCH_NIOS2,      /* Nios-II  */
  IH_ARCH_BLACKFIN,    /* Blackfin  */
  IH_ARCH_AVR32,      /* AVR32  */
  IH_ARCH_ST200,      /* STMicroelectronics ST200  */
  IH_ARCH_SANDBOX,    /* Sandbox architecture (test only) */
  IH_ARCH_NDS32,      /* ANDES Technology - NDS32  */
  IH_ARCH_OPENRISC,    /* OpenRISC 1000  */
  IH_ARCH_ARM64,      /* ARM64  */
  IH_ARCH_ARC,      /* Synopsys DesignWare ARC */
  IH_ARCH_X86_64,      /* AMD x86_64, Intel and Via */
  IH_ARCH_XTENSA,      /* Xtensa  */
  IH_ARCH_RISCV,			/* RISC-V */

  IH_ARCH_COUNT,
};

const char * const enum_IH_ARCH[IH_ARCH_COUNT] = {
  "Invalid",
  "Alpha",
  "ARM",
  "Intel x86",
  "IA64",
  "MIPS",
  "MIPS   64 Bit",
  "PowerPC",
  "IBM S390",
  "SuperH",
  "Sparc",
  "Sparc 64 Bit",
  "M68K",
  "Nios-32",
  "MicroBlaze",
  "Nios-II",
  "Blackfin",
  "AVR32",
  "ST200",
  "Sandbox architecture",
  "NDS32",
  "OpenRISC 1000",
  "ARM64",
  "ARC",
  "x86_64",
  "Xtensa",
  "RISC-V"
};


/*
* Image Types
*
* "Standalone Programs" are directly runnable in the environment
*  provided by U-Boot; it is expected that (if they behave
*  well) you can continue to work in U-Boot after return from
*  the Standalone Program.
* "OS Kernel Images" are usually images of some Embedded OS which
*  will take over control completely. Usually these programs
*  will install their own set of exception handlers, device
*  drivers, set up the MMU, etc. - this means, that you cannot
*  expect to re-enter U-Boot except by resetting the CPU.
* "RAMDisk Images" are more or less just data blocks, and their
*  parameters (address, size) are passed to an OS kernel that is
*  being started.
* "Multi-File Images" contain several images, typically an OS
*  (Linux) kernel image and one or more data images like
*  RAMDisks. This construct is useful for instance when you want
*  to boot over the network using BOOTP etc., where the boot
*  server provides just a single image file, but you want to get
*  for instance an OS kernel and a RAMDisk image.
*
*  "Multi-File Images" start with a list of image sizes, each
*  image size (in bytes) specified by an "uint32_t" in network
*  byte order. This list is terminated by an "(uint32_t)0".
*  Immediately after the terminating 0 follow the images, one by
*  one, all aligned on "uint32_t" boundaries (size rounded up to
*  a multiple of 4 bytes - except for the last file).
*
* "Firmware Images" are binary images containing firmware (like
*  U-Boot or FPGA images) which usually will be programmed to
*  flash memory.
*
* "Script files" are command sequences that will be executed by
*  U-Boot's command interpreter; this feature is especially
*  useful when you configure U-Boot to use a real shell (hush)
*  as command interpreter (=> Shell Scripts).
*
* The following are exposed to uImage header.
* Do not change values for backward compatibility.
*/

enum IH_TYPE : uint8_t {
  IH_TYPE_INVALID = 0,  /* Invalid Image    */
  IH_TYPE_STANDALONE,    /* Standalone Program    */
  IH_TYPE_KERNEL,      /* OS Kernel Image    */
  IH_TYPE_RAMDISK,    /* RAMDisk Image    */
  IH_TYPE_MULTI,      /* Multi-File Image    */
  IH_TYPE_FIRMWARE,    /* Firmware Image    */
  IH_TYPE_SCRIPT,      /* Script file      */
  IH_TYPE_FILESYSTEM,    /* Filesystem Image (any type)  */
  IH_TYPE_FLATDT,      /* Binary Flat Device Tree Blob  */
  IH_TYPE_KWBIMAGE,    /* Kirkwood Boot Image    */
  IH_TYPE_IMXIMAGE,    /* Freescale IMXBoot Image  */
  IH_TYPE_UBLIMAGE,    /* Davinci UBL Image    */
  IH_TYPE_OMAPIMAGE,    /* TI OMAP Config Header Image  */
  IH_TYPE_AISIMAGE,    /* TI Davinci AIS Image    */
  /* OS Kernel Image, can run from any load address */
  IH_TYPE_KERNEL_NOLOAD,
  IH_TYPE_PBLIMAGE,    /* Freescale PBL Boot Image  */
  IH_TYPE_MXSIMAGE,    /* Freescale MXSBoot Image  */
  IH_TYPE_GPIMAGE,    /* TI Keystone GPHeader Image  */
  IH_TYPE_ATMELIMAGE,    /* ATMEL ROM bootable Image  */
  IH_TYPE_SOCFPGAIMAGE,    /* Altera SOCFPGA Preloader  */
  IH_TYPE_X86_SETUP,    /* x86 setup.bin Image    */
  IH_TYPE_LPC32XXIMAGE,    /* x86 setup.bin Image    */
  IH_TYPE_LOADABLE,    /* A list of typeless images  */
  IH_TYPE_RKIMAGE,    /* Rockchip Boot Image    */
  IH_TYPE_RKSD,      /* Rockchip SD card    */
  IH_TYPE_RKSPI,      /* Rockchip SPI image    */
  IH_TYPE_ZYNQIMAGE,    /* Xilinx Zynq Boot Image */
  IH_TYPE_ZYNQMPIMAGE,    /* Xilinx ZynqMP Boot Image */
  IH_TYPE_FPGA,      /* FPGA Image */
  IH_TYPE_VYBRIDIMAGE,  /* VYBRID .vyb Image */
  IH_TYPE_TEE,            /* Trusted Execution Environment OS Image */
  IH_TYPE_FIRMWARE_IVT,		/* Firmware Image with HABv4 IVT */
  IH_TYPE_PMMC,            /* TI Power Management Micro-Controller Firmware */
  IH_TYPE_STM32IMAGE,		/* STMicroelectronics STM32 Image */
  IH_TYPE_SOCFPGAIMAGE_V1,	/* Altera SOCFPGA A10 Preloader	*/
  IH_TYPE_MTKIMAGE,		/* MediaTek BootROM loadable Image */
  IH_TYPE_IMX8MIMAGE,		/* Freescale IMX8MBoot Image	*/
  IH_TYPE_IMX8IMAGE,		/* Freescale IMX8Boot Image	*/

  IH_TYPE_COUNT,      /* Number of image types */
};

const char * const enum_IH_TYPE[IH_TYPE_COUNT] = {
  "Invalid",
  "Standalone Program",
  "OS Kernel Image",
  "RAMDisk Image",
  "Multi-File Image",
  "Firmware Image",
  "Script file",
  "Filesystem Image",
  "Binary Flat Device Tree Blob",
  "Kirkwood Boot Image",
  "Freescale IMXBoot Image",
  "Davinci UBL Image",
  "TI OMAP Config Header Image",
  "TI Davinci AIS Image",
  "OS Kernel Image (No load)",
  "Freescale PBL Boot Image",
  "Freescale MXSBoot Image",
  "TI Keystone GPHeader Image",
  "ATMEL ROM bootable Image",
  "Altera SOCFPGA Preloader",
  "x86 setup.bin Image",
  "LPC32XX Boot Image",
  "A list of typeless images",
  "Rockchip Boot Image",
  "Rockchip SD card",
  "Rockchip SPI image",
  "Xilinx Zynq Boot Image",
  "Xilinx ZynqMP Boot Image",
  "FPGA Image",
  "VYBRID .vyb Image",
  "TEE OS Image",
  "HABv4 IVT Image",
  "TI PMMC Firmware",
  "STM32 Image",
  "Altera SOCFPGA A10 Preloader",
  "MediaTek BootROM loadable Image",
  "Freescale IMX8MBoot Image",
  "Freescale IMX8Boot Image"
};


/*
* Compression Types
*
* The following are exposed to uImage header.
* Do not change values for backward compatibility.
*/
enum IH_COMP : uint8_t {
  IH_COMP_NONE = 0,  /*  No   Compression Used  */
  IH_COMP_GZIP,      /* gzip   Compression Used  */
  IH_COMP_BZIP2,      /* bzip2 Compression Used  */
  IH_COMP_LZMA,      /* lzma  Compression Used  */
  IH_COMP_LZO,      /* lzo   Compression Used  */
  IH_COMP_LZ4,      /* lz4   Compression Used  */

  IH_COMP_COUNT,
};

const char * const enum_IH_COMP[IH_COMP_COUNT] = {
  "None",
  "GZip",
  "BZip2",
  "LZMA",
  "LZO",
  "LZ4"
};


#define IH_MAGIC        0x27051956    /* Image Magic Number    */
#define IH_MAGIC_LE     0x56190527    /* Image Magic Number    */
#define IH_NMLEN        32            /* Image Name Length    */


/*
* Legacy format image header,
* all data in network byte order (aka natural aka bigendian).
*/
typedef struct uimage_header {
  __be32    ih_magic; /* Image Header Magic Number  */
  __be32    ih_hcrc;  /* Image Header CRC Checksum  */
  __be32    ih_time;  /* Image Creation Timestamp  */
  __be32    ih_size;  /* Image Data Size    */
  __be32    ih_load;  /* Data   Load  Address    */
  __be32    ih_ep;    /* Entry Point Address    */
  __be32    ih_dcrc;  /* Image Data CRC Checksum  */
  IH_OS     ih_os;    /* Operating System    */
  IH_ARCH   ih_arch;  /* CPU architecture    */
  IH_TYPE   ih_type;  /* Image Type      */
  IH_COMP   ih_comp;  /* Compression Type    */
  char      ih_name[IH_NMLEN];  /* Image Name    */
} uimage_header_t, UIMG_HDR, *PUIMG_HDR;
