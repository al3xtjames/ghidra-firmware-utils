/** @file

Copyright (c) 2004 - 2008, Intel Corporation. All rights reserved.<BR>
This program and the accompanying materials
are licensed and made available under the terms and conditions of the BSD License
which accompanies this distribution.  The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

Module Name:

  Decompress.c

Abstract:

  Decompressor. Algorithm Ported from OPSD code (Decomp.asm)
  for Efi and Tiano compress algorithm.

--*/

// Build the utility by default
#if !defined(CONFIG_FUZZ) && !defined(CONFIG_JNI)
#define CONFIG_UTIL 1
#endif // !CONFIG_FUZZ && !CONFIG_UTIL

#ifdef CONFIG_UTIL
#include <errno.h>
#include <stdio.h>
#include <string.h>
#endif // CONFIG_UTIL

#ifdef CONFIG_JNI
#include <jni.h>
#endif // CONFIG_JNI

#include <stdlib.h>

#include "efidecompress.h"

//
// Decompression algorithm begins here
//
#define BITBUFSIZ 32
#define MAXMATCH  256
#define THRESHOLD 3
#define CODE_BIT  16
#define BAD_TABLE - 1
#define MPTTABLESIZE 256u
#define MCTABLESIZE 4096u

//
// C: Char&Len Set; P: Position Set; T: exTra Set
//
#define NC      (0xff + MAXMATCH + 2 - THRESHOLD)
#define CBIT    9
#define EFIPBIT 4
#define MAXPBIT 5
#define TBIT    5
#define MAXNP ((1U << MAXPBIT) - 1)
#define NT    (CODE_BIT + 3)
#if NT > MAXNP
#define NPT NT
#else
#define NPT MAXNP
#endif


typedef struct {
  const uint8_t  *mSrcBase;  // Starting address of compressed data
  uint8_t        *mDstBase;  // Starting address of decompressed data
  size_t         mOutBuf;
  size_t         mInBuf;

  uint16_t       mBitCount;
  size_t         mBitBuf;
  size_t         mSubBitBuf;
  uint16_t       mBlockSize;
  size_t         mCompSize;
  size_t         mOrigSize;

  uint16_t       mBadTableFlag;
  uint16_t       mBadAlgorithm;

  uint16_t       mLeft[2 * NC - 1];
  uint16_t       mRight[2 * NC - 1];
  uint8_t        mCLen[NC];
  uint8_t        mPTLen[NPT];
  uint16_t       mCTable[MCTABLESIZE];
  uint16_t       mPTTable[MPTTABLESIZE];
} SCRATCH_DATA;

static uint16_t mPbit = EFIPBIT;

static
void
FillBuf (
  SCRATCH_DATA  *Sd,
  uint16_t      NumOfBits
  )
/*++

Routine Description:

  Shift mBitBuf NumOfBits left. Read in NumOfBits of bits from source.

Arguments:

  Sd        - The global scratch data
  NumOfBit  - The number of bits to shift and read.

Returns: (void)

--*/
{
  if (NumOfBits > BITBUFSIZ) {
    NumOfBits = BITBUFSIZ;
    Sd->mBadTableFlag = 1;
  }

  Sd->mBitBuf = (Sd->mBitBuf << NumOfBits) & 0xFFFFFFFFLL;

  while (NumOfBits > Sd->mBitCount) {
    Sd->mBitBuf |= Sd->mSubBitBuf << (NumOfBits = (uint16_t) (NumOfBits - Sd->mBitCount));

    if (Sd->mCompSize > 0) {
      //
      // Get 1 byte into SubBitBuf
      //
      Sd->mCompSize--;
      Sd->mSubBitBuf  = 0;
      Sd->mSubBitBuf  = Sd->mSrcBase[Sd->mInBuf++];
      Sd->mBitCount   = 8;
    } else {
      //
      // No more bits from the source, just pad zero bit.
      //
      Sd->mSubBitBuf  = 0;
      Sd->mBitCount   = 8;
    }
  }

  Sd->mBitCount = (uint16_t) (Sd->mBitCount - NumOfBits);
  Sd->mBitBuf |= Sd->mSubBitBuf >> Sd->mBitCount;
}

static
size_t
GetBits (
  SCRATCH_DATA  *Sd,
  uint16_t      NumOfBits
  )
/*++

Routine Description:

  Get NumOfBits of bits out from mBitBuf. Fill mBitBuf with subsequent
  NumOfBits of bits from source. Returns NumOfBits of bits that are
  popped out.

Arguments:

  Sd            - The global scratch data.
  NumOfBits     - The number of bits to pop and read.

Returns:

  The bits that are popped out.

--*/
{
  size_t  OutBits;

  if (NumOfBits > BITBUFSIZ) {
    NumOfBits = BITBUFSIZ;
    Sd->mBadTableFlag = 1;
  }

  OutBits = (Sd->mBitBuf >> (BITBUFSIZ - NumOfBits));

  FillBuf (Sd, NumOfBits);

  return OutBits;
}

static
uint16_t
MakeTable (
  SCRATCH_DATA   *Sd,
  uint16_t       NumOfChar,
  const uint8_t  *BitLen,
  uint16_t       TableBits,
  uint16_t       *Table
  )
/*++

Routine Description:

  Creates Huffman Code mapping table according to code length array.

Arguments:

  Sd        - The global scratch data
  NumOfChar - Number of symbols in the symbol set
  BitLen    - Code length array
  TableBits - The width of the mapping table
  Table     - The table

Returns:

  0         - OK.
  BAD_TABLE - The table is corrupted.

--*/
{
  uint16_t  Count[17];
  uint16_t  Weight[17];
  uint16_t  Start[18];
  uint16_t  Pointer;
  uint16_t  *TableReference;
  uint16_t  TableSize;
  uint16_t  Index3;
  uint16_t  Index;
  uint16_t  Len;
  uint16_t  Char;
  uint16_t  JuBits;
  uint16_t  Avail;
  uint16_t  NextCode;
  uint16_t  Mask;

  TableSize = (uint16_t) (1U << TableBits);

  for (Index = 0; Index <= 16; Index++) {
    Count[Index] = 0;
  }

  for (Index = 0; Index < NumOfChar; Index++) {
    if (BitLen[Index] >= 17) {
      Sd->mBadTableFlag = 1;
      return (uint16_t) BAD_TABLE;
    }

    Count[BitLen[Index]]++;
  }

  Start[1] = 0;

  for (Index = 1; Index <= 16; Index++) {
    Start[Index + 1] = (uint16_t) (Start[Index] + (Count[Index] << (16 - Index)));
  }

  if (Start[17] != 0) {
    return (uint16_t) BAD_TABLE;
  }

  JuBits = (uint16_t) (16 - TableBits);

  for (Index = 1; Index <= TableBits; Index++) {
    Start[Index] >>= JuBits;
    Weight[Index] = (uint16_t) (1U << (TableBits - Index));
  }

  while (Index <= 16) {
    Weight[Index] = (uint16_t) (1U << (16 - Index));
    Index++;
  }

  Index = (uint16_t) (Start[TableBits + 1] >> JuBits);

  if (Index != 0) {
    while (Index != TableSize) {
      Table[Index++] = 0;
    }
  }

  Avail = NumOfChar;
  Mask  = (uint16_t) (1U << (15 - TableBits));

  for (Char = 0; Char < NumOfChar; Char++) {
    Len = BitLen[Char];
    if (Len == 0) {
      continue;
    }

    NextCode = (uint16_t) (Start[Len] + Weight[Len]);

    if (Len <= TableBits) {
      for (Index = Start[Len]; Index < NextCode; Index++) {
        if (Index >= TableSize) {
          Sd->mBadAlgorithm = 1;
          return (uint16_t) BAD_TABLE;
        }

        Table[Index] = Char;
      }
    } else {
      Index3  = Start[Len];
      Pointer = Index3 >> JuBits;
      TableReference = Table;
      Index   = (uint16_t) (Len - TableBits);

      while (Index != 0) {
        if (TableReference[Pointer] == 0) {
          Sd->mRight[Avail] = Sd->mLeft[Avail] = 0;
          TableReference[Pointer] = Avail++;
        }

        if (Index3 & Mask) {
          Pointer = TableReference[Pointer];
          TableReference = Sd->mRight;
        } else {
          Pointer = TableReference[Pointer];
          TableReference = Sd->mLeft;
        }

        Index3 <<= 1;
        Index--;
      }

      TableReference[Pointer] = Char;
    }

    Start[Len] = NextCode;
  }
  //
  // Succeeds
  //
  return 0;
}

static
size_t
DecodeP (
  SCRATCH_DATA  *Sd
  )
/*++

Routine Description:

  Decodes a position value.

Arguments:

  Sd      - the global scratch data

Returns:

  The position value decoded.

--*/
{
  uint16_t  Val;
  size_t    Mask;
  size_t    Pos;

  Val = Sd->mPTTable[Sd->mBitBuf >> (BITBUFSIZ - 8)];

  if (Val >= MAXNP) {
    Mask = 1U << (BITBUFSIZ - 1 - 8);

    do {
      if (Sd->mBitBuf & Mask) {
        Val = Sd->mRight[Val];
      } else {
        Val = Sd->mLeft[Val];
      }

      Mask >>= 1;
    } while (Val >= MAXNP);
  }
  //
  // Advance what we have read
  //
  FillBuf (Sd, Sd->mPTLen[Val]);

  Pos = Val;
  if (Val > 1) {
    Pos = ((1LL << (Val - 1)) + GetBits (Sd, (uint16_t) (Val - 1)));
  }

  return Pos;
}

static
uint16_t
ReadPTLen (
  SCRATCH_DATA  *Sd,
  uint16_t      nn,
  uint16_t      nbit,
  uint16_t      Special
  )
/*++

Routine Description:

  Reads code lengths for the Extra Set or the Position Set

Arguments:

  Sd        - The global scratch data
  nn        - Number of symbols
  nbit      - Number of bits needed to represent nn
  Special   - The special symbol that needs to be taken care of

Returns:

  0         - OK.
  BAD_TABLE - Table is corrupted.

--*/
{
  uint16_t  Number;
  uint16_t  CharC;
  uint16_t  Index;
  size_t    Mask;

  Number = (uint16_t) GetBits (Sd, nbit);

  if (Number == 0) {
    CharC = (uint16_t) GetBits (Sd, nbit);

    for (Index = 0; Index < MPTTABLESIZE; Index++) {
      Sd->mPTTable[Index] = CharC;
    }

    for (Index = 0; Index < nn; Index++) {
      Sd->mPTLen[Index] = 0;
    }

    return 0;
  }

  Index = 0;

  while (Index < Number) {
    CharC = (uint16_t) (Sd->mBitBuf >> (BITBUFSIZ - 3));

    if (CharC == 7) {
      Mask = 1U << (BITBUFSIZ - 1 - 3);
      while (Mask & Sd->mBitBuf) {
        Mask >>= 1;
        CharC += 1;
      }
    }

    FillBuf (Sd, (uint16_t) ((CharC < 7) ? 3 : CharC - 3));

    Sd->mPTLen[Index++] = (uint8_t) CharC;

    if (Index == Special) {
      CharC = (uint16_t) GetBits (Sd, 2);
      CharC--;
      while ((int16_t) (CharC) >= 0) {
        if (Index >= NPT) {
          Sd->mBadTableFlag = 1;
          return (uint16_t) BAD_TABLE;
        }

        Sd->mPTLen[Index++] = 0;
        CharC--;
      }
    }
  }

  while (Index < nn) {
    Sd->mPTLen[Index++] = 0;
  }

  return MakeTable (Sd, nn, Sd->mPTLen, 8, Sd->mPTTable);
}

static
void
ReadCLen (
  SCRATCH_DATA  *Sd
  )
/*++

Routine Description:

  Reads code lengths for Char&Len Set.

Arguments:

  Sd    - the global scratch data

Returns: (void)

--*/
{
  uint16_t  Number;
  uint16_t  CharC;
  uint16_t  Index;
  size_t    Mask;

  Number = (uint16_t) GetBits (Sd, CBIT);

  if (Number == 0) {
    CharC = (uint16_t) GetBits (Sd, CBIT);

    for (Index = 0; Index < NC; Index++) {
      Sd->mCLen[Index] = 0;
    }

    for (Index = 0; Index < 4096; Index++) {
      Sd->mCTable[Index] = CharC;
    }

    return ;
  }

  Index = 0;
  while (Index < Number) {
    CharC = Sd->mPTTable[Sd->mBitBuf >> (BITBUFSIZ - 8)];
    if (CharC >= NT) {
      Mask = 1U << (BITBUFSIZ - 1 - 8);

      do {
        if (Mask & Sd->mBitBuf) {
          CharC = Sd->mRight[CharC];
        } else {
          CharC = Sd->mLeft[CharC];
        }

        Mask >>= 1;
      } while (CharC >= NT);
    }
    //
    // Advance what we have read
    //
    FillBuf (Sd, Sd->mPTLen[CharC]);

    if (CharC <= 2) {
      if (CharC == 0) {
        CharC = 1;
      } else if (CharC == 1) {
        CharC = (uint16_t) (GetBits (Sd, 4) + 3);
      } else if (CharC == 2) {
        CharC = (uint16_t) (GetBits (Sd, CBIT) + 20);
      }

      CharC--;
      while ((int16_t) (CharC) >= 0) {
        if (Index >= NC) {
          Sd->mBadTableFlag = 1;
          return;
        }

        Sd->mCLen[Index++] = 0;
        CharC--;
      }
    } else {
      if (Index >= NC) {
        Sd->mBadTableFlag = 1;
        return;
      }

      Sd->mCLen[Index++] = (uint8_t) (CharC - 2);
    }
  }

  while (Index < NC) {
    Sd->mCLen[Index++] = 0;
  }

  MakeTable (Sd, NC, Sd->mCLen, 12, Sd->mCTable);
}

static
uint16_t
DecodeC (
  SCRATCH_DATA  *Sd
  )
/*++

Routine Description:

  Decode a character/length value.

Arguments:

  Sd    - The global scratch data.

Returns:

  The value decoded.

--*/
{
  uint16_t  Index2;
  size_t    Mask;

  if (Sd->mBlockSize == 0) {
    //
    // Starting a new block
    //
    Sd->mBlockSize    = (uint16_t) GetBits (Sd, 16);
    Sd->mBadTableFlag = ReadPTLen (Sd, NT, TBIT, 3);
    if (Sd->mBadTableFlag != 0) {
      return 0;
    }

    ReadCLen (Sd);

    Sd->mBadTableFlag = ReadPTLen (Sd, MAXNP, mPbit, (uint16_t) (-1));
    if (Sd->mBadTableFlag != 0) {
      return 0;
    }
  }

  Sd->mBlockSize--;
  Index2 = Sd->mCTable[Sd->mBitBuf >> (BITBUFSIZ - 12)];
  if (Index2 >= NC) {
    Mask = 1U << (BITBUFSIZ - 1 - 12);

    do {
      if (Sd->mBitBuf & Mask) {
        Index2 = Sd->mRight[Index2];
      } else {
        Index2 = Sd->mLeft[Index2];
      }

      Mask >>= 1;
    } while (Index2 >= NC);
  }
  //
  // Advance what we have read
  //
  FillBuf (Sd, Sd->mCLen[Index2]);

  return Index2;
}

static
void
Decode (
  SCRATCH_DATA  *Sd
  )
/*++

Routine Description:

  Decode the source data and put the resulting data into the destination buffer.

Arguments:

  Sd            - The global scratch data

Returns: (void)

 --*/
{
  uint16_t  BytesRemain;
  uint64_t  DataIdx;
  uint16_t  CharC;

  BytesRemain = (uint16_t) (-1);

  DataIdx     = 0;

  while(1) {
    CharC = DecodeC (Sd);
    if (Sd->mBadTableFlag != 0) {
      return ;
    }

    if (CharC < 256) {
      //
      // Process an Original character
      //
      Sd->mDstBase[Sd->mOutBuf++] = (uint8_t) CharC;
      if (Sd->mOutBuf >= Sd->mOrigSize) {
        return;
      }

    } else {
      //
      // Process a Pointer
      //
      CharC       = (uint16_t) (CharC - (UINT8_MAX + 1 - THRESHOLD));

      BytesRemain = CharC;

      DataIdx     = Sd->mOutBuf - DecodeP (Sd) - 1;
      // If this is not the correct decompression algorithm, this is an overflow possibility.
      if (DataIdx > Sd->mOrigSize) {
        Sd->mBadAlgorithm = 1;
        return;
      }

      BytesRemain--;
      while ((int16_t) (BytesRemain) >= 0) {
        Sd->mDstBase[Sd->mOutBuf++] = Sd->mDstBase[DataIdx++];
        if (Sd->mOutBuf >= Sd->mOrigSize) {
          return;
        }
        BytesRemain--;
      }
    }
  }
}

RETURN_STATUS
GetInfo (
  const void  *Source,
  size_t      SrcSize,
  size_t      *DstSize,
  size_t      *ScratchSize
  )
/*++

Routine Description:

  The implementation of EFI_DECOMPRESS_PROTOCOL.GetInfo().

Arguments:

  Source      - The source buffer containing the compressed data.
  SrcSize     - The size of source buffer
  DstSize     - The size of destination buffer.
  ScratchSize - The size of scratch buffer.

Returns:

  RETURN_SUCCESS           - The size of destination buffer and the size of scratch buffer are successull retrieved.
  RETURN_INVALID_PARAMETER - The source data is corrupted

--*/
{
  const uint8_t *Src;

  *ScratchSize  = sizeof (SCRATCH_DATA);

  Src           = Source;
  if (SrcSize < 8) {
    return RETURN_INVALID_PARAMETER;
  }

  *DstSize = (size_t) (Src[4]) + ((size_t) (Src[5]) << 8) + ((size_t) (Src[6]) << 16) + ((size_t) (Src[7]) << 24);
  return RETURN_SUCCESS;
}

RETURN_STATUS
Decompress (
  const void  *Source,
  size_t      SrcSize,
  void        *Destination,
  size_t      DstSize,
  void        *Scratch,
  size_t      ScratchSize
  )
/*

Routine Description:

  The implementation Efi and Tiano Decompress().

Arguments:

  Source      - The source buffer containing the compressed data.
  SrcSize     - The size of source buffer
  Destination - The destination buffer to store the decompressed data
  DstSize     - The size of destination buffer.
  Scratch     - The buffer used internally by the decompress routine. This  buffer is needed to store intermediate data.
  ScratchSize - The size of scratch buffer.

Returns:

  RETURN_SUCCESS           - Decompression is successfull
  RETURN_INVALID_PARAMETER - The source data is corrupted

--*/
{
  size_t         Index;
  size_t         CompSize;
  size_t         OrigSize;
  RETURN_STATUS  Status;
  SCRATCH_DATA   *Sd;
  const uint8_t  *Src;
  uint8_t        *Dst;

  Status  = RETURN_SUCCESS;
  Src     = Source;
  Dst     = Destination;

  if (ScratchSize < sizeof (SCRATCH_DATA)) {
    return RETURN_INVALID_PARAMETER;
  }

  Sd = (SCRATCH_DATA *) Scratch;

  if (SrcSize < 8) {
    return RETURN_INVALID_PARAMETER;
  }

  CompSize = (size_t) (Src[0]) + ((size_t) (Src[1]) << 8) + ((size_t) (Src[2]) << 16) + ((size_t) (Src[3]) << 24);
  OrigSize = (size_t) (Src[4]) + ((size_t) (Src[5]) << 8) + ((size_t) (Src[6]) << 16) + ((size_t) (Src[7]) << 24);

  if (SrcSize < CompSize + 8) {
    return RETURN_INVALID_PARAMETER;
  }

  if (DstSize != OrigSize) {
    return RETURN_INVALID_PARAMETER;
  }

  Src = Src + 8;

  for (Index = 0; Index < ScratchSize; Index++) {
    ((uint8_t *) Sd)[Index] = 0;
  }

  Sd->mSrcBase  = Src;
  Sd->mDstBase  = Dst;
  Sd->mCompSize = CompSize;
  Sd->mOrigSize = DstSize;

  //
  // Fill the first BITBUFSIZ bits
  //
  FillBuf (Sd, BITBUFSIZ);

  //
  // Decompress it
  //
  Decode (Sd);

  if (Sd->mBadTableFlag != 0 || Sd->mBadAlgorithm != 0) {
    //
    // Something wrong with the source
    //
    Status = RETURN_INVALID_PARAMETER;
  }
  return Status;
}

RETURN_STATUS
EfiGetInfo (
  const void  *Source,
  size_t      SrcSize,
  size_t      *DstSize,
  size_t      *ScratchSize
  )
/*++

Routine Description:

  The implementation Efi Decompress GetInfo().

Arguments:

  Source      - The source buffer containing the compressed data.
  SrcSize     - The size of source buffer
  DstSize     - The size of destination buffer.
  ScratchSize - The size of scratch buffer.

Returns:

  EFI_SUCCESS           - The size of destination buffer and the size of scratch buffer are successull retrieved.
  EFI_INVALID_PARAMETER - The source data is corrupted

--*/
{
  return GetInfo (Source, SrcSize, DstSize, ScratchSize);
}

RETURN_STATUS
TianoGetInfo ( //-V524
  const void  *Source,
  size_t      SrcSize,
  size_t      *DstSize,
  size_t      *ScratchSize
  )
/*++

Routine Description:

  The implementation Tiano Decompress GetInfo().

Arguments:

  Source      - The source buffer containing the compressed data.
  SrcSize     - The size of source buffer
  DstSize     - The size of destination buffer.
  ScratchSize - The size of scratch buffer.

Returns:

  EFI_SUCCESS           - The size of destination buffer and the size of scratch buffer are successull retrieved.
  EFI_INVALID_PARAMETER - The source data is corrupted

--*/
{
  return GetInfo (Source, SrcSize, DstSize, ScratchSize);
}

RETURN_STATUS
EfiDecompress (
  const void  *Source,
  size_t      SrcSize,
  void        *Destination,
  size_t      DstSize,
  void        *Scratch,
  size_t      ScratchSize
  )
/*++

Routine Description:

  The implementation of Efi Decompress().

Arguments:

  Source      - The source buffer containing the compressed data.
  SrcSize     - The size of source buffer
  Destination - The destination buffer to store the decompressed data
  DstSize     - The size of destination buffer.
  Scratch     - The buffer used internally by the decompress routine. This  buffer is needed to store intermediate data.
  ScratchSize - The size of scratch buffer.

Returns:

  EFI_SUCCESS           - Decompression is successfull
  EFI_INVALID_PARAMETER - The source data is corrupted

--*/
{
  mPbit = EFIPBIT;
  return Decompress (Source, SrcSize, Destination, DstSize, Scratch, ScratchSize);
}

RETURN_STATUS
TianoDecompress (
  const void  *Source,
  size_t      SrcSize,
  void        *Destination,
  size_t      DstSize,
  void        *Scratch,
  size_t      ScratchSize
  )
/*++

Routine Description:

  The implementation of Tiano Decompress().

Arguments:

  Source      - The source buffer containing the compressed data.
  SrcSize     - The size of source buffer
  Destination - The destination buffer to store the decompressed data
  DstSize     - The size of destination buffer.
  Scratch     - The buffer used internally by the decompress routine. This  buffer is needed to store intermediate data.
  ScratchSize - The size of scratch buffer.

Returns:

  EFI_SUCCESS           - Decompression is successfull
  EFI_INVALID_PARAMETER - The source data is corrupted

--*/
{
  mPbit = MAXPBIT;
  return Decompress (Source, SrcSize, Destination, DstSize, Scratch, ScratchSize);
}

#ifdef CONFIG_FUZZ
// LLVM libFuzzer target
// clang -std=c11 -Wall -Wextra -O0 -g -fsanitize=address,fuzzer,leak,undefined -DCONFIG_FUZZ -o efidecompress_fuzz efidecompress.c
// ./efidecompress_fuzz <corpus>
// Compressed EFI images should be used for the corpus.
int
LLVMFuzzerTestOneInput (
  const uint8_t  *Data,
  size_t         Size
  )
{
  size_t OutputSize;
  size_t ScratchSize;

  if (EfiGetInfo (Data, Size, &OutputSize, &ScratchSize) != RETURN_SUCCESS) {
    return 0;
  }

  // Use 64 MiB as a maximum output size
  if (OutputSize > 64 * 1024 * 1024) {
    return 0;
  }

  uint8_t *OutputBuf = malloc (OutputSize * sizeof (uint8_t));
  if (!OutputBuf) {
    return 0;
  }

  uint8_t *ScratchBuf = malloc (ScratchSize * sizeof (uint8_t));
  if (!ScratchBuf) {
    free (OutputBuf);
    return 0;
  }

  EfiDecompress (Data, Size, OutputBuf, OutputSize, ScratchBuf, ScratchSize);

  free (ScratchBuf);
  free (OutputBuf);
  return 0;
}
#endif // CONFIG_FUZZ

#ifdef CONFIG_JNI
// JNI implementation with the following signature:
// static byte[] EFIDecompressor.nativeDecompress(byte[] compressedImage)
JNIEXPORT
jbyteArray
JNICALL
Java_firmware_common_EFIDecompressor_nativeDecompress (
  JNIEnv      *Env,
  jclass      Class,
  jbyteArray  CompressedImageArray
  )
{
  // Get the contents of the compressed image.
  jsize CompressedImageSize = (*Env)->GetArrayLength (Env, CompressedImageArray);
  jbyte *CompressedImage = (*Env)->GetByteArrayElements (Env, CompressedImageArray, 0);
  if (!CompressedImage) {
    return NULL;
  }

  // Retrieve information about the compressed image.
  size_t DstSize;
  size_t ScratchSize;
  if (EfiGetInfo (
        CompressedImage,
        CompressedImageSize,
        &DstSize,
        &ScratchSize
        )
      != RETURN_SUCCESS) {
    (*Env)->ReleaseByteArrayElements (Env, CompressedImageArray, CompressedImage, 0);
    return NULL;
  }

  // Allocate memory for the uncompressed image buffer.
  jbyte *Buf = malloc (DstSize);
  if (!Buf) {
    (*Env)->ReleaseByteArrayElements (Env, CompressedImageArray, CompressedImage, 0);
    return NULL;
  }

  // Allocate memory for the scratch data.
  uint8_t *Sd = malloc (ScratchSize);
  if (!Sd) {
    free (Buf);
    (*Env)->ReleaseByteArrayElements (Env, CompressedImageArray, CompressedImage, 0);
    return NULL;
  }

  // Decompress the image.
  if (EfiDecompress (
        CompressedImage,
        CompressedImageSize,
        (uint8_t *) Buf,
        DstSize,
        Sd,
        ScratchSize
        )
      != RETURN_SUCCESS) {
    free (Sd);
    free (Buf);
    (*Env)->ReleaseByteArrayElements (Env, CompressedImageArray, CompressedImage, 0);
  }

  // Construct a Java byte array to store the decompressed image.
  (*Env)->ReleaseByteArrayElements (Env, CompressedImageArray, CompressedImage, 0);
  jbyteArray DecompressedImageArray = (*Env)->NewByteArray (Env, DstSize);
  if (!DecompressedImageArray) {
    free (Sd);
    free (Buf);
    return NULL;
  }

  // Copy the contents of the decompressed image buffer to the Java byte array.
  (*Env)->SetByteArrayRegion (Env, DecompressedImageArray, 0, DstSize, Buf);
  free (Sd);
  free (Buf);
  return DecompressedImageArray;
}
#endif // CONFIG_JNI

#ifdef CONFIG_UTIL
int
main (
  int   argc,
  char  *argv[]
  )
{
  if (argc != 3) {
    fprintf (stderr, "Usage: efidecompress <compressed input file> <output file>\n");
    return 1;
  }

  FILE *InputFile = fopen (argv[1], "rb");
  if (!InputFile) {
    fprintf (stderr, "Failed to open %s: %s\n", argv[1], strerror (errno));
    return 1;
  }

  fseek (InputFile, 0, SEEK_END);
  size_t InputSize = ftell (InputFile);
  rewind (InputFile);

  uint8_t *InputBuf = malloc (InputSize * sizeof (uint8_t));
  if (fread (InputBuf, sizeof (uint8_t), InputSize, InputFile) != InputSize) {
    fprintf (stderr, "Failed to read %s\n", argv[1]);
    free (InputBuf);
    fclose (InputFile);
    return 1;
  }

  size_t OutputSize;
  size_t ScratchSize;
  if (EfiGetInfo (InputBuf, InputSize, &OutputSize, &ScratchSize) != RETURN_SUCCESS) {
    fprintf (stderr, "Failed to get compression info\n");
    free (InputBuf);
    fclose (InputFile);
    return 1;
  }

  printf ("Compressed size is %zu bytes, uncompressed size is %zu bytes\n",
          InputSize - 8, OutputSize);

  uint8_t *OutputBuf = malloc (OutputSize * sizeof (uint8_t));
  if (!OutputBuf) {
    fprintf (stderr, "Failed to allocate memory for output buffer\n");
    free (InputBuf);
    fclose (InputFile);
  }

  uint8_t *ScratchBuf = malloc (ScratchSize * sizeof (uint8_t));
  if (!ScratchBuf) {
    fprintf (stderr, "Failed to allocate memory for scratch buffer\n");
    free (OutputBuf);
    free (InputBuf);
    fclose (InputFile);
  }

  if (EfiDecompress (InputBuf, InputSize, OutputBuf, OutputSize,
                     ScratchBuf, ScratchSize) != RETURN_SUCCESS) {
    fprintf (stderr, "Failed to decompress input\n");
    free (ScratchBuf);
    free (OutputBuf);
    free (InputBuf);
    fclose (InputFile);
    return 1;
  }

  FILE *OutputFile = fopen (argv[2], "wb");
  if (!OutputFile) {
    fprintf (stderr, "Failed to open %s: %s\n", argv[2], strerror (errno));
    free (ScratchBuf);
    free (OutputBuf);
    free (InputBuf);
    fclose (InputFile);
  }

  if (fwrite (OutputBuf, sizeof (uint8_t), OutputSize, OutputFile) != OutputSize) {
    fprintf (stderr, "Failed to write %s\n", argv[2]);
    fclose (OutputFile);
    free (ScratchBuf);
    free (OutputBuf);
    free (InputBuf);
    fclose (InputFile);
  }

  printf ("Wrote %zu bytes to %s\n", OutputSize, argv[2]);

  fclose (OutputFile);
  free (ScratchBuf);
  free (OutputBuf);
  free (InputBuf);
  fclose (InputFile);

  return 0;
}
#endif // CONFIG_UTIL
