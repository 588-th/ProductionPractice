using System.Runtime.InteropServices;

namespace PackerCrypt
{
    /// <summary>
    /// Provides methods for working with Portable Executable (PE) files, including alignment calculations, format checking, and manipulation.
    /// </summary>
    public static class PETools
    {
        /// <summary>
        /// Aligns the given size to the specified alignment.
        /// </summary>
        /// <param name="size">The size to align.</param>
        /// <param name="alignment">The alignment value.</param>
        /// <returns>The aligned size.</returns>
        public static uint AlignSize(uint size, uint alignment)
        {
            if (size % alignment == 0)
                return size;
            else
                return size + (alignment - (size % alignment));
        }

        /// <summary>
        /// Checks whether the provided byte array represents a valid PE file.
        /// </summary>
        /// <param name="image">The byte array representing the PE file.</param>
        /// <returns>True if the file is a valid PE file; otherwise, false.</returns>
        public static bool CheckPE(byte[] image)
        {
            var dos = BitConverter.ToUInt16(image, 0);
            if (dos != 0x5A4D) // "MZ" in hex
            {
                Console.WriteLine("[PETools] Format error! Payload file hasn't DOS signature!");
                return false;
            }

            var lfanew = BitConverter.ToUInt32(image, 0x3C);
            if (lfanew < 0x40)
            {
                Console.WriteLine("[PETools] Format error! Payload PE header not found!");
                return false;
            }

            var signature = BitConverter.ToUInt32(image, (int)lfanew);
            if (signature != 0x4550) // "PE\0\0" in hex
            {
                Console.WriteLine("[PETools] Format error! Payload file hasn't PE signature!");
                return false;
            }

            return true;
        }

        /// <summary>
        /// Retrieves the file header of the PE file from the provided byte array.
        /// </summary>
        /// <param name="image">The byte array representing the PE file.</param>
        /// <returns>The file header of the PE file.</returns>
        public static IMAGE_FILE_HEADER GetPEFileHeader(byte[] image)
        {
            var lfanew = BitConverter.ToUInt32(image, 0x3C);
            var fileHeaderOffset = lfanew + 4; // Skipping PE signature
            return ByteArrayToStructure<IMAGE_FILE_HEADER>(image, (int)fileHeaderOffset);
        }

        /// <summary>
        /// Retrieves the file header of the PE file from the provided byte array.
        /// </summary>
        /// <param name="image">The byte array representing the PE file.</param>
        /// <returns>The file header of the PE file.</returns>
        public static ushort GetPEArch(IMAGE_FILE_HEADER ntHeader)
        {
            return ntHeader.Machine;
        }

        /// <summary>
        /// Retrieves the architecture of the PE file from the provided byte array.
        /// </summary>
        /// <param name="image">The byte array representing the PE file.</param>
        /// <returns>The architecture of the PE file.</returns>
        public static ushort GetPEArch(byte[] image)
        {
            var fileHeader = GetPEFileHeader(image);
            return GetPEArch(fileHeader);
        }

        /// <summary>
        /// Concatenates the provided payload and AES key into the PE file represented by the byte array.
        /// </summary>
        /// <param name="payload">The payload to concatenate.</param>
        /// <param name="payloadSize">The size of the payload.</param>
        /// <param name="aesKey">The AES key to concatenate.</param>
        /// <param name="aesKeySize">The size of the AES key.</param>
        /// <param name="image">The byte array representing the PE file.</param>
        /// <param name="imageSize">The size of the PE file.</param>
        /// <returns>True if the concatenation was successful; otherwise, false.</returns>
        public static bool ConcatPEX64(byte[] payload, uint payloadSize, byte[] aesKey, uint aesKeySize, byte[] image, uint imageSize)
        {
            var dos = ByteArrayToStructure<IMAGE_DOS_HEADER>(image, 0);
            var ntHeader = GetPEFileHeader(image);
            var nt64 = ByteArrayToStructure<IMAGE_NT_HEADERS64>(image, (int)dos.e_lfanew);
            var sectionsCount = ntHeader.NumberOfSections;

            var idata = ByteArrayToStructure<IMAGE_SECTION_HEADER>(image, (int)dos.e_lfanew + Marshal.SizeOf<IMAGE_NT_HEADERS64>());

            var pbPayload = new byte[payloadSize + aesKeySize];
            Array.Copy(payload, 0, pbPayload, 0, payloadSize);
            Array.Copy(aesKey, 0, pbPayload, payloadSize, aesKeySize);

            idata.SizeOfRawData = AlignSize(idata.VirtualSize + payloadSize + aesKeySize, nt64.OptionalHeader.FileAlignment);
            var oldSize = idata.VirtualSize;
            idata.VirtualSize += payloadSize + aesKeySize;
            nt64.OptionalHeader.SizeOfImage = AlignSize(idata.VirtualSize + idata.VirtualAddress, nt64.OptionalHeader.FileAlignment);

            var a = BitConverter.GetBytes(nt64.OptionalHeader.ImageBase + idata.VirtualAddress + oldSize);

            for (int i = 0; i < imageSize - sizeof(ulong); i++)
            {
                if (BitConverter.ToUInt64(image, i) == 0xDEADBEEFFEEDBAFF)
                    Buffer.BlockCopy(BitConverter.GetBytes(nt64.OptionalHeader.ImageBase + idata.VirtualAddress + oldSize), 0, image, i, sizeof(ulong));
                else if (BitConverter.ToUInt32(image, i) == 0xBEEFCACE)
                    Buffer.BlockCopy(BitConverter.GetBytes(payloadSize), 0, image, i, sizeof(uint));
                else if (BitConverter.ToUInt64(image, i) == 0xBAFFCACEBEEFDEAD)
                    Buffer.BlockCopy(BitConverter.GetBytes(nt64.OptionalHeader.ImageBase + idata.VirtualAddress + oldSize + payloadSize), 0, image, i, sizeof(ulong));
            }

            return true;
        }

        /// <summary>
        /// Concatenates the provided payload and AES key into the PE file represented by the byte array.
        /// </summary>
        /// <param name="payload">The payload to concatenate.</param>
        /// <param name="payloadSize">The size of the payload.</param>
        /// <param name="aesKey">The AES key to concatenate.</param>
        /// <param name="aesKeySize">The size of the AES key.</param>
        /// <param name="image">The byte array representing the PE file.</param>
        /// <param name="imageSize">The size of the PE file.</param>
        /// <returns>True if the concatenation was successful; otherwise, false.</returns>
        public static bool ConcatPEX32(byte[] payload, uint payloadSize, byte[] aesKey, uint aesKeySize, byte[] image, uint imageSize)
        {
            var dos = ByteArrayToStructure<IMAGE_DOS_HEADER>(image, 0);
            var ntHeader = GetPEFileHeader(image);
            var nt32 = ByteArrayToStructure<IMAGE_NT_HEADERS32>(image, (int)dos.e_lfanew);
            var sectionsCount = ntHeader.NumberOfSections;

            var idata = ByteArrayToStructure<IMAGE_SECTION_HEADER>(image, (int)dos.e_lfanew + Marshal.SizeOf<IMAGE_NT_HEADERS32>());

            var pbPayload = new byte[payloadSize];
            Array.Copy(payload, 0, pbPayload, 0, payloadSize);
            Array.Copy(aesKey, 0, pbPayload, payloadSize, aesKeySize);

            idata.SizeOfRawData = AlignSize(idata.VirtualSize + payloadSize + aesKeySize, nt32.OptionalHeader.FileAlignment);
            var oldSize = idata.VirtualSize;
            idata.VirtualSize += payloadSize + aesKeySize;
            nt32.OptionalHeader.SizeOfImage = AlignSize(idata.VirtualSize + idata.VirtualAddress, nt32.OptionalHeader.FileAlignment);

            for (int i = 0; i < imageSize; i++)
            {
                if (BitConverter.ToUInt32(image, i) == 0xDEADBEEF)
                    Buffer.BlockCopy(BitConverter.GetBytes(nt32.OptionalHeader.ImageBase + idata.VirtualAddress + oldSize), 0, image, i, sizeof(uint));
                else if (BitConverter.ToUInt32(image, i) == 0xBEEFCACE)
                    Buffer.BlockCopy(BitConverter.GetBytes(payloadSize), 0, image, i, sizeof(uint));
                else if (BitConverter.ToUInt32(image, i) == 0xBAFFCACE)
                    Buffer.BlockCopy(BitConverter.GetBytes(nt32.OptionalHeader.ImageBase + idata.VirtualAddress + oldSize + payloadSize), 0, image, i, sizeof(uint));
            }

            return true;
        }

        /// <summary>
        /// Converts a byte array to a structure of the specified type.
        /// </summary>
        /// <typeparam name="T">The type of structure to convert to.</typeparam>
        /// <param name="bytes">The byte array to convert.</param>
        /// <param name="offset">The offset in the byte array where the structure starts.</param>
        /// <returns>The structure of type T.</returns>
        private static T ByteArrayToStructure<T>(byte[] bytes, int offset) where T : struct
        {
            IntPtr ptr = Marshal.AllocHGlobal(Marshal.SizeOf<T>());
            try
            {
                Marshal.Copy(bytes, offset, ptr, Marshal.SizeOf<T>());
                return Marshal.PtrToStructure<T>(ptr);
            }
            finally
            {
                Marshal.FreeHGlobal(ptr);
            }
        }
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IMAGE_DOS_HEADER
    {
        public ushort e_magic;
        public ushort e_cblp;
        public ushort e_cp;
        public ushort e_crlc;
        public ushort e_cparhdr;
        public ushort e_minalloc;
        public ushort e_maxalloc;
        public ushort e_ss;
        public ushort e_sp;
        public ushort e_csum;
        public ushort e_ip;
        public ushort e_cs;
        public ushort e_lfarlc;
        public ushort e_ovno;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public ushort[] e_res1;
        public ushort e_oemid;
        public ushort e_oeminfo;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
        public ushort[] e_res2;
        public int e_lfanew;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IMAGE_NT_HEADERS32
    {
        public uint Signature;
        public IMAGE_FILE_HEADER FileHeader;
        public IMAGE_OPTIONAL_HEADER32 OptionalHeader;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IMAGE_NT_HEADERS64
    {
        public uint Signature;
        public IMAGE_FILE_HEADER FileHeader;
        public IMAGE_OPTIONAL_HEADER64 OptionalHeader;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IMAGE_FILE_HEADER
    {
        public ushort Machine;
        public ushort NumberOfSections;
        public uint TimeDateStamp;
        public uint PointerToSymbolTable;
        public uint NumberOfSymbols;
        public ushort SizeOfOptionalHeader;
        public ushort Characteristics;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IMAGE_OPTIONAL_HEADER32
    {
        public ushort Magic;
        public byte MajorLinkerVersion;
        public byte MinorLinkerVersion;
        public uint SizeOfCode;
        public uint SizeOfInitializedData;
        public uint SizeOfUninitializedData;
        public uint AddressOfEntryPoint;
        public uint BaseOfCode;
        public uint BaseOfData;
        public uint ImageBase;
        public uint SectionAlignment;
        public uint FileAlignment;
        public ushort MajorOperatingSystemVersion;
        public ushort MinorOperatingSystemVersion;
        public ushort MajorImageVersion;
        public ushort MinorImageVersion;
        public ushort MajorSubsystemVersion;
        public ushort MinorSubsystemVersion;
        public uint Win32VersionValue;
        public uint SizeOfImage;
        public uint SizeOfHeaders;
        public uint CheckSum;
        public ushort Subsystem;
        public ushort DllCharacteristics;
        public uint SizeOfStackReserve;
        public uint SizeOfStackCommit;
        public uint SizeOfHeapReserve;
        public uint SizeOfHeapCommit;
        public uint LoaderFlags;
        public uint NumberOfRvaAndSizes;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public IMAGE_DATA_DIRECTORY[] DataDirectory;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IMAGE_OPTIONAL_HEADER64
    {
        public ushort Magic;
        public byte MajorLinkerVersion;
        public byte MinorLinkerVersion;
        public uint SizeOfCode;
        public uint SizeOfInitializedData;
        public uint SizeOfUninitializedData;
        public uint AddressOfEntryPoint;
        public uint BaseOfCode;
        public ulong ImageBase;
        public uint SectionAlignment;
        public uint FileAlignment;
        public ushort MajorOperatingSystemVersion;
        public ushort MinorOperatingSystemVersion;
        public ushort MajorImageVersion;
        public ushort MinorImageVersion;
        public ushort MajorSubsystemVersion;
        public ushort MinorSubsystemVersion;
        public uint Win32VersionValue;
        public uint SizeOfImage;
        public uint SizeOfHeaders;
        public uint CheckSum;
        public ushort Subsystem;
        public ushort DllCharacteristics;
        public ulong SizeOfStackReserve;
        public ulong SizeOfStackCommit;
        public ulong SizeOfHeapReserve;
        public ulong SizeOfHeapCommit;
        public uint LoaderFlags;
        public uint NumberOfRvaAndSizes;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public IMAGE_DATA_DIRECTORY[] DataDirectory;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IMAGE_DATA_DIRECTORY
    {
        public uint VirtualAddress;
        public uint Size;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IMAGE_SECTION_HEADER
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public byte[] Name;
        public uint VirtualSize;
        public uint VirtualAddress;
        public uint SizeOfRawData;
        public uint PointerToRawData;
        public uint PointerToRelocations;
        public uint PointerToLinenumbers;
        public ushort NumberOfRelocations;
        public ushort NumberOfLinenumbers;
        public uint Characteristics;
    }
}
