using System;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Collections.ObjectModel;

namespace PS_Like
{
	class Program
	{
		static void Main(string[] args)
		{
			if (args.Length == 0) HelpMenu();

			// Create a custom runspace
			Runspace rs = RunspaceFactory.CreateRunspace();
			rs.Open();

			// Instantiate a new PowerShell class and set the runspace to our newly created runsapce
			PowerShell ps = PowerShell.Create();
			ps.Runspace = rs;

			string Command;

			switch (args[0].ToLower())
			{
				case "-t":
				case "/t":
					Console.WriteLine("Welcome to my shell\nEnter Exit to exit");
					while (true)
					{
						try
						{
							Console.Write("PS> ");
							Command = Console.ReadLine();

							if (Command == "Exit".ToLower())
							{
								Console.WriteLine("Bye");
								rs.Close();
								Environment.Exit(0);
							}

							ps.Streams.ClearStreams();
							ps.Commands.Clear();

							HandleCommands(rs, ps, Command);

						}
						catch (Exception e)
						{
							Console.ForegroundColor = ConsoleColor.Red;
							Console.WriteLine($"The Execution was failed, the error is:\n {e.Message}");
							Console.ResetColor();
						}
					}

					break;

				case "-c":
				case "/c":
					Command = "";
					foreach (String item in args)
					{
						Command += item + " ";
					}
					Command = Command.Substring(3, Command.Length - 3);

					HandleCommands(rs, ps, Command);
					rs.Close();

					break;

				default:
					rs.Close();
					HelpMenu();
					break;
			}
		}
		private static void HelpMenu()
		{
			Console.WriteLine("No argument supplied\n" +
				"-t	Open a terminal-like of PowerShell\n" +
				"-c	Execute single command and close program");
			Environment.Exit(0);
		}

		private static void HandleCommands(Runspace rs, PowerShell ps, String Command)
		{
			try
			{
				ps.AddScript(Command);
				Collection<PSObject> results = ps.Invoke();


				// Handle all PowerShell Streams
				if (results != null)
				{
					foreach (PSObject output in results)
					{
						Console.WriteLine(output);
					}
				}

				if (ps.Streams.Error.Count != 0)
				{
					Console.ForegroundColor = ConsoleColor.Red;

					foreach (ErrorRecord error in ps.Streams.Error)
					{
						Console.WriteLine(error);
					}

					Console.ResetColor();
				}

				if (ps.Streams.Warning.Count != 0)
				{
					Console.ForegroundColor = ConsoleColor.Magenta;

					foreach (WarningRecord item in ps.Streams.Warning)
					{
						Console.WriteLine(item);
					}

					Console.ResetColor();
				}

				if (ps.Streams.Debug.Count != 0)
				{
					Console.ForegroundColor = ConsoleColor.Green;

					foreach (DebugRecord item in ps.Streams.Debug)
					{
						Console.WriteLine(item);
					}

					Console.ResetColor();
				}

				if (ps.Streams.Verbose.Count != 0)
				{
					Console.ForegroundColor = ConsoleColor.Yellow;

					foreach (VerboseRecord item in ps.Streams.Verbose)
					{
						Console.WriteLine(item);
					}

					Console.ResetColor();
				}

			}
			
			catch (Exception e) 
			{
				Console.ForegroundColor = ConsoleColor.Red;
				Console.WriteLine($"The Execution was failed, the error is:\n {e.Message}");
				Console.ResetColor();
			}
		}

	}
}
