using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net;
using System.DirectoryServices;
using System.Security.Principal;
using System.Security;
using System.DirectoryServices.ActiveDirectory;
using System.Runtime.InteropServices;
using System.Threading;
using System.Security.Permissions;
using System.Security.AccessControl;

namespace SharpShares
{
    class Program
    {
        public static Semaphore MaxThreads { get; set; }

        [DllImport("Netapi32.dll", SetLastError = true)]
        public static extern int NetWkstaGetInfo(string servername, int level, out IntPtr bufptr);

        [DllImport("Netapi32.dll", SetLastError = true)]
        static extern int NetApiBufferFree(IntPtr Buffer);

        [DllImport("Netapi32.dll", CharSet = CharSet.Unicode)]
        private static extern int NetShareEnum(
            StringBuilder ServerName,
            int level,
            ref IntPtr bufPtr,
            uint prefmaxlen,
            ref int entriesread,
            ref int totalentries,
            ref int resume_handle
        );

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct WKSTA_INFO_100
        {
            public int platform_id;
            public string computer_name;
            public string lan_group;
            public int ver_major;
            public int ver_minor;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct SHARE_INFO_0
        {
            public string shi0_netname;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct SHARE_INFO_1
        {
            public string shi1_netname;
            public uint shi1_type;
            public string shi1_remark;
            public SHARE_INFO_1(string sharename, uint sharetype, string remark)
            {
                this.shi1_netname = sharename;
                this.shi1_type = sharetype;
                this.shi1_remark = remark;
            }
            public override string ToString()
            {
                return shi1_netname;
            }
        }

        const uint MAX_PREFERRED_LENGTH = 0xFFFFFFFF;
        const int NERR_Success = 0;

        private enum NetError : uint
        {
            NERR_Success = 0,
            NERR_BASE = 2100,
            NERR_UnknownDevDir = (NERR_BASE + 16),
            NERR_DuplicateShare = (NERR_BASE + 18),
            NERR_BufTooSmall = (NERR_BASE + 23),
        }

        private enum SHARE_TYPE : uint
        {
            STYPE_DISKTREE = 0,
            STYPE_PRINTQ = 1,
            STYPE_DEVICE = 2,
            STYPE_IPC = 3,
            STYPE_SPECIAL = 0x80000000,
        }

        public static SHARE_INFO_1[] EnumNetShares(string Server)
        {
            List<SHARE_INFO_1> ShareInfos = new List<SHARE_INFO_1>();
            int entriesread = 0;
            int totalentries = 0;
            int resume_handle = 0;
            int nStructSize = Marshal.SizeOf(typeof(SHARE_INFO_1));
            IntPtr bufPtr = IntPtr.Zero;
            StringBuilder server = new StringBuilder(Server);
            int ret = NetShareEnum(server, 1, ref bufPtr, MAX_PREFERRED_LENGTH, ref entriesread, ref totalentries, ref resume_handle);
            if (ret == NERR_Success)
            {
                IntPtr currentPtr = bufPtr;
                for (int i = 0; i < entriesread; i++)
                {
                    SHARE_INFO_1 shi1 = (SHARE_INFO_1)Marshal.PtrToStructure(currentPtr, typeof(SHARE_INFO_1));
                    ShareInfos.Add(shi1);
                    currentPtr += nStructSize;
                }
                NetApiBufferFree(bufPtr);
                return ShareInfos.ToArray();
            }
            else
            {
                ShareInfos.Add(new SHARE_INFO_1("ERROR=" + ret.ToString(), 10, string.Empty));
                return ShareInfos.ToArray();
            }
        }

        public static List<DomainController> GetDomainControllers()
        {
            List<DomainController> domainControllers = new List<DomainController>();
            try
            {
                Domain domain = Domain.GetCurrentDomain();
                foreach (DomainController dc in domain.DomainControllers)
                {
                    domainControllers.Add(dc);
                }
            }
            catch { }
            return domainControllers;
        }

        public static void GetComputerAddresses(List<string> computers)
        {
            foreach (string computer in computers)
            {
                try
                {
                    IPAddress[] ips = System.Net.Dns.GetHostAddresses(computer);
                    foreach (IPAddress ip in ips)
                    {
                        if (!ip.ToString().Contains(":"))
                        {
                            Console.WriteLine("{0}: {1}", computer, ip);
                        }
                    }
                }
                catch (Exception ex)
                {
                }
            }
        }

        public static List<string> GetComputers()
        {
            List<string> computerNames = new List<string>();
            List<DomainController> dcs = GetDomainControllers();
            if (dcs.Count > 0)
            {
                try
                {
                    Domain domain = Domain.GetCurrentDomain();
                    //domain.
                    string currentUser = WindowsIdentity.GetCurrent().Name.Split('\\')[1];


                    using (DirectoryEntry entry = new DirectoryEntry(String.Format("LDAP://{0}", dcs[0])))
                    {
                        using (DirectorySearcher mySearcher = new DirectorySearcher(entry))
                        {
                            mySearcher.Filter = ("(objectClass=computer)");

                            // No size limit, reads all objects
                            mySearcher.SizeLimit = 0;

                            // Read data in pages of 250 objects. Make sure this value is below the limit configured in your AD domain (if there is a limit)
                            mySearcher.PageSize = 250;

                            // Let searcher know which properties are going to be used, and only load those
                            mySearcher.PropertiesToLoad.Add("name");

                            foreach (SearchResult resEnt in mySearcher.FindAll())
                            {
                                // Note: Properties can contain multiple values.
                                if (resEnt.Properties["name"].Count > 0)
                                {
                                    string computerName = (string)resEnt.Properties["name"][0];
                                    computerNames.Add(computerName);
                                }
                            }
                        }
                    }
                }
                catch { }
            }
            else
            {
                Console.WriteLine("ERROR: Could not get a list of Domain Controllers.");
            }
            return computerNames;
        }

        public static bool DirectoryHasPermission(string DirectoryPath, FileSystemRights AccessRight)
        {
            if (string.IsNullOrEmpty(DirectoryPath)) return false;

            try
            {
                AuthorizationRuleCollection rules = System.IO.Directory.GetAccessControl(DirectoryPath).GetAccessRules(true, true, typeof(System.Security.Principal.SecurityIdentifier));
                WindowsIdentity identity = WindowsIdentity.GetCurrent();

                foreach (FileSystemAccessRule rule in rules)
                {
                    if (identity.Groups.Contains(rule.IdentityReference) || identity.Owner.Equals(rule.IdentityReference))
                    {
                        if ((AccessRight & rule.FileSystemRights) > 0)
                        {
                            if (rule.AccessControlType == AccessControlType.Allow)
                                return true;
                        }
                    }
                }
            }
            catch
            {
            }
            return false;
        }

        public class SharpShareResult
        {
            public string path { get; set; }
            public string shortname { get; set; }

            public bool writeable { get; set; }

            public bool readable { get; set; }

            public bool inaccessible { get; set; }

            public SharpShareResult(string path_arg, string shortname_arg)
            {

                writeable = false;
                readable = false;
                inaccessible = true;
                path = path_arg;
                shortname = shortname_arg;
            }
            public void set_writeable()
            {
                writeable = true;
                inaccessible = false;
            }
            public void set_readable()
            {
                readable = true;
                inaccessible = false;
            }
            public string print_grepable()
            {
                string return_line = "SharpShare," + path;
                if (writeable)
                {
                    return_line += ",write";
                }
                if (readable)
                {
                    return_line += ",read";
                }

                return return_line;
            }
        }

        public static void GetComputerShares(string computer, bool publicOnly = false, bool grepable = true)
        {
            string[] errors = { "ERROR=53", "ERROR=5" };
            SHARE_INFO_1[] computerShares = EnumNetShares(computer);
            if (computerShares.Length > 0)
            {
                List<SharpShareResult> results = new List<SharpShareResult>();
                foreach (SHARE_INFO_1 share in computerShares)
                {
                    string path = String.Format("\\\\{0}\\{1}", computer, share.shi1_netname);

                    SharpShareResult next_result = new SharpShareResult(path, share.shi1_netname);

                    if (DirectoryHasPermission(path, FileSystemRights.Read))
                    {
                        next_result.set_readable();
                    }
                    if (DirectoryHasPermission(path, FileSystemRights.Write))
                    {
                        next_result.set_writeable();
                    }
                    results.Add(next_result);
                }
                if (grepable)
                {

                    foreach (SharpShareResult result in results)
                    {
                        Console.WriteLine(result.print_grepable());
                    }
                }
                else
                {

                    string output = string.Format("Shares for {0}:\n", computer);

                    string read_output = "";
                    string write_output = "";
                    string denied_output = "";
                    foreach (SharpShareResult result in results)
                    {
                        if (result.writeable)
                        {
                            write_output += string.Format("\t\t{0}\n", result.shortname);

                        }
                        if (result.readable)
                        {
                            read_output += string.Format("\t\t{0}\n", result.shortname);
                        }
                        if (result.inaccessible && !(publicOnly))
                        {
                            denied_output += string.Format("\t\t{0}\n", result.shortname);
                        }
                    }
                    if (!String.IsNullOrEmpty(write_output))
                    {
                        write_output = "\t[--- Writeable Shares ---]\n" + write_output;

                    }
                    if (!String.IsNullOrEmpty(read_output))
                    {
                        read_output = "\t[--- Listable Shares ---]\n" + read_output;

                    }
                    if (!String.IsNullOrEmpty(denied_output))
                    {
                        denied_output = "\t[--- Unreadable Shares ---]\n" + denied_output;
                    }
                    output += read_output + write_output + denied_output;
                    Console.WriteLine(output);

                }
            }
        }

        public static void GetAllShares(List<string> computers, bool publicOnly = false, bool grepable = false)
        {
            List<Thread> runningThreads = new List<Thread>();
            foreach (string computer in computers)
            {
                Thread t = new Thread(() => GetComputerShares(computer, publicOnly, grepable));
                t.Start();
                runningThreads.Add(t);
            }
            foreach (Thread t in runningThreads)
            {
                t.Join();
            }
        }

        static void GetComputerVersions(List<string> computers)
        {
            foreach (string computer in computers)
            {
                Console.WriteLine("Computer: {0}", computer);
                string serverName = String.Format("\\\\{0}", computer);
                Console.WriteLine(serverName);
                IntPtr buffer;
                var ret = NetWkstaGetInfo(serverName, 100, out buffer);
                var strut_size = Marshal.SizeOf(typeof(WKSTA_INFO_100));
                Console.WriteLine("Ret is:");
                Console.WriteLine(ret);
                if (ret == NERR_Success)
                {
                    var info = (WKSTA_INFO_100)Marshal.PtrToStructure(buffer, typeof(WKSTA_INFO_100));
                    if (!string.IsNullOrEmpty(info.computer_name))
                    {
                        Console.WriteLine(info.computer_name);
                        Console.WriteLine(info.platform_id);
                        Console.WriteLine(info.ver_major);
                        Console.WriteLine(info.ver_minor);
                        Console.WriteLine(info.lan_group);
                    }
                }
            }
        }

        static void Main(string[] args)
        {
            bool pubOnly = false;
            bool grepable = false;
            int argcount = 0;
            string mode = "";
            bool mode_selected = false;
            bool pos_arg_seen = false;
            bool flag_seen = false;
            bool is_flag = false;
            bool is_pos_arg = false;
            List<string> computers;

            string[] valid_flags =
            {

                "--shares",
                "--versions",
                "--ips",
                "--grepable",
                "--public-only",
            };

            // set thread pool early
            ThreadPool.SetMaxThreads(10, 10);

            // ensure that: (1) user has not placed any positional arguments before flags
            // easy to do: we should never see a positional argument appear before
            // a flag in the sequence (2) all flags are valid

            foreach (string a in args)
            {
                // check if a is a flag
                if (a.StartsWith("--"))
                {
                    flag_seen = true;
                    if (pos_arg_seen)
                    {
                        Console.WriteLine("Error: Positional arguments should come after flags. Valid example: --shares example.com specterops.io");
                        return;
                    }

                    // check if valid flag
                    if (Array.IndexOf(valid_flags, a) < 0)
                    {
                        Console.WriteLine("Error: invalid flag: " + a);
                        return;
                    }
                }
                else
                {
                    pos_arg_seen = true;
                }
            }

            // process mode flags - note: there should only be ONE of these
            if (args.Contains("--shares"))
            {
                mode = "shares";
                if (mode_selected == true)
                {
                    Console.WriteLine("Error: please choose exactly one of the following modes: --shares, --versions, --ips");
                    return;
                }
                argcount++;
                mode_selected = true;
            }
            if (args.Contains("--versions"))
            {
                mode = "versions";
                if (mode_selected == true)
                {
                    Console.WriteLine("Error: please choose exactly one of the following modes: --shares, --versions, --ips");
                    return;
                }
                argcount++;
                mode_selected = true;
            }
            if (args.Contains("--ips"))
            {
                mode = "ips";
                if (mode_selected == true)
                {
                    Console.WriteLine("Error: please choose exactly one of the following modes: --shares, --versions, --ips");
                    return;
                }
                argcount++;
                mode_selected = true;
            }

            // process flags - any number of these can be selected
            if (args.Contains("--public-only"))
            {
                pubOnly = true;
                argcount++;
            }
            if (args.Contains("--grepable"))
            {
                grepable = true;
                argcount++;
            }

            // process positional arguments - check if user has manually specified a list of computers
            if (args.Length == argcount)
            {

                // if we end up here, it means that we've processed every command line argument
                // and the user has NOT provided a list of computers. Make call to GetComputers()
                // to obtain one.
                computers = GetComputers();
            }
            else
            {

                // otherwise, the user has passed a list of computers via the CLI. Read them.
                computers = new List<string>();
                for (int i = argcount; i < args.Length; i++)
                {
                    computers.Add(args[i]);
                }
            }
            // now that we've set command line options and obtained a list of computers, we need
            // to select and enter a runtime mode
            switch (mode)
            {

                case "shares":
                    GetAllShares(computers, pubOnly, grepable);
                    break;
                case "versions":
                    GetComputerVersions(computers);
                    break;
                case "ips":
                    GetComputerAddresses(computers);
                    break;
                default:
                    // default to error message if no mode selected
                    Console.WriteLine("Error: Not enough arguments. Please pass \"ips\" or \"shares\".");
                    break;
            }
        }
    }
}
