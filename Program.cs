using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net;
using System.DirectoryServices;
using System.Security.Principal;
using System.DirectoryServices.ActiveDirectory;
using System.Runtime.InteropServices;


namespace SharpShares
{
    class Program
    {
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
                IPAddress[] ips = System.Net.Dns.GetHostAddresses(computer);
                foreach (IPAddress ip in ips)
                {
                    if (!ip.ToString().Contains(":"))
                    {
                        Console.WriteLine("{0}: {1}", computer, ip);
                    }
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

        public static void GetShares(List<string> computers)
        {
            string[] errors = { "ERROR=53", "ERROR=5" };
            foreach(string computer in computers)
            {
                SHARE_INFO_1[] computerShares = EnumNetShares(computer);
                if (computerShares.Length > 0)
                {
                    List<string> readableShares = new List<string>();
                    List<string> unauthorizedShares = new List<string>();
                    foreach(SHARE_INFO_1 share in computerShares)
                    {
                        try
                        {
                            string path = String.Format("\\\\{0}\\{1}", computer, share.shi1_netname);
                            var files = System.IO.Directory.GetFiles(path);
                            readableShares.Add(share.shi1_netname);
                        }
                        catch
                        {
                            if (!errors.Contains(share.shi1_netname))
                            {
                                unauthorizedShares.Add(share.shi1_netname);
                            }
                        }
                    }
                    if (unauthorizedShares.Count > 0 || readableShares.Count > 0)
                    {
                        Console.WriteLine("Shares for {0}:", computer);
                        if (unauthorizedShares.Count > 0)
                        {
                            Console.WriteLine("\t[--- Unreadable Shares ---]");
                            foreach (string share in unauthorizedShares)
                            {
                                Console.WriteLine("\t\t{0}", share);
                            }
                        }
                        if (readableShares.Count > 0)
                        {
                            Console.WriteLine("\t[--- Listable Shares ---]");
                            foreach (string share in readableShares)
                            {
                                Console.WriteLine("\t\t{0}", share);
                            }
                        }
                    }
                }
            }
        }

        static void Main(string[] args)
        {
            var computers = GetComputers();
            if (args.Contains("ips"))
            {
                GetComputerAddresses(computers);
            }
            else if (args.Contains("shares"))
            {
                GetShares(computers);
            }
            else
            {
                Console.WriteLine("Error: Not enough arguments. Please pass \"ip\" or \"shares\".");
            }
        }
    }
}
