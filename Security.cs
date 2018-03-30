//Getting device Information takes alot of time
//so I'm making then static
//so It Compute only once 

using System.Text;
using System.Management;
using System.Security.Cryptography;

namespace Security
{
    public class ComputerFingerPrint
    {
        private static string s_fingerPrint = string.Empty;

        private static string FingerPrint { get => s_fingerPrint; set => s_fingerPrint = value; }
        public static string Value
        {
            get
            {
                if (string.IsNullOrEmpty(FingerPrint))
                {
                    FingerPrint = GetHash("CPU >> " + CpuId() + "\nBIOS >> " +
                BiosId() + "\nBASE >> " + BaseId()
                                //+"\nDISK >> "+ diskId() + "\nVIDEO >> " 
                                +
                VideoId() + "\nMAC >> " + MacId()
                                         );
                }
                return FingerPrint;
            }
        }
        #region PRIVATE FUNCTION
        private static string MacId() => Identifier("Win32_NetworkAdapterConfiguration", "MACAddress", "IPEnabled");
        private static string VideoId() => Identifier("Win32_VideoController", "DriverVersion") + Identifier("Win32_VideoController", "Name");
        private static string BaseId() => Identifier("Win32_BaseBoard", "Model") + Identifier("Win32_BaseBoard", "Manufacturer") + Identifier("Win32_BaseBoard", "Name") + Identifier("Win32_BaseBoard", "SerialNumber");
        private static string DiskId() => Identifier("Win32_DisDrive", "Model") + Identifier("Win32_DiskDrive", "Manufacturer") + Identifier("Win32_DiskDrive", "Signature") + Identifier("Win32_DiskDrive", "TotalHeads");
        private static string BiosId() => Identifier("Win32_BIOS", "Manufacturer") + Identifier("Win32_BIOS", "SMBIOSBIOSVersion") + Identifier("Win32_BIOS", "IdentificationCode") + Identifier("Win32_BIOS", "SerialNumber") + Identifier("Win32_BIOS", "ReleaseDate") + Identifier("Win32_BIOS", "Version");
        private static string CpuId()
        {
            string retVal = Identifier("Win32_Processor", "UniqueId");
            if (retVal == string.Empty)
            {
                retVal = Identifier("Win32_Processor", "ProcessorId");
                if (retVal == string.Empty)
                {
                    retVal = Identifier("Win32_Processor", "Name");
                    if (retVal == string.Empty)
                    {
                        retVal = Identifier("Win32_Processor", "Manufacturer");

                    }
                    retVal += Identifier("Win32_Processor", "MaxClockSpeed");
                }
            }
            return retVal;
        }
        private static string GetHexString(byte[] bt)
        {
            string s = string.Empty;
            for (int i = 0; i < bt.Length; i++)
            {
                byte b = bt[i];
                int n, n1, n2;
                n = (int)b;
                n1 = n & 15;
                n2 = (n >> 4) & 15;
                if (n2 > 9)
                    s += ((char)(n2 - 10 + (int)'A')).ToString();
                else
                    s += n2.ToString();
                if (n1 > 9)
                    s += ((char)(n1 - 10 + (int)'A')).ToString();
                else
                    s += n1.ToString();
                if ((i + 1) != bt.Length && (i + 1) % 2 == 0) s += "-";
            }
            return s;
        }
        private static string GetHash(string s)
        {
            MD5 sec = new MD5CryptoServiceProvider();
            ASCIIEncoding enc = new ASCIIEncoding();
            byte[] bt = enc.GetBytes(s);
            return GetHexString(sec.ComputeHash(bt));
        }

        #endregion
        #region PUBLIC FUNCTIONS

        public static string Identifier(string _class, string _property)
        {
            string result = string.Empty;
            ManagementClass mc = new ManagementClass(_class);
            ManagementObjectCollection moc = mc.GetInstances();
            foreach (ManagementObject mo in moc)
            {
                if (result == string.Empty)
                {
                    try
                    {
                        result = mo[_property].ToString();
                        break;
                    }
                    catch
                    {
                        //do nothing
                    }
                }
            }
            return result;
        }
        public static string Identifier(string _class, string _property, string mustBeTrue)
        {
            string result = string.Empty;
            ManagementClass mc = new ManagementClass(_class);
            ManagementObjectCollection moc = mc.GetInstances();
            foreach (ManagementObject mo in moc)
            {
                if (mo[mustBeTrue].ToString() == "True")
                {
                    if (result == string.Empty)
                    {
                        try
                        {
                            result = mo[_property].ToString();
                            break;
                        }
                        catch
                        {

                        }
                    }
                }
            }
            return result;

        }
        #endregion
    }
}
