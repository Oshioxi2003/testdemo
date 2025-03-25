using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Flic.Shared
{

    public class ThongtinAPI
    {
        public string MaKhoanThu { get; set; }
        public double SoTien { get; set; }
        public string KyThanhToan { get; set; }
        public string MaSV { get; set; }
        public string HoTen { get; set; }
        public string SoDienThoai { get; set; }
        public int MaLoi { get; set; }

    }
    public static class FileClass
    {
        public static bool CopyDoisoatFile(string pathLog, string pathOut)
        {
            DateTime now = DateTime.Now;
            int recordNo = 0;
            string checksum_all = "";
            // Appending the given texts
            if (System.IO.File.Exists(pathLog))
            {
                if (!System.IO.File.Exists(pathOut))
                {
                    List<string> lines = System.IO.File.ReadAllLines(pathLog).ToList();
                    System.IO.File.WriteAllLines(pathOut, lines.GetRange(0, lines.Count).ToArray());

                    recordNo = lines.Count - 1; //tru header và footer
                    for (int j = 1; j < lines.Count; j++)
                    {
                        List<string> aline = lines[j].Split('|').ToList();
                        checksum_all += aline[aline.Count - 1];

                    }

                    /// Write footer line
                    /// 

                    string transtime = string.Format("{0:yyyymmddhhmmss}", now);
                    string s = "";
                    s += "009" + "|";
                    s += CommonInfo.PROVIDERID + "|"; //userID
                    s += "Admin|";
                    s += recordNo + "|"; //recordNo                                            
                    s += transtime + "|"; //transTime

                    string checksum_content =
                        CommonInfo.PROVIDERID +
                        "Admin" +
                        recordNo +
                        transtime +
                        checksum_all;
                    //_Logger.LogWarning("File Content doi soat:" + checksum_content);
                    string sig_ = MD5Key.GenerateMd5Hash(checksum_content); // checksum
                                                                            //_Logger.LogWarning("File Sig doi soat:" + sig_);
                    s += sig_;

                    using (TextWriter tw = System.IO.File.AppendText(pathOut))
                    {
                        tw.WriteLine(s);
                    }
                    //
                    return true;
                }

            }
            else
            {
                return false;
            }
            return false;
        }
    }
    public static class CommonInfo
    {
        public static string ConnectionString { get; set; }
        public static string BankApiKey { get; set; }
        public static string PrivateKeyPath { get; set; }
        public static string PublicKeyPath { get; set; }
        public static string PasswordPath { get; set; }
        public static string BankPublicKeyPath { get; set; }
        public static string PROVIDERID { get; set; }
        public static string VTBPublicKeyPath { get; set; }
        public static ConfigurationManager config { get; set; }

        public static string VIETINBANK_IN { get; set; }
        public static string VIETINBANK_LOG { get; set; }
        public static string VIETINBANK_OUT { get; set; }
        public static string VIETINBANK_BACKUP { get; set; }
        public static string CronSchedule { get; set; }
    }
    public static class MD5Key
    {
        public static string GenerateMd5Hash(string data)
        {
            using (System.Security.Cryptography.MD5 md5 = System.Security.Cryptography.MD5.Create())
            {
                // inputNew = "Palnati"
                data = data + CommonInfo.BankApiKey;
                //_Logger.LogWarning("Content:" + data);
                Encoding encoding = new UTF8Encoding();

                //byte[] inputBytes = System.Text.Encoding.ASCII.GetBytes(data);
                byte[] inputBytes = System.Text.Encoding.UTF8.GetBytes(data);
                byte[] hashBytes = md5.ComputeHash(inputBytes);

                string sig = Convert.ToHexString(hashBytes).ToLower(); // .NET 5 +
                //_Logger.LogWarning("Signature:" + sig);
                return sig;                                                      // return Convert.ToBase64String(hashBytes);

            }
        }
        public static bool VerifyWithMD5(string text, string signatureBase64)
        {
            string newSignature = GenerateMd5Hash(text).ToLower();
            return newSignature.Equals(signatureBase64.ToLower());
        }
    }
}