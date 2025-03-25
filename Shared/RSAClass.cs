using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Text;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using System.Xml;

namespace Flic.Shared
{
    public class RSAClass
    {
        private string enc_publickey = "";
        private string enc_privatekey = "";
        private string enc_passpharse = "";

        private string sign_publickey;// = System.Configuration.ConfigurationManager.AppSettings["cert"];
        private string sign_privatekey;// = System.Configuration.ConfigurationManager.AppSettings["private"];
        private string sign_passpharse;// = System.Configuration.ConfigurationManager.AppSettings["sign_passpharse"];
        private string hashAlgorithm = "SHA1"; //"MD5";

        //Added by thinhdt - date 16/08/2014
        private bool _ignore_expire_date = false;
        private Encoding _encoding = Encoding.UTF8;//Default

        public Encoding ENCODING
        {
            get { return _encoding; }
            set { _encoding = value; }
        }

        //Added by thinhdt - date 20/07/2015

        bool _UsingX509KeyStorageFlags = false;

        public bool UsingX509KeyStorageFlags
        {
            get { return _UsingX509KeyStorageFlags; }
            set { _UsingX509KeyStorageFlags = value; }
        }

        X509KeyStorageFlags _X509KeyStorageFlags = X509KeyStorageFlags.MachineKeySet;

        public X509KeyStorageFlags X509KeyStorageFLAGS
        {
            get { return _X509KeyStorageFlags; }
            set { _X509KeyStorageFlags = value; }
        }

        /// <summary>
        /// This property is used to ignore check expire date of certificate when set value true.
        /// </summary>
        public bool IGNORE_EXPIRE_DATE
        {
            get { return _ignore_expire_date; }
            set { _ignore_expire_date = value; }
        }

        /// <summary>
        /// Used to set hash algorithm (SHA1, MD5) for signing data; Default is 'SHA1'.
        /// </summary>
        public string HASH_ALGORITHM
        {
            get { return hashAlgorithm; }
            set { hashAlgorithm = value; }
        }

        UTF8Encoding encoding = null;
        RSACryptoServiceProvider rsaCSP = null;
        private X509Certificate2 cert = null;

        XmlDocument xmlDoc = null;
        // SignedXml signedXML = null;
        //KeyInfo keyinfo = null;
        //KeyInfoX509Data keyInfoData = null;
        //Reference reference = null;

        RSAPKCS1SignatureDeformatter formater;
        MD5CryptoServiceProvider md5;
        SHA1CryptoServiceProvider sha1;

        //Added by thinhdt - Date 25/04/2014
        private string m_strHSM_IP = "10.0.43.31";
        private string m_strHSM_Port = "01500";
        //HSM8000 HSM8000 = null;
        StreamReader sr = null;//Read private key pem
        //Added by thinhdt - Date 26/04/2014
        private bool m_CheckExpiredDate = false;
        private bool m_pemFormat = false;
        //Added by thinhdt - Date 28/04/2014
        private bool m_EnableHSM = false;
        private bool m_EnableVerifyHash = false;

        //Added by thinhdt - Date 29/04/2014
        private string m_strAESPassWord = "daotungthinh@gmail.com";
        /// <summary>
        /// Password for encrypting and decrypting AES.
        /// </summary>
        public string AES_PASSWORD
        {
            get { return m_strAESPassWord; }
            set { m_strAESPassWord = value; }
        }
        private int m_iAESBit = 128;
        /// <summary>
        /// 128, 192 or 256 for algorithm.
        /// </summary>
        public int AES_BIT
        {
            get { return m_iAESBit; }
            set { m_iAESBit = value; }
        }



        /// <summary>
        /// This property used to enable verifyhash for VerifyData().
        /// </summary>
        public bool ENABLE_VERIFY_HASH
        {
            get { return m_EnableVerifyHash; }
            set { m_EnableVerifyHash = value; }
        }


        /// <summary>
        /// This property used to set HSM for signing.
        /// Default is false.
        /// </summary>
        public bool ENABLE_HSM
        {
            get { return m_EnableHSM; }
            set { m_EnableHSM = value; }
        }

        public bool PEM_FORMAT
        {
            get { return m_pemFormat; }
            set { m_pemFormat = value; }
        }

        /// <summary>
        /// Public key used to Verify functions (format *.cer, *.der).
        /// </summary>
        public string SIGN_PUBLICKEY
        {
            get { return sign_publickey; }
            set { sign_publickey = value; }
        }
        /// <summary>
        /// Private key used to Sign functions (format *.p12).
        /// </summary>
        public string SIGN_PRIVATEKEY
        {
            get { return sign_privatekey; }
            set { sign_privatekey = value; }
        }
        /// <summary>
        /// Password used to protect sign private key.
        /// </summary>
        public string SIGN_PASSPHARSE
        {
            get { return sign_passpharse; }
            set { sign_passpharse = value; }
        }
        /// <summary>
        /// Used to set check expire date of certificate; Default is false.
        /// </summary>
        public bool CHECK_EXPIRE_DATE
        {
            get { return m_CheckExpiredDate; }
            set { m_CheckExpiredDate = value; }
        }
        //Added by thinhdt - date 04/06/2015
        public RSAClass(string pub, string pri, string pass)
        {
            sign_publickey = pub;
            sign_privatekey = pri;
            sign_passpharse = pass;
        }
        public string SignData(string data, string str_privatekey)
        {
            try
            {
                //Added by thinhdt - Date 28/04/2014

                sign_passpharse = "123456";
                encoding = new UTF8Encoding();
                rsaCSP = new RSACryptoServiceProvider();
                cert = GetCertificate2FromFile(str_privatekey, sign_passpharse);
                rsaCSP = GetPrivateKey(cert);
                //return Convert.ToBase64String(rsaCSP.SignData(encoding.GetBytes(data), "SHA1"));
                return Convert.ToBase64String(rsaCSP.SignData(encoding.GetBytes(data), hashAlgorithm));
            }
            catch (Exception ex)
            {
                throw ex;
            }
            finally
            {
                cert = null;
                rsaCSP = null;
                encoding = null;
            }
        }

        public string SignData(string data, ref string digestValue)
        {
            try
            {
                //Added by thinhdt - Date 28/04/2014

                encoding = new UTF8Encoding();
                rsaCSP = new RSACryptoServiceProvider();

                byte[] tmpBuf = encoding.GetBytes(data);

                //Compute hash based on source data
                sha1 = new SHA1CryptoServiceProvider();
                tmpBuf = sha1.ComputeHash(tmpBuf);

                digestValue = Convert.ToBase64String(tmpBuf);

                cert = GetCertificate2FromFile(sign_privatekey, sign_passpharse);
                rsaCSP = GetPrivateKey(cert);
                //return Convert.ToBase64String(rsaCSP.SignData(encoding.GetBytes(data), "SHA1"));
                return Convert.ToBase64String(rsaCSP.SignData(encoding.GetBytes(data), hashAlgorithm));
            }
            catch (Exception ex)
            {
                throw ex;
            }
            finally
            {
                cert = null;
                rsaCSP = null;
                encoding = null;
                sha1 = null;
            }
        }

        public bool VerifyData(string signedData, string data, string publickey)
        {
            try
            {

                encoding = new UTF8Encoding();
                rsaCSP = new RSACryptoServiceProvider();

                byte[] bufData = encoding.GetBytes(data);

                byte[] bufSigned = Convert.FromBase64String(signedData);

                cert = GetCertificate2FromFile(publickey, "");
                rsaCSP = GetPublicKey(cert);
                ////Added by thinhdt date 26/04/2014
                ////For checking expire date of certificate
                //if (m_CheckExpiredDate)
                //{
                //    DateTime expireDate = DateTime.Parse(cert.GetExpirationDateString());
                //    if (expireDate.CompareTo(DateTime.Now) <= 0)
                //    {
                //        throw new Exception("VerifyData() failed by certificate is expired!");
                //    }
                //}
                //Added by thinhdt date 28/04/2014
                //For checking enable verifyhash
                if (m_EnableVerifyHash)
                {
                    sha1 = new SHA1CryptoServiceProvider();

                    byte[] hash = sha1.ComputeHash(bufData);
                    return rsaCSP.VerifyHash(hash, CryptoConfig.MapNameToOID(hashAlgorithm), bufSigned);
                }

                //return rsaCSP.VerifyData(bufData, "SHA1", bufSigned);
                return rsaCSP.VerifyData(bufData, hashAlgorithm, bufSigned);
            }
            catch (Exception ex)
            {
                throw ex;
            }
            finally
            {
                rsaCSP = null;
                encoding = null;
                sha1 = null;
            }
        }

        private RSACryptoServiceProvider ReadPublicKey()
        {
            // read the XML formated public key
            try
            {
                string modStr = "";
                string expStr = "";
                RSAParameters RSAKeyInfo = new RSAParameters();
                RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();

                XmlTextReader reader = new XmlTextReader(sign_publickey);
                while (reader.Read())
                {
                    if (reader.NodeType == XmlNodeType.Element)
                    {
                        if (reader.Name == "Modulus")
                        {
                            reader.Read();
                            modStr = reader.Value;
                        }
                        else if (reader.Name == "Exponent")
                        {
                            reader.Read();
                            expStr = reader.Value;
                        }
                    }
                }
                if (modStr.Equals("") || expStr.Equals(""))
                {
                    //throw exception
                    throw new Exception("Invalid public key");
                }
                RSAKeyInfo.Modulus = Convert.FromBase64String(modStr);
                RSAKeyInfo.Exponent = Convert.FromBase64String(expStr);
                rsa.ImportParameters(RSAKeyInfo);
                return rsa;
            }
            catch (Exception e)
            {
                throw new Exception("Invalid Public Key.");
            }
            finally
            {
                //rsa = null;
            }
        }

        public bool VerifySignature(string signedData, string data)
        {
            try
            {
                rsaCSP = LoadPublicKeyXML(sign_publickey);

                byte[] signature = Convert.FromBase64String(signedData);
                formater = new RSAPKCS1SignatureDeformatter(rsaCSP);
                bool result = false;
                if (hashAlgorithm.Equals("MD5"))
                {
                    md5 = new MD5CryptoServiceProvider();
                    byte[] hash = md5.ComputeHash(System.Text.ASCIIEncoding.ASCII.GetBytes(data));
                    formater.SetHashAlgorithm("MD5");
                    result = formater.VerifySignature(hash, signature);
                }
                else if (hashAlgorithm.Equals("SHA1"))
                {
                    sha1 = new SHA1CryptoServiceProvider();
                    byte[] hash = sha1.ComputeHash(System.Text.ASCIIEncoding.ASCII.GetBytes(data));
                    formater.SetHashAlgorithm("SHA1");
                    result = formater.VerifySignature(hash, signature);
                }

                return result;
            }
            catch (Exception ex)
            {
                throw ex;
            }
            finally
            {
                md5 = null;
                sha1 = null;
                formater = null;
            }

        }

        private RSACryptoServiceProvider GetPublicKey(X509Certificate2 cert)
        {
            try
            {
                PublicKey publickey = cert.PublicKey;
                return (RSACryptoServiceProvider)publickey.Key;
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        private RSACryptoServiceProvider GetPrivateKey(X509Certificate2 cert)
        {
            try
            {
                return (RSACryptoServiceProvider)cert.PrivateKey;
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        public string GetCertString(string filePath)
        {
            try
            {

                sr = new StreamReader(filePath);
                return sr.ReadToEnd();
            }
            catch (Exception ex)
            {
                throw new Exception("GetCertString(): " + ex.Message);
            }
        }
        private X509Certificate2 GetCertificate2FromFile(string filePath, string passWord)
        {
            try
            {
                X509Certificate2 cert = null;

                //Added by thinhdt - Date 26/04/2014
                if (m_pemFormat)
                {

                    string sPublicKey = GetCertString(filePath);

                    //Modified by thinhdt - Date 26/04/2014
                    string cf = sPublicKey.Replace("-----BEGIN CERTIFICATE-----", "");
                    cf = cf.Replace("-----END CERTIFICATE-----", "");
                    byte[] bInput;
                    bInput = Convert.FromBase64String(cf);
                    cert = new X509Certificate2();
                    if (string.IsNullOrEmpty(passWord))
                    {
                        cert.Import(bInput);
                    }
                    else
                    {
                        cert.Import(bInput);
                        //cert.Import(bInput, passWord, X509KeyStorageFlags.Exportable);
                    }

                    return cert;
                }

                if (passWord != "")
                {
                    if (_UsingX509KeyStorageFlags == false)
                    {
                        cert = new X509Certificate2(filePath, passWord);
                    }
                    else
                    {
                        //For Windows 2008 64bit
                        cert = new X509Certificate2(filePath, passWord, _X509KeyStorageFlags);//X509KeyStorageFlags.MachineKeySet
                    }
                }
                else
                {
                    cert = new X509Certificate2(filePath);
                }

                return cert;

            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        private X509Certificate2 GetCertificate2FromFile(string filePath, string passWord, bool bExport)
        {
            try
            {
                X509Certificate2 cert = null;

                if (passWord != "")
                {
                    if (bExport)
                    {
                        cert = new X509Certificate2(filePath, passWord, X509KeyStorageFlags.Exportable);
                    }
                    else
                    {

                        if (_UsingX509KeyStorageFlags == false)
                        {
                            cert = new X509Certificate2(filePath, passWord);
                        }
                        else
                        {
                            //For Windows 2008 64bit
                            cert = new X509Certificate2(filePath, passWord, _X509KeyStorageFlags);//X509KeyStorageFlags.MachineKeySet
                        }
                    }
                }
                else
                {
                    cert = new X509Certificate2(filePath);
                }

                return cert;

            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        //------------------------------------------------------
        //      Date        : 15/08/2013
        //      Author      : thinhdt
        //      Perpose     : Load public key from XML file.
        //------------------------------------------------------
        private RSACryptoServiceProvider LoadPublicKeyXML(String pathXMLfile)
        {
            try
            {
                rsaCSP = new RSACryptoServiceProvider();
                StreamReader sr = File.OpenText(pathXMLfile);
                string rsaXml = sr.ReadToEnd();
                sr.Close();
                rsaCSP.FromXmlString(rsaXml);
                return rsaCSP;
            }
            catch (Exception ex)
            {
                throw new Exception("" + ex.Message);
            }
            finally
            {
                rsaCSP = null;
            }
        }

        private RSACryptoServiceProvider LoadPrivateKeyXML(String pathXMLfile)
        {
            try
            {
                rsaCSP = new RSACryptoServiceProvider();
                StreamReader sr = File.OpenText(pathXMLfile);
                string rsaXml = sr.ReadToEnd();
                sr.Close();
                rsaCSP.FromXmlString(rsaXml);
                return rsaCSP;
            }
            catch (Exception ex)
            {
                throw new Exception("" + ex.Message);
            }
            finally
            {
                rsaCSP = null;
            }
        }


        public string GetDigestValue(string MessageInPut)
        {
            SHA1 sha1 = new SHA1CryptoServiceProvider();
            ASCIIEncoding aaa = new ASCIIEncoding();

            byte[] MessageDigestBytes = aaa.GetBytes(MessageInPut);
            byte[] MessageDigestHash = sha1.ComputeHash(MessageDigestBytes);
            string MessageDigestBase64 = Convert.ToBase64String(MessageDigestHash);
            return MessageDigestBase64;
        }

        public string GetDigestValueUTF(string MessageInPut)
        {
            SHA1 sha1 = new SHA1CryptoServiceProvider();
            UnicodeEncoding aaa = new UnicodeEncoding();

            byte[] MessageDigestBytes = aaa.GetBytes(MessageInPut);
            byte[] MessageDigestHash = sha1.ComputeHash(MessageDigestBytes);
            string MessageDigestBase64 = Convert.ToBase64String(MessageDigestHash);
            return MessageDigestBase64;
        }
    }
}
