using Flic.Server.Data;
using Flic.Server.Interfaces;
using Flic.Shared.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Hosting;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Text;
using Flic.Shared;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.Pkcs;
using Newtonsoft.Json;
using System.Security.Authentication.ExtendedProtection;
using MathNet.Numerics.Distributions;
using Microsoft.EntityFrameworkCore;
using DocumentFormat.OpenXml.Spreadsheet;
using DocumentFormat.OpenXml.Office2010.Excel;
using Org.BouncyCastle.Ocsp;
using Radzen;
using DocumentFormat.OpenXml.ExtendedProperties;
using NPOI.HSSF.Record;
using NPOI.SS.Formula.Functions;
using System.Globalization;

namespace Flic.Server.Controllers
{
    //[CustomAuthorization]
    [Route("api/[controller]")]
    [ApiController]
    public class BankAPIController : ControllerBase
    {
        private readonly ApplicationDbContext _context;
        private readonly IThutien _IThutien;
        private static IWebHostEnvironment _env;
        private RSA privateKey;
        private RSA publicKey;
        private RSA VTBPublicKey;

        private ILoggerFactory _Factory;
        private ILogger _Logger;

        // ./openssl.exe req -x509 -nodes -days 3650 -newkey rsa:1024 -keyout privatekey.pem -out mycert.pem

        //./openssl.exe rsa -in privatekey.pem -pubout -out publickey.pem
        // ./openssl.exe pkcs12 -export -out mycertprivatekey.pfx -in mycert.pem -inkey privatekey.pem -name "my_certificate"
        public BankAPIController(IThutien context, ApplicationDbContext dbContext, IWebHostEnvironment env, ILoggerFactory factory, ILogger logger)
        {
            this._IThutien = context;
            _env = env;
            _context = dbContext;

            _Factory = factory;
            _Logger = logger;

            ///
            /*
            string pub_path = Path.Combine(_env.ContentRootPath, "KHDT_SIGN_CERT.der");
            string VTB_pub_path = Path.Combine(_env.ContentRootPath, "KHDT_SIGN_CERT.der");
            string pri_path = Path.Combine(_env.ContentRootPath, "KHDT_SIGN_PRIVATE.p12");
            string pass_path = Path.Combine(_env.ContentRootPath, "Pass.txt");
            */

            //string pub_path = Path.Combine(_env.ContentRootPath, CommonInfo.PublicKeyPath);
            //string VTB_pub_path = Path.Combine(_env.ContentRootPath,  CommonInfo.VTBPublicKeyPath);
            //string pri_path = Path.Combine(_env.ContentRootPath,  CommonInfo.PrivateKeyPath);
            //string pass_path = Path.Combine(_env.ContentRootPath, CommonInfo.PasswordPath);

            try
            {
                ///
                /*
                var privateKeyText = System.IO.File.ReadAllText(pri_path);
                var privateKeyBlocks = privateKeyText.Split("-", StringSplitOptions.RemoveEmptyEntries);
                var privateKeyBytes = Convert.FromBase64String(privateKeyBlocks[1]);

                privateKey = RSA.Create();
                string Password = System.IO.File.ReadAllText(pass_path);
                privateKey.ImportEncryptedPkcs8PrivateKey(Password, privateKeyBytes, out _);

                byte[] publicPemBytes = System.IO.File.ReadAllBytes(pub_path);
                using var publicX509 = new X509Certificate2(publicPemBytes);
                publicKey = publicX509.GetRSAPublicKey();

                //VTB Public Key
                var VTB_collection = new X509Certificate2Collection();
                VTB_collection.Import(VTB_pub_path);
                var VTB_certificate = VTB_collection[0];
                VTBPublicKey = (RSA)VTB_certificate.PublicKey.Key;
                */
                //

                ////



                //var collection = new X509Certificate2Collection();
                ////
                //collection.Import(pub_path);
                //var certificate = collection[0];

                //publicKey = (RSA)certificate.PublicKey.Key;
                ////VTB Public Key
                //var VTB_collection = new X509Certificate2Collection();
                //VTB_collection.Import(VTB_pub_path);
                //var VTB_certificate = VTB_collection[0];                
                //VTBPublicKey = (RSA)VTB_certificate.PublicKey.Key;
                ////

                //string Password = System.IO.File.ReadAllText(pass_path);

                //var private_collection = new X509Certificate2Collection();
                ////collection.Import(System.IO.File.ReadAllBytes(pri_path), Password, X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet);
                //private_collection.Import(System.IO.File.ReadAllBytes(pri_path), Password, X509KeyStorageFlags.DefaultKeySet);
                //var private_certificate = private_collection[0];
                //privateKey = (RSA)private_certificate.PrivateKey;

            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                _Logger.LogError("Lỗi không xác thực được Request - " + ex.Message);
                throw ex;
            }


        }

        [HttpGet("TestEncrypt/{ma}")]
        public async Task<string> TestEncrypt(string ma)
        {
            try
            {
                var list = await Task.FromResult(_IThutien.GetByMSV(ma));

                //string json = JsonConvert.SerializeObject(list);
                string json = ma;
                var s1 = SignWithPrivate(json, privateKey);
                //json = JsonConvert.SerializeObject(list) +"A";
                //s1 += "A";
                var chk1 = VerifyWithPublic(json, s1, publicKey);

                var chk2 = VerifyWithPublic(json, s1, VTBPublicKey);

                //var s2 = SignWithPublic(json, publicKey);
                //var chk2 = VerifyWithPrivate(json, s2, privateKey);

                var result = new
                {
                    data = json,
                    signature1 = s1,
                    check1 = chk1,
                    //signature2 = s2,
                    check2 = chk2,
                };
                return JsonConvert.SerializeObject(result);

            }
            catch (Exception e)
            {
                Console.Write(e.Message);
                _Logger.LogError("Lỗi không xác thực được Request - " + e.Message);
                return e.Message;
            }
        }


        [HttpGet("TestMD5/{text}/{sig}")]
        public async Task<string> TestMD5(string text, string sig)
        {
            try
            {

                //s1 += "A";
                string newmd5 = MD5Key.GenerateMd5Hash(text);
                var chk1 = MD5Key.VerifyWithMD5(text, sig);

                //var s2 = SignWithPublic(json, publicKey);
                //var chk2 = VerifyWithPrivate(json, s2, privateKey);

                var result = new
                {
                    data = text,
                    signature = sig,
                    newMD5 = newmd5,
                    check = chk1,
                    //signature2 = s2,
                    //check2 = chk2,
                };
                return JsonConvert.SerializeObject(result);

            }
            catch (Exception e)
            {
                Console.Write(e.Message);
                _Logger.LogError("Lỗi không xác thực được Request - " + e.Message);
                return e.Message;
            }
        }
        [HttpGet("TaoDoisoat")]
        public async Task<bool> TaoDoisoat()
        {
            try
            {
                string fnameLog = "";
                string fname = "";

                DateTime now = DateTime.Now;
                DateTime yesterday = DateTime.Today.AddDays(-1);
                fname = string.Format("{0:yyyyMMdd}", yesterday);
                fnameLog = string.Format("{0:yyyyMMdd}", yesterday);


                string pathLog = Directory.GetCurrentDirectory() + "\\StaticFiles\\Doisoat\\" + CommonInfo.VIETINBANK_LOG + "\\" + fnameLog + "_" + CommonInfo.PROVIDERID + "_BILLHOCPHI_IN.txt";
                string pathOut = Directory.GetCurrentDirectory() + "\\StaticFiles\\Doisoat\\" + CommonInfo.VIETINBANK_OUT + "\\" + fname + "_" + CommonInfo.PROVIDERID + "_BILLHOCPHI_IN.txt";

                return FileClass.CopyDoisoatFile(pathLog, pathOut);

            }
            catch (Exception e)
            {
                Console.Write(e.Message);
                _Logger.LogError("Lỗi không xác thực được Request - " + e.Message);
                return false;
            }
        }

        [HttpGet("TaoDoisoat/{date}")]
        public async Task<bool> TaoDoisoat(string date)
        {
            try
            {
                string fnameLog = "";
                string fname = "";
                if (date != null && date != "")
                {
                    var now = DateTime.ParseExact(date, "yyyyMMdd", CultureInfo.InvariantCulture);
                    fnameLog = string.Format("{0:yyyyMMdd}", now);

                    //DateTime nextDay = now.AddDays(+1);
                    fname = string.Format("{0:yyyyMMdd}", now);
                    string pathLog = Directory.GetCurrentDirectory() + "\\StaticFiles\\Doisoat\\" + CommonInfo.VIETINBANK_LOG + "\\" + fnameLog + "_" + CommonInfo.PROVIDERID + "_BILLHOCPHI_IN.txt";
                    string pathOut = Directory.GetCurrentDirectory() + "\\StaticFiles\\Doisoat\\" + CommonInfo.VIETINBANK_OUT + "\\" + fname + "_" + CommonInfo.PROVIDERID + "_BILLHOCPHI_IN.txt";

                    return FileClass.CopyDoisoatFile(pathLog, pathOut);
                }
                return false;
            }
            catch (Exception e)
            {
                Console.Write(e.Message);
                _Logger.LogError("Lỗi không xác thực được Request - " + e.Message);
                return false;
            }
        }

        [HttpGet("FindInvoice/{ma}")]
        public async Task<string> FindInvoice(string ma)
        {
            try
            {
                var list = await Task.FromResult(_IThutien.GetByMSV(ma));
                string json = JsonConvert.SerializeObject(list);
                var signature = SignWithPrivate(json, privateKey);
                //var result = new { Data: json, Signature: signature};
                var result = new
                {
                    data = json,
                    signature = signature
                };
                return JsonConvert.SerializeObject(result);
            }
            catch (Exception e)
            {
                Console.Write(e.Message);
                _Logger.LogError("Lỗi không xác thực được Request - " + e.Message);
                return null;
            }
        }
        [HttpPut("PaymentUpdate")]
        public async Task<bool> PaymentUpdate(int id)
        {
            try
            {
                return _IThutien.ThanhtoanByID(id);

            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                _Logger.LogError("Lỗi không xác thực được Request - " + e.Message);
                return false;
            }
        }
        [HttpPost("QueryBillInfo")]
        public async Task<ResponseVanTinView> Vantin(RequestVanTin req)
        {
            ResponseVanTin rs = new ResponseVanTin();
            ResponseVanTinView rs_view = new ResponseVanTinView();
            string SignatureContent = "";
            //Verify VTB Signature
            SignatureContent = req.requestId + req.providerId + req.merchantId + req.custCode;
            string sig = MD5Key.GenerateMd5Hash(SignatureContent).ToLower();
            bool chk1 = req.signature.ToLower().Equals(sig);
            try
            {
                req.timeRequest = DateTime.Now.ToString();

                _context.RequestVanTins.Add(req);
                _context.SaveChanges();
                if (!chk1)
                {
                    rs_view.responseDesc = "Lỗi không xác thực được Request - " + req.requestId + "/" + req.providerId + "/" + req.merchantId + "/" + req.custCode + "/" + req.signature;
                    _Logger.LogError("Lỗi không xác thực được Request - req.requestId:" + req.requestId + "/req.providerId:" + req.providerId + "/req.merchantId:" + req.merchantId + "/req.custCode:" + req.custCode + "SignatureContent:" + SignatureContent + "/req.sig:" + req.signature + "/sig:" + sig);
                    rs.responseCode = "06";
                    rs_view.responseCode = "06";
                    rs_view.providerId = req.providerId;
                    rs_view.merchantId = req.merchantId;
                    return rs_view;
                }

                SignatureContent = "";
                //End Verify VTB Signature
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                //throw ex;
                rs_view.responseDesc = "Lỗi không cập nhật được Request - " + ex.Message;
                _Logger.LogError("Lỗi không cập nhật được Request - " + ex.Message);
                rs.responseCode = "05";
                rs_view.responseCode = "05";
                rs_view.providerId = req.providerId;
                rs_view.merchantId = req.merchantId;
                return rs_view;
            }
            string itemsSignature = "";

            try
            {
                var std = _context.Students.Where(m => m.MaSV != null && m.MaSV.Equals(req.custCode)).FirstOrDefault();
                if (std == null)
                {
                    std = _context.Students.Where(m => m.SoNH != null && m.SoNH.Equals(req.custCode)).FirstOrDefault();
                }
                string transTime = DateTime.Now.ToString();
                if (std != null)
                {
                    var list = await Task.FromResult(_IThutien.GetByStudentId(std.id));
                    List<ResponseItem> items = new List<ResponseItem>();
                    itemsSignature = "";
                    foreach (var item in list)
                    {
                        if (item.TrangThai == 0)
                        {
                            ResponseItem t = new ResponseItem();
                            t.order = item.id.ToString();
                            t.code = item.KyThanhToan;
                            t.amount = item.SoTien.Value;
                            t.content = item.LoaiKhoanthuID;                            
                            t.note = std.MaSV + " " + std.HoDem + " " + std.Ten + " " + std.LopID;
                            t.currency = "VND";
                            items.Add(t);
                            itemsSignature += t.order.ToString() + t.code.ToString() + t.content.ToString() + t.amount.ToString();
                            //itemsSignature += t.content.ToString()
                            //    + t.currency
                            //    + t.code.ToString()
                            //    + t.order.ToString()
                            //    + t.amount.ToString()
                            //    + t.note;
                        }

                    }

                    rs.items = items.ToList().ToString();
                    rs.custCode = std.id.ToString();
                    rs.custName = std.HoDem + " " + std.Ten;
                    rs.address = std.LopID;
                    rs.addInfor1 = std.NganhID;
                    rs.birthday = std.Ngaysinh;
                    rs.providerId = req.providerId;
                    rs.merchantId = req.merchantId;
                    rs.custType = "01";

                    //

                    rs_view.items = items.ToList();
                    rs_view.custCode = std.id.ToString();
                    rs_view.custName = std.HoDem + " " + std.Ten;
                    rs_view.address = std.LopID;
                    rs_view.addInfor1 = std.NganhID;
                    rs_view.birthday = std.Ngaysinh;
                    rs_view.providerId = req.providerId;
                    rs_view.merchantId = req.merchantId;
                    rs_view.custType = "01";
                    //
                    rs.responseCode = "00";
                    rs_view.responseCode = "00";

                    rs.responseDesc = "Thành công";
                    rs_view.responseDesc = "Thành công";
                }
                else
                {
                    rs.responseCode = "01";
                    rs_view.responseCode = "01";
                    rs.responseDesc = "Không tìm thấy thông tin sinh viên";
                    rs_view.responseDesc = "Không tìm thấy thông tin sinh viên";
                    _Logger.LogError("Không tìm thấy sinh viên - " + req.custCode);
                }

                rs.requestId = req.requestId;
                rs.transTime = transTime;

                //
                rs_view.requestId = req.requestId;
                rs_view.transTime = transTime;

                //
                SignatureContent = rs.requestId 
                    + rs.providerId 
                    + rs.merchantId 
                    + rs.transTime 
                    + rs.custCode 
                    + rs.responseCode 
                    + itemsSignature;

                var signature = MD5Key.GenerateMd5Hash(SignatureContent);
                rs.signature = signature;
                rs_view.signature = signature;
                _context.ResponseVanTins.Add(rs);
                _context.SaveChanges();
                _Logger.LogError("Signature Content:" + SignatureContent + "/ sig:" + signature);

            }
            catch (Exception ex)
            {
                rs_view.responseDesc = "Lỗi " + ex.Message;
                _Logger.LogError("Lỗi không xử lý được Request - " + ex.Message);
                return rs_view;
            }

            return rs_view;
        }

        [HttpPost("Reconcile")]
        public async Task<ResponseGachNo> Gachno(RequestGachNoView req)
        {
            ResponseGachNo rs = new ResponseGachNo();
            string SignatureContent = "";

            try
            {
                RequestGachNo reqLog = new RequestGachNo();
                reqLog.requestId = req.requestId;
                reqLog.providerId = req.providerId;
                reqLog.merchantId = req.merchantId;
                reqLog.primaryKeyId = req.primaryKeyId;
                reqLog.custCode = req.custCode;
                reqLog.custType = req.custType;
                reqLog.custName = req.custName;
                reqLog.address = req.address;
                reqLog.birthday = req.birthday;
                reqLog.phoneNo = req.phoneNo;
                reqLog.idCard = req.idCard;
                reqLog.addInfor1 = req.addInfor1;
                reqLog.addInfor2 = req.addInfor2;
                reqLog.addInfor3 = req.addInfor3;
                reqLog.addInfor4 = req.addInfor4;
                reqLog.addInfor5 = req.addInfor5;
                reqLog.bankTransactionId = req.bankTransactionId;
                reqLog.responseCode = req.responseCode;
                reqLog.responseDesc = req.responseDesc;
                reqLog.transTime = req.transTime;
                reqLog.channel = req.channel;
                reqLog.signature = req.signature;
                reqLog.items = JsonConvert.SerializeObject(req.items); ;
                reqLog.timeUpdate = DateTime.Now;
                _context.RequestGachNos.Add(reqLog);
                _context.SaveChanges();
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                //throw ex;
                rs.responseCode = "01";
                rs.responseDesc = "Lỗi không cập nhật được Request - " + ex.Message;
                _Logger.LogError("Lỗi không cập nhật được Request gach nợ - " + ex.Message);
                return rs;
            }

            try
            {
                List<ResponseItem> items = req.items;
                string sReq = "";
                //Verify VTB Signature
                SignatureContent = req.requestId + req.providerId + req.merchantId + req.transTime + req.custCode + req.responseCode;
                sReq = "requestId:" + req.requestId + "/providerId:" + req.providerId + "/merchantId:" + req.merchantId + "/transTime:" + req.transTime + "/custCode:" + req.custCode + "/responseCode:" + req.responseCode + "/ items:";
                foreach (var it in items)
                {
                    SignatureContent += it.order.ToString() + it.code.ToString() + it.content.ToString() + it.amount.ToString();
                    sReq += "/order:" + it.order.ToString() + "/code:" + it.code.ToString() + "/content:" + it.content.ToString() + "/amount:" + it.amount.ToString() + "/";
                }
                sReq += "/req.signature:" + req.signature;
                //bool chk1 = VerifyWithPublic(SignatureContent, req.signature, VTBPublicKey);
                string sig = MD5Key.GenerateMd5Hash(SignatureContent).ToLower();
                //bool chk1 = VerifyWithMD5(SignatureContent, req.signature);
                bool chk1 = req.signature.ToLower().Equals(sig);
                if (!chk1)
                {
                    rs.responseDesc = "Lỗi không xác thực được Request - " + sReq + "/sig:" + sig;
                    _Logger.LogError("Lỗi không xác thực được Request - " + sReq + "/sig:" + sig);
                    rs.responseCode = "06";                    
                    return rs;
                }
                SignatureContent = "";
                //End Verify VTB Signature

                if (items != null)
                {
                    foreach (var it in items)
                    {
                        ThuTienView tt = _IThutien.Get(Int32.Parse(it.order));

                        if (tt != null)
                        {
                            if (tt.TrangThai == 1)
                            {
                                rs.responseCode = "01";
                                rs.responseDesc = "Lỗi: Khoản thu này đã thanh toán rồi: " + req.custCode + " Order: " + it.order + " Amount: " + it.amount;
                                _Logger.LogWarning("Lỗi khoản thu đã thanh toán rồi MSV: " + req.custCode + " Order: " + it.order + " Amount: " + it.amount);
                            }
                            else if (Math.Abs((double)tt.SoTien - (double)it.amount) < 0.000001 && tt.MaSinhVien.ToString().Trim() == req.custCode.Trim())
                            {
                                ThuTien tt1 = _IThutien.GetById(Int32.Parse(it.order));
                                if (tt1 != null)
                                {
                                    DateTime now = DateTime.Now;
                                    tt1.ThanhtoanReqId = req.requestId;
                                    tt1.TrangThai = 1;
                                    tt1.NgayThanhToan = now;
                                    _IThutien.Update(tt1);

                                    rs.responseCode = "00";
                                    rs.responseDesc = "Thành công";
                                    _Logger.LogWarning("Thành công gạch nợ MSV" + req.custCode + " Order: " + it.order + " Amount: " + it.amount);

                                    /////Start Update file doi chieu cong no                                    

                                    string fname = string.Format("{0:yyyyMMdd}", now);
                                    string path = Directory.GetCurrentDirectory() + "\\StaticFiles\\Doisoat\\" + CommonInfo.VIETINBANK_LOG + "\\" + fname + "_" + CommonInfo.PROVIDERID + "_BILLHOCPHI_IN.txt";
                                    int recordNo = 0;
                                    string checksum_all = "";
                                    // Appending the given texts
                                    if (!System.IO.File.Exists(path))
                                    {
                                        using (TextWriter tw = System.IO.File.AppendText(path))
                                        {
                                            tw.WriteLine("recordType,requestId,svrProviderCode,merchantId,serviceType,custId,custname,amount,currencyCode, billCycle,billId,transTime,status,bankTransId,recordChecksum");
                                        }
                                    }
                                    

                                    if (System.IO.File.Exists(path))
                                    {
                                        using (TextWriter tw = System.IO.File.AppendText(path))
                                        {
                                            string s = "";
                                            s += "002" + "|"; //recordType
                                            s += req.requestId + "|"; //requestId
                                            s += req.providerId + "|"; //svrProviderCode
                                            s += req.merchantId + "|"; //merchantId
                                            s += req.custType + "|"; // serviceType
                                            s += req.custCode + "|"; // Mã sinh viên
                                            s += req.custName + "|";//tt.HoDem + " " + tt.Ten + "|"; //custName
                                            s += tt.SoTien + "|"; //amount
                                            s += "VND" + "|"; //currencyCode
                                            s += tt.KyThanhToan + "|"; //billCycle
                                            s += it.order + "|"; //billId
                                            s += req.transTime + "|"; //transTime
                                            s += "00" + "|"; //status
                                            s += req.bankTransactionId + "|";//bankTransId
                                            string checksum_content = /*"02" +*/
                                                req.requestId +
                                                req.providerId +
                                                req.merchantId +
                                                req.custType +
                                                req.custCode +
                                                req.custName +
                                                tt.SoTien +
                                                "VND" +
                                                tt.KyThanhToan +
                                                it.order +
                                                req.transTime +
                                                "00" +
                                                req.bankTransactionId;
                                            _Logger.LogWarning("Line Content doi soat:" + checksum_content);

                                            string sig_ = MD5Key.GenerateMd5Hash(checksum_content); // checksum
                                            s += sig_;
                                            _Logger.LogWarning("Line Sig doi soat:" + sig_);
                                            tw.WriteLine(s);
                                            recordNo = recordNo + 1; //Them 1 dong
                                            checksum_all = checksum_all + sig_;                                            
                                        }
                                    }
                                    ///End Update file doi chieu cong no
                                }
                                else
                                {
                                    rs.responseCode = "02";
                                    rs.responseDesc = "Lỗi: không cập nhật trạng thái được: " + req.custCode + " Order: " + it.order + " Amount: " + it.amount;
                                    _Logger.LogError("Lỗi :không cập nhật trạng thái được: " + req.custCode + " / " + tt.MaSinhVien + " Order: " + it.order + " Amount: " + it.amount);
                                }

                            }
                            else
                            {
                                rs.responseCode = "02";
                                rs.responseDesc = "Lỗi: Số tiền hoặc thông tin sinh viên không khớp" + req.custCode + " Order: " + it.order + " Amount: " + it.amount;
                                _Logger.LogError("Lỗi :Số tiền hoặc thông tin sinh viên không khớp MSV: " + req.custCode + " / " + tt.MaSinhVien + " Order: " + it.order + " Amount: " + it.amount);
                            }
                        }

                    }
                }
                string transTime = DateTime.Now.ToString();
                rs.requestId = req.requestId;
                rs.providerId = req.providerId;
                rs.merchantId = req.merchantId;
                rs.confirmTransactionId = "";
                rs.transTime = transTime;

                rs.addInfo = "";
                rs.signature = "";
                SignatureContent = rs.requestId + rs.providerId + rs.merchantId + rs.confirmTransactionId + rs.transTime + rs.responseCode;

                string signature = MD5Key.GenerateMd5Hash(SignatureContent);
                rs.signature = signature;

                _context.ResponseGachNos.Add(rs);
                _context.SaveChanges();
                _Logger.LogError("Signature Content:" + SignatureContent + "/ sig:" + signature);
            }
            catch (Exception ex)
            {
                rs.responseCode = "03";
                rs.responseDesc = "Lỗi ngoại lệ: " + ex.Message + " " + ex.InnerException;
                _Logger.LogError("Lỗi không xử lý được Request - " + ex.Message + " " + ex.InnerException);
                _Logger.LogError("Lỗi không xử lý được Request MSV  " + req.custCode + " ErrMsg: " + ex.Message + " " + ex.InnerException);
                return rs;
            }

            return rs;
        }

        [HttpPost("sign-with-private")]
        // Sign with RSA using private key
        public string SignWithPrivate(string text, RSA rsa)
        {
            byte[] data = Encoding.UTF8.GetBytes(text);
            byte[] signature = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            return Convert.ToBase64String(signature);
        }
        [HttpPost("verify-with-public")]
        public bool VerifyWithPublic(string text, string signatureBase64, RSA rsa)
        {
            byte[] data = Encoding.UTF8.GetBytes(text);
            byte[] signature = Convert.FromBase64String(signatureBase64);
            bool isValid = rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            return isValid;
        }



    }
}
