using com.google.zxing.qrcode;
using DocumentFormat.OpenXml.InkML;
using DocumentFormat.OpenXml.Office2010.Excel;
using Flic.Server.Data;
using Flic.Server.Interfaces;
using Flic.Shared.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using QRCoder;
using System.Drawing;
using System.Text.RegularExpressions;
// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace Flic.Server.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class DKHocController : ControllerBase
    {
        private readonly IDKHoc _IDKHoc;
        readonly ApplicationDbContext _dbContext;
        private readonly IWebHostEnvironment env;
        private readonly IConfiguration _configuration;
        public VietQR qr;
        public DKHocController(IDKHoc dkhoc, ApplicationDbContext dbContext, 
            IWebHostEnvironment env, IConfiguration configuration)
        {
            _IDKHoc = dkhoc;
            _dbContext = dbContext;
            this.env = env;
            _configuration = configuration;
            qr = new VietQR(_configuration["QR:payloadFormatIndicator"],
                _configuration["QR:pointOfInitiationMethod"],
                _configuration["QR:consumerAccountInformation"],
                _configuration["QR:transactionCurrency"],
                _configuration["QR:countryCode"]
                );
        }

        // GET: api/<LophocController>
        [HttpGet("DKHocGetList")]
        public async Task<List<DKHoc>> DKHocGetList()
        {
            return await Task.FromResult(_IDKHoc.Get());
        }
        //
        [HttpGet("DKHocGetListActive")]
        public async Task<List<DKHoc>> DKHocGetListActive()
        {
            return await Task.FromResult(_IDKHoc.GetActive());
        }
        //
        [HttpGet("DKHocGetListByLoai/{loailop}")]
        public async Task<List<DKHoc>> DKHocGetListByLoai(string loailop)
        {
            List<string> LL = new List<string>(loailop.Split(";"));
            var list = _IDKHoc.GetActive().Where(m=>m.CourseId !=null && LL.Contains(m.CourseId.ToString())).ToList();
            return await Task.FromResult(list);
        }

        [HttpGet("DKHocGetListInActive")]
        public async Task<List<DKHoc>> DKHocGetListInActive()
        {
            return await Task.FromResult(_IDKHoc.GetInActive());
        }
        // GET api/<LophocController>/5
        [HttpGet("DKHocGetByID/{id}")]
        public IActionResult GetByID(int id)
        {
            DKHoc item = _IDKHoc.Get(id);
            using (QRCodeGenerator qrGenerator = new QRCodeGenerator())
            using (QRCodeData qrCodeData = qrGenerator.CreateQrCode("The text which should be encoded.", QRCodeGenerator.ECCLevel.Q))
            using (PngByteQRCode qrCode = new PngByteQRCode(qrCodeData))
            {
                byte[] qrCodeImage = qrCode.GetGraphic(20);
            }
            //return View(BitmapToBytes(qrCodeImage));

            if (item != null)
            {
                return Ok(item);
            }
            return NotFound();
        }
        public string LocDau(string str)
        {
            str = str.ToLower();
            str = Regex.Replace(str, "[àáạảãâầấậẩẫăằắặẳẵ]", "a");
            str = Regex.Replace(str, "[èéẹẻẽêềếệểễ]", "e");
            str = Regex.Replace(str, "[ìíịỉĩ]", "i");
            str = Regex.Replace(str, "[òóọỏõôồốộổỗơờớợởỡ]", "o");
            str = Regex.Replace(str, "[ùúụủũưừứựửữ]", "u");
            str = Regex.Replace(str, "[ỳýỵỷỹ]", "y");
            str = Regex.Replace(str, "đ", "d");
            //str = Regex.Replace(str, " ", "-");
            str = str.Replace(",", "");
            str = str.Replace(".", "");
            return str.ToUpper();
        }
        [HttpGet("DKHocGetQRByID/{id}")]
        public IActionResult DKHocGetQRByID(int id)
        {
            DKHoc item = _IDKHoc.Get(id);

            //return View(BitmapToBytes(qrCodeImage));
            //QRCodeGenerator qrGen= new QRCodeGenerator();
            //QRCodeReader qrCodeReader = new QRCodeReader();
            //var path = Path.Combine(env.ContentRootPath, "Uploads/qr_sample.png");
            //byte[] image = System.IO.File.ReadAllBytes(path);
            //QRCodeData qrData = qrCodeReader.decode(image);
            //QRCodeData qrData = new QRCodeData(path, QRCodeData.Compression.Uncompressed);

          

            if (item != null)
            {                
                
                qr.setTransactionAmount(item.Hocphi.ToString());
                //qr.setAdditionalDataFieldTemplate("DEMO");
                string hoten = LocDau(item.HovaDem + " " + item.Ten);
                string str = "TATC:" + item.MaSinhvien + "_" + hoten +"_"+ item.LopID + "_" + item.DienThoai + "_" + item.Id.ToString();
                if (str.Length > 99) { str = str.Substring(0, 98); }
                //qr.setAdditionalDataFieldTemplate(str);
                //qr.setBillNumber(item.Id.ToString());
                qr.setPurposeOfTransaction(str);
                //qr.setOther(str);
                //qr.setBillNumber(item.Id.ToString());
                //qr.setMobileNumber(item.DienThoai);
                //qr.setCustomerLabel(item.MaSinhvien);
                //qr.setStoreLabel(item.HovaDem + " " + item.Ten);
                //qr.setPurposeOfTransaction("TATC");

                var qrContent = qr.buidQR();
                using (QRCodeGenerator qrGenerator = new QRCodeGenerator())
                //using (QRCodeData qrCodeData = qrGenerator.CreateQrCode("00020101021138570010A00000072701270006970422011331501291288880208QRIBFTTA53037045802VN80300012com.vng.zalo0110ZABANKCARD63040B9D", QRCodeGenerator.ECCLevel.Q))
                using (QRCodeData qrCodeData = qrGenerator.CreateQrCode(qrContent, QRCodeGenerator.ECCLevel.Q))
                using (PngByteQRCode qrCode = new PngByteQRCode(qrCodeData))
                {
                    byte[] qrCodeImage = qrCode.GetGraphic(20); 

                    //string str = System.Convert.ToBase64String(qrCodeImage);
                    var imagesrc = Convert.ToBase64String(qrCodeImage);
                    var imageDataURL = string.Format("data:image/jpeg;base64,{0}", imagesrc);
                    return Ok(imageDataURL);
                }
                //return Ok(item);
            }
            return NotFound();
        }
        [HttpGet("DKHocGetByCCCD/{cccd}")]
        public IActionResult DKHocGetByCCCD(string cccd)
        {
            List<DKHoc> items = _IDKHoc.Get();
            if (items != null)
            {
                return Ok(items);
            }
            return NotFound();
        }
        [HttpGet("DKHocGetByMobile/{mobile}")]
        public IActionResult DKHocGetByMobile(string mobile)
        {
            List<DKHoc> list = _IDKHoc.GetByMobile(mobile);
            var _lophoc = _dbContext.Lophocs.ToList().Distinct().ToDictionary(x => x.Id, x => x.TenLop);
            if (list != null)
            {
                List<DKHocView> ls = new List<DKHocView>();
                int index = 1;
                foreach (var item in list)
                {
                    DKHocView rs = new DKHocView();
                    rs.Id = item.Id;
                    rs.HovaDem = item.HovaDem;
                    rs.Ten = item.Ten;
                    rs.GioiTinh = item.GioiTinh;
                    rs.DiaChi = item.DiaChi;
                    rs.Email = item.Email;
                    rs.DienThoai = item.DienThoai;
                    rs.Trangthai = item.Trangthai;
                    rs.NgayThanhtoan = item.NgayThanhtoan;

                    string str;
                    bool hasValue;
                    if (item.CourseId != null)
                    {
                        hasValue = _lophoc.TryGetValue(item.CourseId, out str);
                        if (hasValue) rs.CourseName = str;
                    }                    
                    ls.Add(rs);
                }
                return Ok(ls);
            }
            return NotFound();
        }
        [HttpGet("DKHocGetByEmail/{email}")]
        public IActionResult DKHocGetByEmail(string email)
        {
            List<DKHoc> list = _IDKHoc.GetByEmail(email);
            var _lophoc = _dbContext.Lophocs.ToList().Distinct().ToDictionary(x => x.Id, x => x.TenLop);
            if (list != null)
            {
                List<DKHocView> ls = new List<DKHocView>();
                int index = 1;
                foreach (var item in list)
                {
                    DKHocView rs = new DKHocView();
                    rs.Id = item.Id;
                    rs.HovaDem = item.HovaDem;
                    rs.Ten = item.Ten;
                    rs.GioiTinh = item.GioiTinh;
                    rs.DiaChi = item.DiaChi;
                    rs.Email = item.Email;
                    rs.DienThoai = item.DienThoai;
                    rs.Trangthai = item.Trangthai;
                    rs.NgayThanhtoan = item.NgayThanhtoan;

                    string str;
                    bool hasValue;
                    if (item.CourseId != null)
                    {
                        hasValue = _lophoc.TryGetValue(item.CourseId, out str);
                        if (hasValue) rs.CourseName = str;
                    }
                    ls.Add(rs);
                }
                return Ok(ls);
            }
            return NotFound();
        }
        // POST api/<LophocController>

        [HttpPost("DKHocAdd")]
        public async Task<IActionResult> DKHocAdd(DKHoc item)
        {
            try
            {
                _IDKHoc.Add(item);
                return Ok(item);
            }
            catch (Exception e)
            {
                return BadRequest();
            }
        }

        // PUT api/<LophocController>/5
        [HttpPut("DKHocUpdate")]
        public void LophocUpdate(DKHoc item)
        {
            _IDKHoc.Update(item);
        }

        // DELETE api/<LophocController>/5
        [HttpDelete("DKHocDelete/{id}")]
        public bool DKHocDelete(int id)
        {
            try
            {
                _IDKHoc.Delete(id);
                return true;
            }
            catch (Exception e)
            {
                Console.WriteLine("ERROR: Delete Lop ID " + id + " " + e.Message);
                return false;
            }

        }
    }
}
