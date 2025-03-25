using DocumentFormat.OpenXml.Packaging;
using DocumentFormat.OpenXml.Spreadsheet;
using DocumentFormat.OpenXml;
using Flic.Server.Interfaces;
using Flic.Shared.Models;
using Microsoft.AspNetCore.Mvc;
using ClosedXML.Excel;
//using NPOI.SS.UserModel;
//using NPOI.XSSF.UserModel.Extensions;
using System.IO;
using NPOI.HSSF.UserModel;
using NPOI.SS.UserModel;
using NPOI.XSSF.UserModel;
using System.Net;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using Flic.Shared;
using BootstrapBlazor.Components;
//using NPOI.XSSF.Streaming.Values;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace Flic.Server.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class DangkyTH03Controller : ControllerBase
    {
        // GET: api/<DangkyTH03Controller>
        private readonly IDangkyTH03 _Interface;
        private readonly IWebHostEnvironment env;
        private ILogger _Logger;
        public DangkyTH03Controller(IDangkyTH03 _Int, IWebHostEnvironment _env, ILogger logger)
        {
            _Interface = _Int;
            this.env = _env;
            _Logger = logger;
        }
        public static string ToUpperEveryWord(string s)
        {
            // Check for empty string.  
            s = s.ToLower();
            if (string.IsNullOrEmpty(s))
            {
                return string.Empty;
            }

            var words = s.Split(' ');

            var t = "";
            foreach (var word in words)
            {
                if (word !=" ")
                {
                    t += char.ToUpper(word[0]) + word.Substring(1) + ' ';
                }
                
            }
            return t.Trim();
        }
        //[HttpGet("TH03GetList")]
        //public async Task<List<DangkyTH03>> TH03GetList()
        //{
        //    return await Task.FromResult(_Interface.Get());
        //}

        [HttpGet("TH03GetList")]
        public async Task<List<DangkyTH03>> TH03GetList()
        {
            return await Task.FromResult(_Interface.Get());
        }

        //IActionResult
        [HttpGet("TH03GetListView/{dotthi}")]
        public async Task<List<DangkyTH03_View>> TH03GetListView(string dotthi = null)
        {
            return await Task.FromResult(_Interface.GetListView(dotthi));
        }

        [HttpGet("TH03GetPhieuDK/{cccd}")]
        public async Task<List<DangkyTH03>> TH03GetPhieuDK(string cccd)
        {
            var rs = await Task.FromResult(_Interface.Get());
            return rs.Where(m => m.CCCD == cccd).ToList();
        }
        [HttpGet("TH03GetListByDiadiem/{diadiem}")]
        public async Task<List<DangkyTH03>> TH03GetListByDiadiem(string diadiem)
        {
            return await Task.FromResult(_Interface.Get().ToList().Where(m => m.DiaDiemThi.ToLower().Contains(diadiem)).ToList());
        }
        [HttpGet("TH03GetListByDotthi/{dotthi}")]
        public async Task<List<DangkyTH03>> TH03GetListByDotthi(string dotthi)
        {
            return await Task.FromResult(_Interface.Get().ToList().Where(m => m.DotThi.ToLower().Contains(dotthi)).ToList());
        }

        [HttpGet("TH03GetByID/{id}")]
        public IActionResult TH03GetByID(int id)
        {
            DangkyTH03 item = _Interface.Get(id);
            if (item != null)
            {
                return Ok(item);
            }
            return NotFound();
        }
        [HttpGet("TH03GetViewByID/{id}")]
        public IActionResult TH03GetViewByID(int id)
        {
            DangkyTH03_View item = _Interface.GetView(id);
            if (item != null)
            {
                return Ok(item);
            }
            return NotFound();
        }
        [HttpGet("TH03GetByCCCD/{cccd}")]
        public IActionResult TH03GetByCCCD(string cccd)
        {
            List<DangkyTH03> items = _Interface.Get();
            
            return Ok(items.Where(m=>m.CCCD!=null && m.CCCD.Contains(cccd)).ToList());
        }

        [HttpPost("TH03Add")]
        public async Task<int> TH03Add(DangkyTH03 item)
        {

            try
            {
                item.HovaDem = ToUpperEveryWord(item.HovaDem.Trim());
                item.Ten = ToUpperEveryWord(item.Ten.Trim());
                var s = item.Ten.Split(' ');
                if (s.Length > 1)
                {
                    item.Ten = s[s.Length-1];
                    for (var i =0; i < s.Length-1; i++)
                    {
                        item.HovaDem += " " + s[i];
                    }
                }
                
                item.guid = Guid.NewGuid().ToString();
                //
                if (item.DiemLT != null || item.DiemTH != null) {
                    //Trường hợp nhập tay dữ liệu cũ đã có điểm thi
                    if (item.DiemLT != null && item.DiemLT >= 5 && item.DiemTH != null && item.DiemTH >= 5)
                    {
                        item.Ketqua = "Đạt";
                    }
                    else
                    {
                        item.Ketqua = "Không đạt";
                    }
                }
                
                int rs = _Interface.Add(item);
                return rs;
            }
            catch (Exception e)
            {
                throw e;
            }
        }

        [HttpPost("TH03LapDSThiTin")]
        public async Task<int> TH03LapDSThiTin(LapDSTinhoc item)
        {
            try
            {
                int rs = _Interface.LapDS(item);
                return rs;
            }
            catch (Exception e)
            {
                throw e;
            }
        }
        [HttpPost("TH03GetDSPTView")]
        public async Task<List<DangkyTH03_View>> TH03GetDSPTView([FromBody] string p)
        {
            return await Task.FromResult(_Interface.GetDSPhongthi(p));
        }

        [HttpPost("TH03GetDSSCCC")]
        public async Task<List<DangkyTH03_View>> TH03GetDSSCCC([FromBody] string p)
        {
            var list1 = _Interface.GetDSPhongthi(p).ToList();
            var list = list1.Where(x => x.DiemLT != null && x.DiemLT >= 5 && x.DiemTH != null && x.DiemTH >= 5).ToList();
            return await Task.FromResult(list);
        }

        [HttpPut("TH03Update")]
        public void TH03Update(DangkyTH03 item)
        {
            item.HovaDem = ToUpperEveryWord(item.HovaDem.Trim());
            item.Ten = ToUpperEveryWord(item.Ten.Trim());
            var s = item.Ten.Split(' ');
            if (s.Length > 1)
            {
                item.Ten = s[s.Length - 1];
                for (var i = 0; i < s.Length - 1; i++)
                {
                    item.HovaDem += " " + s[i];
                }
            }
            //if (item.guid.IsNullOrEmpty() ||  item.guid == null ||  item.guid=="")
            //{
            //    item.guid = Guid.NewGuid().ToString();
            //}
            if (string.IsNullOrEmpty(item.guid))
            {
                item.guid = Guid.NewGuid().ToString();
            }

            _Interface.Update(item);
        }

        [HttpPost("TH03ChangeDuDKState")]
        public void TH03ChangeDuDKState(ChangeDuDKState item)
        {
            _Interface.ChangeDuDKState(item);
        }

        [HttpDelete("TH03Delete/{id}")]
        public bool TH03Delete(int id)
        {
            try
            {
                _Interface.Delete(id);
                return true;
            }
            catch (Exception e)
            {
                System.Console.WriteLine("ERROR: Delete Lop ID " + id + " " + e.Message);
                return false;
            }
        }
        //Import diem thi
        [HttpPost("ImportDiemthi")]
        public IActionResult ImportDiemthi(Tinhoc03ImportView uploadedFile)
        {
            //var path = $"{env.WebRootPath}\\{uploadedFile.FileName}";
            string trustedFileNameForFileStorage;
            trustedFileNameForFileStorage = uploadedFile.FileName;//  Path.GetRandomFileName();
            var untrustedFileName = uploadedFile.FileName;
            var trustedFileNameForDisplay = WebUtility.HtmlEncode(untrustedFileName);
            Tinhoc03ImportResult result = new Tinhoc03ImportResult();

            StringBuilder sb = new StringBuilder();
            List<DangkyTH03> ImportedList = new List<DangkyTH03>();
            List<DangkyTH03> ExistList = new List<DangkyTH03>();
            List<DangkyTH03> ErrorList = new List<DangkyTH03>();

            var path = Path.Combine(env.ContentRootPath, "Uploads", trustedFileNameForFileStorage);
            var fs = System.IO.File.Create(path);
            fs.Write(uploadedFile.FileContent, 0,
            uploadedFile.FileContent.Length);
            fs.Close();
            FileStream fs1 = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            string sFileExtension = Path.GetExtension(uploadedFile.FileName).ToLower();
            ISheet sheet;

            if (sFileExtension == ".xls")
            {
                HSSFWorkbook hssfwb = new HSSFWorkbook(fs1); //This will read the Excel 97-2000 formats  
                sheet = hssfwb.GetSheetAt(0); //get first sheet from workbook  
            }
            else
            {
                XSSFWorkbook hssfwb = new XSSFWorkbook(fs1); //This will read 2007 Excel format      
                sheet = hssfwb.GetSheetAt(0); //get first sheet from workbook       
            }
            int first_row = 8;
            IRow headerRow = sheet.GetRow(first_row); //Get Header Row
            int cellCount = headerRow.LastCellNum;

            for (int j = 0; j < cellCount; j++)
            {
                NPOI.SS.UserModel.ICell cell = headerRow.GetCell(j);
                if (cell == null || string.IsNullOrWhiteSpace(cell.ToString())) continue;
            }
            //bo dòng cuối
            for (int i = (first_row + 1); i < sheet.LastRowNum; i++) //Read Excel File    
            {
                IRow row = sheet.GetRow(i);
                if (row == null) continue;
                if (row.Cells.All(d => d.CellType == NPOI.SS.UserModel.CellType.Blank)) continue;

                //DangkyTH03 usr = new DangkyTH03();
                try
                {
                    //string SoBD = row.GetCell(1).StringCellValue;
                    //string CCCD = row.GetCell(2).StringCellValue;
                    string SoBD = "";
                    string CCCD = "";
                    if (row.GetCell(1) != null) SoBD = row.GetCell(1).StringCellValue;
                    if (row.GetCell(2) != null) CCCD = row.GetCell(2).StringCellValue;

                    DangkyTH03 usr = _Interface.DangkyTH03Import(SoBD, CCCD, uploadedFile.Madotthi);
                    if ( usr != null )
                    {
                        try
                        {
                            if(row.GetCell(8) != null) usr.DiemLT = Math.Round(row.GetCell(8).NumericCellValue,1);
                            if(row.GetCell(9) != null) usr.DiemTH = Math.Round(row.GetCell(9).NumericCellValue,1);
                            //usr.SoChungChi = row.GetCell(10).StringCellValue;
                            //usr.SoVaoSo = row.GetCell(11).StringCellValue;
                        }
                        catch (Exception ex)
                        {
                            //Trường hợp bỏ thi, hoãn thi
                        }

                        usr.Ketqua = row.GetCell(10).StringCellValue;// row.GetCell(10).ToString();
                        if (_Interface.Update(usr))
                        {
                            ImportedList.Add(usr);
                        }
                        else
                        {
                            usr.Ghichu = "Update không thành công";
                            ErrorList.Add(usr);
                        }
                    }else
                    {
                        usr = new DangkyTH03();
                        if (row.GetCell(1) != null) usr.SoBD = row.GetCell(1).StringCellValue;
                        if (row.GetCell(2) != null) usr.CCCD = row.GetCell(2).StringCellValue;
                        if (row.GetCell(3) != null) usr.HovaDem = row.GetCell(3).StringCellValue;
                        if (row.GetCell(4) != null) usr.Ten = row.GetCell(4).StringCellValue;
                        if (row.GetCell(5) != null) usr.NgaySinh = row.GetCell(5).StringCellValue;
                        usr.Ghichu = "Không tìm thấy";

                        ErrorList.Add(usr);
                    }
                }
                catch (Exception e)
                {
                    DangkyTH03 usr = new DangkyTH03();                  
                    if (row.GetCell(1) != null) usr.SoBD = row.GetCell(1).StringCellValue;
                    if (row.GetCell(2) != null) usr.CCCD = row.GetCell(2).StringCellValue;
                    if (row.GetCell(3) != null) usr.HovaDem = row.GetCell(3).StringCellValue;
                    if (row.GetCell(4) != null) usr.Ten = row.GetCell(4).StringCellValue;
                    if (row.GetCell(5) != null) usr.NgaySinh = row.GetCell(5).StringCellValue;
                    usr.Ghichu = e.Message;
                    ErrorList.Add(usr);
                }
            }
            result.ErrorList = ErrorList;
            result.ImportedList = ImportedList;
            
            return Ok(result);

        }

        [HttpPost("ImportDiemthiLT")]
        public IActionResult ImportDiemthiLT(Tinhoc03ImportView uploadedFile)
        {
            //var path = $"{env.WebRootPath}\\{uploadedFile.FileName}";
            string trustedFileNameForFileStorage;
            trustedFileNameForFileStorage = uploadedFile.FileName;//  Path.GetRandomFileName();
            var untrustedFileName = uploadedFile.FileName;
            var trustedFileNameForDisplay = WebUtility.HtmlEncode(untrustedFileName);
            Tinhoc03ImportResult result = new Tinhoc03ImportResult();

            StringBuilder sb = new StringBuilder();
            List<DangkyTH03> ImportedList = new List<DangkyTH03>();
            List<DangkyTH03> ExistList = new List<DangkyTH03>();
            List<DangkyTH03> ErrorList = new List<DangkyTH03>();
            try
            {
                var path = Path.Combine(env.ContentRootPath, "Uploads", trustedFileNameForFileStorage);
                var fs = System.IO.File.Create(path);
                fs.Write(uploadedFile.FileContent, 0,
                uploadedFile.FileContent.Length);
                fs.Close();
                FileStream fs1 = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                string sFileExtension = Path.GetExtension(uploadedFile.FileName).ToLower();
                ISheet sheet;

                if (sFileExtension == ".xls")
                {
                    HSSFWorkbook hssfwb = new HSSFWorkbook(fs1); //This will read the Excel 97-2000 formats  
                    sheet = hssfwb.GetSheetAt(0); //get first sheet from workbook  
                }
                else
                {
                    XSSFWorkbook hssfwb = new XSSFWorkbook(fs1); //This will read 2007 Excel format      
                    sheet = hssfwb.GetSheetAt(0); //get first sheet from workbook       
                }
            

                int first_row = 0;
                IRow headerRow = sheet.GetRow(first_row); //Get Header Row
                int cellCount = headerRow.LastCellNum;

                for (int j = 0; j < cellCount; j++)
                {
                    NPOI.SS.UserModel.ICell cell = headerRow.GetCell(j);
                    if (cell == null || string.IsNullOrWhiteSpace(cell.ToString())) continue;
                }
                //bo dòng cuối
                for (int i = (first_row + 1); i <= sheet.LastRowNum; i++) //Read Excel File    
                {
                    IRow row = sheet.GetRow(i);
                    if (row == null) continue;
                    if (row.Cells.All(d => d.CellType == NPOI.SS.UserModel.CellType.Blank)) continue;

                    //DangkyTH03 usr = new DangkyTH03();
                    //0: First name; 1:Surname, 2: ID number (SBD),3: Institution, 4: Department, 5: Email address, 6: Điểm LT
                    try
                    {
                        //string SoBD = row.GetCell(1).StringCellValue;
                        //string CCCD = row.GetCell(2).StringCellValue;
                        string SoBD = "";
                    
                        if (row.GetCell(2) != null) SoBD = row.GetCell(2).StringCellValue;
                        //if (row.GetCell(2) != null) CCCD = row.GetCell(2).StringCellValue;

                        DangkyTH03 usr = _Interface.DangkyTH03Import(SoBD, uploadedFile.Madotthi);
                        if (usr != null && !usr.Lock)
                        {
                            try
                            {
                                if (row.GetCell(6) != null) usr.DiemLT = Math.Round(row.GetCell(6).NumericCellValue, 1);
                                //if (row.GetCell(9) != null) usr.DiemTH = Math.Round(row.GetCell(9).NumericCellValue, 1);
                                //usr.SoChungChi = row.GetCell(10).StringCellValue;
                                //usr.SoVaoSo = row.GetCell(11).StringCellValue;
                            }
                            catch (Exception ex)
                            {
                                //Trường hợp bỏ thi, hoãn thi
                            }
                            if (usr.DiemLT != null && usr.DiemLT >= 5 && usr.DiemTH != null && usr.DiemTH >= 5) {
                                usr.Ketqua = "Đạt";
                            } else 
                            {
                                usr.Ketqua = "Không đạt";
                            }

                            if (_Interface.Update(usr))
                            {
                                usr.Ghichu = "Update thành công";
                                ImportedList.Add(usr);
                            }
                            else
                            {
                                usr.Ghichu = "Update không thành công";
                                ErrorList.Add(usr);
                            }
                        }
                        else
                        {
                            usr = new DangkyTH03();
                            if (row.GetCell(0) != null) usr.HovaDem = row.GetCell(0).StringCellValue;                                                
                            if (row.GetCell(1) != null) usr.Ten = row.GetCell(1).StringCellValue;
                            if (row.GetCell(2) != null) usr.SoBD = row.GetCell(2).StringCellValue;

                            //if (row.GetCell(2) != null) usr.CCCD = row.GetCell(2).StringCellValue;
                            //if (row.GetCell(5) != null) usr.NgaySinh = row.GetCell(5).StringCellValue;
                            usr.Ghichu = "Không tìm thấy hoặc thông tin đã bị khóa";

                            ErrorList.Add(usr);
                        }
                    }
                    catch (Exception e)
                    {
                        DangkyTH03 usr = new DangkyTH03();
                        if (row.GetCell(0) != null) usr.HovaDem = row.GetCell(0).StringCellValue;
                        if (row.GetCell(1) != null) usr.Ten = row.GetCell(1).StringCellValue;
                        if (row.GetCell(2) != null) usr.SoBD = row.GetCell(2).StringCellValue;
                        usr.Ghichu = e.Message;
                        ErrorList.Add(usr);
                        _Logger.LogError("Lỗi - " + e.Message);
                    }
                }
                result.ErrorList = ErrorList;
                result.ImportedList = ImportedList;

                return Ok(result);
            }
            catch (Exception ex)
            {
                _Logger.LogError("Lỗi - " + ex.Message);
                return BadRequest(ex.Message);
            }

        }

        // Import Phach thuc hanh tu file excel gom nhieu sheet
        
        [HttpPost("ImportPhach")]
        public IActionResult ImportPhach(Tinhoc03ImportView uploadedFile)
        {
            //var path = $"{env.WebRootPath}\\{uploadedFile.FileName}";
            string trustedFileNameForFileStorage;
            trustedFileNameForFileStorage = uploadedFile.FileName;//  Path.GetRandomFileName();
            var untrustedFileName = uploadedFile.FileName;
            var trustedFileNameForDisplay = WebUtility.HtmlEncode(untrustedFileName);
            Tinhoc03ImportResult result = new Tinhoc03ImportResult();

            StringBuilder sb = new StringBuilder();
            List<DangkyTH03> ImportedList = new List<DangkyTH03>();
            List<DangkyTH03> ExistList = new List<DangkyTH03>();
            List<DangkyTH03> ErrorList = new List<DangkyTH03>();

            var path = Path.Combine(env.ContentRootPath, "Uploads", trustedFileNameForFileStorage);
            var fs = System.IO.File.Create(path);
            fs.Write(uploadedFile.FileContent, 0,
            uploadedFile.FileContent.Length);
            fs.Close();
            FileStream fs1 = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            string sFileExtension = Path.GetExtension(uploadedFile.FileName).ToLower();
            List<ISheet> sheets = new List<ISheet>();

            if (sFileExtension == ".xls")
            {
                HSSFWorkbook hssfwb = new HSSFWorkbook(fs1); //This will read the Excel 97-2000 formats  
                for (int i = 0; i < hssfwb.Count; i++)
                {
                    sheets.Add(hssfwb.GetSheetAt(i)); //get first sheet from workbook
                }
                //sheet = hssfwb.GetSheetAt(0); //get first sheet from workbook  
            }
            else
            {
                XSSFWorkbook hssfwb = new XSSFWorkbook(fs1); //This will read 2007 Excel format      


                for (int i = 0; i < hssfwb.Count; i++)
                {
                    sheets.Add(hssfwb.GetSheetAt(i)); //get first sheet from workbook
                }

            }
            result = ProcessImportPhach(sheets, uploadedFile.Madotthi);
            return Ok(result);

        }

        [HttpPost("ProcessImportPhach")]
        public Tinhoc03ImportResult ProcessImportPhach(List<ISheet> sheets, string Madotthi)
        {
            Tinhoc03ImportResult result = new Tinhoc03ImportResult();
            List<DangkyTH03> ImportedList = new List<DangkyTH03>();
            List<DangkyTH03> ExistList = new List<DangkyTH03>();
            List<DangkyTH03> ErrorList = new List<DangkyTH03>();
            foreach (ISheet sheet in sheets)
            {
                int first_row = 0;
                IRow headerRow = sheet.GetRow(first_row); //Get Header Row
                int cellCount = headerRow.LastCellNum;

                for (int j = 0; j < cellCount; j++)
                {
                    NPOI.SS.UserModel.ICell cell = headerRow.GetCell(j);
                    if (cell == null || string.IsNullOrWhiteSpace(cell.ToString())) continue;
                }
                
                for (int i = (first_row + 1); i <= sheet.LastRowNum; i++) //Read Excel File    
                {
                    IRow row = sheet.GetRow(i);
                    if (row == null) continue;
                    if (row.Cells.All(d => d.CellType == NPOI.SS.UserModel.CellType.Blank)) continue;

                    //DangkyTH03 usr = new DangkyTH03();
                    //0: STT; 1:SBD, 2: Số CCCD,3: Họ, 4: Tên, 5: Ngày sinh, 6: Giới tính, 7: Số phách, 8: Điểm TH
                    try
                    {
                        string SoBD = "";

                        if (row.GetCell(1) != null) SoBD = row.GetCell(1).StringCellValue;

                        DangkyTH03 usr = _Interface.DangkyTH03Import(SoBD, Madotthi);
                        if (usr != null && !usr.Lock)
                        {
                            try
                            {
                                if (row.GetCell(7) != null) usr.SoPhach = row.GetCell(7).StringCellValue;
                            }
                            catch (Exception ex)
                            {
                                //Trường hợp bỏ thi, hoãn thi
                            }
                            

                            if (_Interface.Update(usr))
                            {
                                usr.Ghichu = "Update thành công";
                                ImportedList.Add(usr);
                            }
                            else
                            {
                                usr.Ghichu = "Update không thành công";
                                ErrorList.Add(usr);
                            }
                        }
                        else
                        {
                            usr = new DangkyTH03();
                            if (row.GetCell(1) != null) usr.SoBD = row.GetCell(1).StringCellValue;
                            if (row.GetCell(3) != null) usr.HovaDem = row.GetCell(3).StringCellValue;
                            if (row.GetCell(4) != null) usr.Ten = row.GetCell(4).StringCellValue;
                            if (row.GetCell(7) != null) usr.SoPhach = row.GetCell(7).StringCellValue;

                            usr.Ghichu = "Không tìm thấy hoặc thông tin đã bị khóa";

                            ErrorList.Add(usr);
                        }
                    }
                    catch (Exception e)
                    {
                        DangkyTH03 usr = new DangkyTH03();
                        if (row.GetCell(1) != null) usr.SoBD = row.GetCell(1).StringCellValue;
                        if (row.GetCell(3) != null) usr.HovaDem = row.GetCell(3).StringCellValue;
                        if (row.GetCell(4) != null) usr.Ten = row.GetCell(4).StringCellValue;
                        if (row.GetCell(7) != null) usr.SoPhach = row.GetCell(7).StringCellValue;
                        usr.Ghichu = e.Message;
                        ErrorList.Add(usr);
                    }
                }
            }

            result.ErrorList = ErrorList;
            result.ImportedList = ImportedList;

            return result;
        }

        // Import diem thuc hanh tu file excel gom nhieu sheet
        public Tinhoc03ImportResult DiemthiTH(List<ISheet> sheets, string Madotthi)
        {
            Tinhoc03ImportResult result = new Tinhoc03ImportResult();
            List<DangkyTH03> ImportedList = new List<DangkyTH03>();
            List<DangkyTH03> ExistList = new List<DangkyTH03>();
            List<DangkyTH03> ErrorList = new List<DangkyTH03>();
            foreach (ISheet sheet in sheets)
            {
                int first_row = 0;
                IRow headerRow = sheet.GetRow(first_row); //Get Header Row
                int cellCount = headerRow.LastCellNum;

                for (int j = 0; j < cellCount; j++)
                {
                    NPOI.SS.UserModel.ICell cell = headerRow.GetCell(j);
                    if (cell == null || string.IsNullOrWhiteSpace(cell.ToString())) continue;
                }
                //bo dòng cuối
                for (int i = (first_row + 1); i <= sheet.LastRowNum; i++) //Read Excel File    
                {
                    IRow row = sheet.GetRow(i);
                    if (row == null) continue;
                    if (row.Cells.All(d => d.CellType == NPOI.SS.UserModel.CellType.Blank)) continue;

                    //DangkyTH03 usr = new DangkyTH03();
                    //0: STT; 1:SBD, 2: Số CCCD,3: Họ, 4: Tên, 5: Ngày sinh, 6: Giới tính, 7: Số phách, 8: Điểm TH
                    try
                    {
                        string SoBD = "";

                        if (row.GetCell(1) != null) SoBD = row.GetCell(1).StringCellValue;

                        DangkyTH03 usr = _Interface.DangkyTH03Import(SoBD, Madotthi);
                        if (usr != null && !usr.Lock)
                        {
                            try
                            {
                                if (row.GetCell(8) != null) usr.DiemTH = Math.Round(row.GetCell(8).NumericCellValue, 1);
                            }
                            catch (Exception ex)
                            {
                                //Trường hợp bỏ thi, hoãn thi
                            }
                            if (usr.DiemLT != null && usr.DiemLT >= 5 && usr.DiemTH != null && usr.DiemTH >= 5)
                            {
                                usr.Ketqua = "Đạt";
                            }
                            else
                            {
                                usr.Ketqua = "Không đạt";
                            }

                            if (_Interface.Update(usr))
                            {
                                usr.Ghichu = "Update thành công";
                                ImportedList.Add(usr);
                            }
                            else
                            {
                                usr.Ghichu = "Update không thành công";
                                ErrorList.Add(usr);
                            }
                        }
                        else
                        {
                            usr = new DangkyTH03();
                            if (row.GetCell(1) != null) usr.SoBD = row.GetCell(1).StringCellValue;
                            if (row.GetCell(3) != null) usr.HovaDem = row.GetCell(3).StringCellValue;
                            if (row.GetCell(4) != null) usr.Ten = row.GetCell(4).StringCellValue;
                            

                            usr.Ghichu = "Không tìm thấy hoặc thông tin đã bị khóa";

                            ErrorList.Add(usr);
                        }
                    }
                    catch (Exception e)
                    {
                        DangkyTH03 usr = new DangkyTH03();
                        if (row.GetCell(1) != null) usr.SoBD = row.GetCell(1).StringCellValue;
                        if (row.GetCell(3) != null) usr.HovaDem = row.GetCell(3).StringCellValue;
                        if (row.GetCell(4) != null) usr.Ten = row.GetCell(4).StringCellValue;
                        usr.Ghichu = e.Message;
                        ErrorList.Add(usr);
                    }
                }
            }
            
            result.ErrorList = ErrorList;
            result.ImportedList = ImportedList;

            return result;
        }

        [HttpPost("DiemthiTH")]
        // Import diem thuc hanh tu file excel gom nhieu sheet
        public Tinhoc03ImportResult DiemthiTH_Phach(List<ISheet> sheets, string Madotthi)
        {
            Tinhoc03ImportResult result = new Tinhoc03ImportResult();
            List<DangkyTH03> ImportedList = new List<DangkyTH03>();
            List<DangkyTH03> ExistList = new List<DangkyTH03>();
            List<DangkyTH03> ErrorList = new List<DangkyTH03>();
            foreach (ISheet sheet in sheets)
            {
                int first_row = 0;
                IRow headerRow = sheet.GetRow(first_row); //Get Header Row
                int cellCount = headerRow.LastCellNum;

                for (int j = 0; j < cellCount; j++)
                {
                    NPOI.SS.UserModel.ICell cell = headerRow.GetCell(j);
                    if (cell == null || string.IsNullOrWhiteSpace(cell.ToString())) continue;
                }
                //bo dòng cuối
                for (int i = (first_row + 1); i <= sheet.LastRowNum; i++) //Read Excel File    
                {
                    IRow row = sheet.GetRow(i);
                    if (row == null) continue;
                    if (row.Cells.All(d => d.CellType == NPOI.SS.UserModel.CellType.Blank)) continue;

                    //DangkyTH03 usr = new DangkyTH03();
                    //0: STT; 1:SoPhach, 2: Điểm TH
                    try
                    {
                        string SoPhach = "";

                        if (row.GetCell(1) != null) SoPhach = row.GetCell(1).StringCellValue;

                        DangkyTH03 usr = _Interface.DangkyTH03FindPhach(SoPhach, Madotthi);
                        if (usr != null && !usr.Lock)
                        {
                            try
                            {
                                if (row.GetCell(2) != null) usr.DiemTH = Math.Round(row.GetCell(2).NumericCellValue, 1);
                            }
                            catch (Exception ex)
                            {
                                //Trường hợp bỏ thi, hoãn thi
                            }
                            if (usr.DiemLT != null && usr.DiemLT >= 5 && usr.DiemTH != null && usr.DiemTH >= 5)
                            {
                                usr.Ketqua = "Đạt";
                            }
                            else
                            {
                                usr.Ketqua = "Không đạt";
                            }

                            if (_Interface.Update(usr))
                            {
                                usr.Ghichu = "Update thành công";
                                ImportedList.Add(usr);
                            }
                            else
                            {
                                usr.Ghichu = "Update không thành công";
                                ErrorList.Add(usr);
                            }
                        }
                        else
                        {
                            usr = new DangkyTH03();
                            if (row.GetCell(1) != null) usr.SoPhach = row.GetCell(1).StringCellValue;
                            //if (row.GetCell(3) != null) usr.HovaDem = row.GetCell(3).StringCellValue;
                            //if (row.GetCell(4) != null) usr.Ten = row.GetCell(4).StringCellValue;


                            usr.Ghichu = "Không tìm thấy hoặc thông tin đã bị khóa";

                            ErrorList.Add(usr);
                        }
                    }
                    catch (Exception e)
                    {
                        DangkyTH03 usr = new DangkyTH03();
                        if (row.GetCell(1) != null) usr.SoPhach = row.GetCell(1).StringCellValue;
                        
                        usr.Ghichu = e.Message;
                        ErrorList.Add(usr);
                    }
                }
            }

            result.ErrorList = ErrorList;
            result.ImportedList = ImportedList;

            return result;
        }

        [HttpPost("ImportDiemthiTH")]
        public IActionResult ImportDiemthiTH(Tinhoc03ImportView uploadedFile)
        {
            //var path = $"{env.WebRootPath}\\{uploadedFile.FileName}";
            string trustedFileNameForFileStorage;
            trustedFileNameForFileStorage = uploadedFile.FileName;//  Path.GetRandomFileName();
            var untrustedFileName = uploadedFile.FileName;
            var trustedFileNameForDisplay = WebUtility.HtmlEncode(untrustedFileName);
            Tinhoc03ImportResult result = new Tinhoc03ImportResult();

            StringBuilder sb = new StringBuilder();
            List<DangkyTH03> ImportedList = new List<DangkyTH03>();
            List<DangkyTH03> ExistList = new List<DangkyTH03>();
            List<DangkyTH03> ErrorList = new List<DangkyTH03>();

            var path = Path.Combine(env.ContentRootPath, "Uploads", trustedFileNameForFileStorage);
            var fs = System.IO.File.Create(path);
            fs.Write(uploadedFile.FileContent, 0,
            uploadedFile.FileContent.Length);
            fs.Close();
            FileStream fs1 = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            string sFileExtension = Path.GetExtension(uploadedFile.FileName).ToLower();
            List<ISheet> sheets = new List<ISheet>();
            
            if (sFileExtension == ".xls")
            {
                HSSFWorkbook hssfwb = new HSSFWorkbook(fs1); //This will read the Excel 97-2000 formats  
                for (int i = 0; i < hssfwb.Count; i++)
                {
                    sheets.Add(hssfwb.GetSheetAt(i)); //get first sheet from workbook
                }
                //sheet = hssfwb.GetSheetAt(0); //get first sheet from workbook  
            }
            else
            {
                XSSFWorkbook hssfwb = new XSSFWorkbook(fs1); //This will read 2007 Excel format      
                
                
                for (int i = 0; i < hssfwb.Count; i++)
                {
                    sheets.Add(hssfwb.GetSheetAt(i)); //get first sheet from workbook
                }
                
            }
            result = DiemthiTH_Phach(sheets, uploadedFile.Madotthi);
            return Ok(result);

        }
        //
        //Import diem thi
        [HttpPost("ImportSoCC")]
        public IActionResult ImportSoCC(Tinhoc03ImportView uploadedFile)
        {
            //var path = $"{env.WebRootPath}\\{uploadedFile.FileName}";
            string trustedFileNameForFileStorage;
            trustedFileNameForFileStorage = uploadedFile.FileName;//  Path.GetRandomFileName();
            var untrustedFileName = uploadedFile.FileName;
            var trustedFileNameForDisplay = WebUtility.HtmlEncode(untrustedFileName);
            Tinhoc03ImportResult result = new Tinhoc03ImportResult();

            StringBuilder sb = new StringBuilder();
            List<DangkyTH03> ImportedList = new List<DangkyTH03>();
            List<DangkyTH03> ExistList = new List<DangkyTH03>();
            List<DangkyTH03> ErrorList = new List<DangkyTH03>();

            var path = Path.Combine(env.ContentRootPath, "Uploads", trustedFileNameForFileStorage);
            var fs = System.IO.File.Create(path);
            fs.Write(uploadedFile.FileContent, 0,
            uploadedFile.FileContent.Length);
            fs.Close();
            FileStream fs1 = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            string sFileExtension = Path.GetExtension(uploadedFile.FileName).ToLower();
            ISheet sheet;

            if (sFileExtension == ".xls")
            {
                HSSFWorkbook hssfwb = new HSSFWorkbook(fs1); //This will read the Excel 97-2000 formats  
                sheet = hssfwb.GetSheetAt(0); //get first sheet from workbook  
            }
            else
            {
                XSSFWorkbook hssfwb = new XSSFWorkbook(fs1); //This will read 2007 Excel format      
                sheet = hssfwb.GetSheetAt(0); //get first sheet from workbook       
            }
            int first_row = 8;
            //IRow headerRow = sheet.GetRow(first_row); //Get Header Row
            //int cellCount = headerRow.LastCellNum;

            //for (int j = 0; j < cellCount; j++)
            //{
            //    NPOI.SS.UserModel.ICell cell = headerRow.GetCell(j);
            //    if (cell == null || string.IsNullOrWhiteSpace(cell.ToString())) continue;
            //}
            //bo dòng cuối
            for (int i = (first_row + 1); i < sheet.LastRowNum; i++) //Read Excel File    
            {
                IRow row = sheet.GetRow(i);
                if (row == null) continue;
                if (row.Cells.All(d => d.CellType == NPOI.SS.UserModel.CellType.Blank)) continue;

                //DangkyTH03 usr = new DangkyTH03();
                try
                {
                    string SoBD = "";
                    string CCCD = "";
                    if (row.GetCell(1) != null) SoBD = row.GetCell(1).StringCellValue;
                    if (row.GetCell(2) != null) CCCD = row.GetCell(2).StringCellValue;

                    DangkyTH03 usr = _Interface.DangkyTH03Import(SoBD, CCCD, uploadedFile.Madotthi);
                    if (usr != null)
                    {
                        try
                        {
                            //usr.DiemLT = Math.Round(row.GetCell(8).NumericCellValue, 1);
                            //usr.DiemTH = Math.Round(row.GetCell(9).NumericCellValue, 1);
                            if (row.GetCell(12) != null) usr.SoChungChi = row.GetCell(12).StringCellValue;
                            if (row.GetCell(13) != null)  usr.SoVaoSo = row.GetCell(13).StringCellValue;
                        }
                        catch (Exception ex)
                        {
                            //Trường hợp bỏ thi, hoãn thi
                        }

                        usr.Ketqua = row.GetCell(10).StringCellValue;// row.GetCell(10).ToString();
                        if (_Interface.Update(usr))
                        {
                            ImportedList.Add(usr);
                        }
                        else
                        {
                            usr.Ghichu = "Cập nhật thông tin khôn thành công!";
                            ErrorList.Add(usr);
                        }
                    }
                    else
                    {
                        usr = new DangkyTH03();
                        if (row.GetCell(1) != null) usr.SoBD = row.GetCell(1).StringCellValue;
                        if (row.GetCell(2) != null) usr.CCCD = row.GetCell(2).StringCellValue;
                        if (row.GetCell(3) != null) usr.HovaDem = row.GetCell(3).StringCellValue;
                        if (row.GetCell(4) != null) usr.Ten = row.GetCell(4).StringCellValue;
                        if (row.GetCell(5) != null) usr.NgaySinh = row.GetCell(5).StringCellValue;
                        usr.Ghichu = "Không tìm thấy";
                        ErrorList.Add(usr);
                    }
                }
                catch (Exception e)
                {
                    DangkyTH03 usr = new DangkyTH03();
                    if (row.GetCell(1) != null) usr.SoBD = row.GetCell(1).StringCellValue;
                    if (row.GetCell(2) != null) usr.CCCD = row.GetCell(2).StringCellValue;
                    if (row.GetCell(3) != null) usr.HovaDem = row.GetCell(3).StringCellValue;
                    if (row.GetCell(4) != null) if (row.GetCell(4)!=null) usr.Ten = row.GetCell(4).StringCellValue;
                    if (row.GetCell(5) != null) usr.NgaySinh = row.GetCell(5).StringCellValue;
                    usr.Ghichu = e.Message;
                    ErrorList.Add(usr);
                }
            }
            result.ErrorList = ErrorList;
            result.ImportedList = ImportedList;

            return Ok(result);

        }

    }
}
