using Flic.Server.Data;
using Flic.Server.Interfaces;
using Flic.Shared;
using Flic.Shared.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Data;
using System.Runtime.Serialization.Formatters.Binary;
using System.Runtime.Serialization;
using System.Linq.Expressions;
using NPOI.SS.UserModel;
using ClosedXML.Excel;
using NPOI.HSSF.UserModel;
using NPOI.XSSF.UserModel;
using System.Net;
using System.Text;
using System.Xml.Serialization;

namespace eBHYT.Server.Controllers
{
    [Authorize]
    [Route("api/[controller]")]
    [ApiController]
    
    public class ThutienController : ControllerBase
    {
        // readonly ApplicationDbContext _context;
        private readonly IThutien _IThutien;
        private readonly IWebHostEnvironment env;
        public ThutienController(IThutien context, IWebHostEnvironment env)
        {
            this._IThutien = context;
            this.env = env;
        }
        //public static byte[] GetBytesFromDatatable(DataTable table)
        //{
        //    byte[] data = null;
        //    using (MemoryStream stream = new MemoryStream())
        //    {
        //        IFormatter bf = new BinaryFormatter();
        //        table.RemotingFormat = SerializationFormat.Binary;
        //        try{
        //            bf.Serialize(stream, table);
        //        }
        //        catch (Exception ex)
        //        {
        //            throw new Exception(ex.Message);
        //        }
        //        data = stream.ToArray();
        //    }
        //    return data;
        //}
        public static byte[] GetBytesFromDatatable(DataTable table)
        {

            if (table == null) throw new ArgumentNullException(nameof(table));

            using (MemoryStream stream = new MemoryStream())
            {
                XmlSerializer serializer = new XmlSerializer(typeof(DataTable));
                serializer.Serialize(stream, table);
                return stream.ToArray();
            }
        }

        public static DataTable DeserializeFromBytes(byte[] data)
        {
            if (data == null || data.Length == 0) throw new ArgumentNullException(nameof(data));

            using (MemoryStream stream = new MemoryStream(data))
            {
                XmlSerializer serializer = new XmlSerializer(typeof(DataTable));
                return (DataTable)serializer.Deserialize(stream);
            }
        }

        [HttpGet("ThutienGetList")]
        public async Task<List<ThuTienView>> ThutienGetList()
        {
            try
            {                
                return await Task.FromResult(_IThutien.Get());
            }
            catch (Exception e)
            {
                Console.Write(e.Message);
                return null;
            }
        }
        //
        [HttpGet("ThutienGetByKyThanhtoan/{LoaiKhoanthu}/{KyThanhtoan}")]
        public async Task<List<ThuTienView>> ThutienGetByKyThanhtoan(string LoaiKhoanthu, string KyThanhtoan)
        {
            try
            {
                return await Task.FromResult(_IThutien.GetByKyThanhtoan(LoaiKhoanthu,KyThanhtoan));
            }
            catch (Exception e)
            {
                Console.Write(e.Message);
                return null;
            }
        }
        //
        [HttpPost("PostThutienList")]        
        public async Task<ThutienSearchOption> PostThutienList(ThutienSearchOption s)
        {
            return await Task.FromResult(_IThutien.GetThutiens(s));
        }
        [HttpPost("PostThutienExport")]
        public async Task<List<ThuTienView>> PostThutienExport(ThutienSearchOption s)
        {
            List<ThuTienView> thutiens = _IThutien.GetThutienExport(s);         

            return await Task.FromResult(thutiens);
        }
        [HttpGet("ThutienGetByID/{id}")]
        public IActionResult ThutienGetByID(int id)
        {
            ThuTienView item = _IThutien.Get(id);
            if (item != null)
            {
                return Ok(item);
            }
            return NotFound();
        }

        [HttpGet("ThutienGetByMSV/{ma}")]
        public async Task<List<ThuTienView>> ThutienGetByMSV(string ma)
        {
            try
            {
                return await Task.FromResult(_IThutien.GetByMSV(ma));
            }
            catch (Exception e)
            {
                Console.Write(e.Message);
                return null;
            }
        }

        [HttpGet("ThutienThanhtoanByMSV/{ma}")]
        public async Task<bool> ThutienThanhtoanByMSV(string ma)
        {
            try
            {                
                return await Task.FromResult(_IThutien.ThanhtoanByMSV(ma));
            }
            catch (Exception e)
            {
                Console.Write(e.Message);
                return false;
            }
        }

        [HttpPost("ThutienAdd")]
        public async Task<IActionResult> ThutienAdd(ThuTienView tt)
        {  
            try
            {
                ThuTien item = new ThuTien();
                item.id = tt.id;
                item.SinhVienID= tt.SinhVienID;
                item.LoaiKhoanthuID = tt.LoaiKhoanthuID;
                item.KyThanhToan=tt.KyThanhToan;
                item.SoTien= tt.SoTien;
                item.NgayTao = DateTime.Now;
                item.TrangThai = 0;
                if ( _IThutien.Add(item)){
                    return Ok();
                }
                return BadRequest("Không tạo mới được");
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                return BadRequest(e.Message);
            }
        }
        [HttpPut ("ThutienUpdate")]
        public async Task<bool> ThutienUpdate(ThuTienView item)
        {
            try
            {
                ThuTien t = new ThuTien();
                t.id = item.id;
                t.SoTien = item.SoTien;
                t.SinhVienID = item.SinhVienID;
                t.LoaiKhoanthuID = item.LoaiKhoanthuID;
                t.KyThanhToan = item.KyThanhToan;
                t.NgayTao = item.NgayTao;
                t.TrangThai = item.TrangThai;

                _IThutien.Update(t);
                return true;
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                return false;
            }           

        }
        [HttpPost("ThutienLapDS")]
        public async Task<bool> ThutienLapDS(ThuTienView kt)
        {
            try
            {
                _IThutien.LapDS(kt);
                return true;
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                return false;
            }

        }
        //Import danh sách khoản thu đối với sinh viên cho một loại khoản thu, một kỳ thu đã chọn
        //Input: 1 file excel gồm các cột sau:
        //0: STT; 1: Mã sinh viên; 2: Họ đêm; 3: Tên; 4: Lớp; 5:Số tiền
        [HttpPost("ThutienImport")]
        public IActionResult ThutienImport(ThutienImportView uploadedFile)
        {
            //var path = $"{env.WebRootPath}\\{uploadedFile.FileName}";
            string trustedFileNameForFileStorage;
            trustedFileNameForFileStorage = uploadedFile.FileName;//  Path.GetRandomFileName();
            var untrustedFileName = uploadedFile.FileName;
            var trustedFileNameForDisplay = WebUtility.HtmlEncode(untrustedFileName);
            ThutienImportResult result = new ThutienImportResult();

            StringBuilder sb = new StringBuilder();
            List<ThuTienView> ImportedList = new List<ThuTienView>();
            List<ThuTienView> ExistList = new List<ThuTienView>();
            List<ThuTienView> ErrorList = new List<ThuTienView>();

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
                    string MaSV = "";

                    if (row.GetCell(1) != null) MaSV = row.GetCell(1).StringCellValue;

                    ThuTienView usr = new ThuTienView();
                    
                    usr = _IThutien.GetByMSV(MaSV)
                        .Where(m => m.LoaiKhoanthuID != null && m.LoaiKhoanthuID.Equals(uploadedFile.LoaiKhoanthu))
                        .Where(m => m.KyThanhToan != null && m.KyThanhToan.Equals(uploadedFile.KyThanhtoan))
                        .FirstOrDefault();

                    if (usr != null)
                    {

                        //Đã có tên sinh viên này trong khoản thu
                        // Thông báo khoản thu đã có trong cơ sở dữ liệu
                        if (row.GetCell(0) != null) usr.STT = Convert.ToInt16(row.GetCell(0).NumericCellValue);// STT
                        if (row.GetCell(1) != null) usr.MaSinhVien = row.GetCell(1).StringCellValue;
                        if (row.GetCell(2) != null) usr.HoDem = row.GetCell(2).StringCellValue;
                        if (row.GetCell(3) != null) usr.Ten = row.GetCell(3).StringCellValue;
                        if (row.GetCell(4) != null) usr.LopID = row.GetCell(4).StringCellValue;
                        if (row.GetCell(5) != null) usr.SoTien = row.GetCell(5).NumericCellValue;

                        usr.LoaiKhoanthuID = uploadedFile.LoaiKhoanthu;
                        usr.KyThanhToan = uploadedFile.KyThanhtoan;

                        usr.Ghichu = "Lỗi: Khoản thu này đã có trong cơ sở dữ liệu";
                        ExistList.Add(usr);
                    }
                    else
                    {
                        // Chua có khoản thu đối với sinh viên
                        // Thêm khoản thu này
                        usr = new ThuTienView();
                        if (row.GetCell(0) != null) usr.STT = Convert.ToInt16(row.GetCell(0).NumericCellValue);// STT
                        if (row.GetCell(1) != null) usr.MaSinhVien = row.GetCell(1).StringCellValue;
                        if (row.GetCell(2) != null) usr.HoDem = row.GetCell(2).StringCellValue;
                        if (row.GetCell(3) != null) usr.Ten = row.GetCell(3).StringCellValue;                        
                        if (row.GetCell(4) != null) usr.LopID = row.GetCell(4).StringCellValue;
                        if (row.GetCell(5) != null) usr.SoTien = row.GetCell(5).NumericCellValue;

                        usr.LoaiKhoanthuID = uploadedFile.LoaiKhoanthu;
                        usr.KyThanhToan = uploadedFile.KyThanhtoan;
                        if (row.GetCell(1) == null || row.GetCell(5)==null)
                        {
                            usr.Ghichu = "Import lỗi: Mã sinh viên hoặc số tiền null";
                            ErrorList.Add(usr);
                        }
                        else
                        {
                            try
                            {
                                _IThutien.AddFromView(usr);
                                usr.Ghichu = "Import thành công";
                                ImportedList.Add(usr);
                            }
                            catch (Exception ex)
                            {
                                usr.Ghichu = "Import lỗi: " + ex.Message;
                                ErrorList.Add(usr);
                            }
                        }                       
                                                
                    }
                }
                catch (Exception e)
                {
                    ThuTienView usr = new ThuTienView();
                    if (row.GetCell(0) != null) usr.STT = Convert.ToInt16(row.GetCell(0).NumericCellValue);// STT
                    if (row.GetCell(1) != null) usr.MaSinhVien = row.GetCell(1).StringCellValue;
                    if (row.GetCell(2) != null) usr.HoDem = row.GetCell(2).StringCellValue;
                    if (row.GetCell(3) != null) usr.Ten = row.GetCell(3).StringCellValue;
                    if (row.GetCell(4) != null) usr.LopID = row.GetCell(4).StringCellValue;
                    if (row.GetCell(5) != null) usr.SoTien = row.GetCell(5).NumericCellValue;

                    usr.LoaiKhoanthuID = uploadedFile.LoaiKhoanthu;
                    usr.KyThanhToan = uploadedFile.KyThanhtoan;

                    usr.Ghichu = "Import lỗi:" + e.Message;
                                        
                    ErrorList.Add(usr);
                }
            }
            result.ErrorList = ErrorList;
            result.ImportedList = ImportedList;
            result.ExistList = ExistList;

            return Ok(result);

        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="kt"></param>
        /// <returns></returns>
        //Import danh sách khoản thu đối với sinh viên cho một loại khoản thu, một kỳ thu đã chọn
        //Input: 1 file excel gồm các cột sau:
        //0: STT; 1: Mã sinh viên; 2: Họ đêm; 3: Tên; 4: Lớp; 5:Số tiền; 6: Trạng thái (0: chưa thanh toán; 1: đã thanh toán)
        [HttpPost("ThutienImportTrangthai")]
        public IActionResult ThutienImportTrangthai(ThutienImportView uploadedFile)
        {
            //var path = $"{env.WebRootPath}\\{uploadedFile.FileName}";
            string trustedFileNameForFileStorage;
            trustedFileNameForFileStorage = uploadedFile.FileName;//  Path.GetRandomFileName();
            var untrustedFileName = uploadedFile.FileName;
            var trustedFileNameForDisplay = WebUtility.HtmlEncode(untrustedFileName);
            ThutienImportResult result = new ThutienImportResult();

            StringBuilder sb = new StringBuilder();
            List<ThuTienView> ImportedList = new List<ThuTienView>();
            List<ThuTienView> ExistList = new List<ThuTienView>();
            List<ThuTienView> ErrorList = new List<ThuTienView>();

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
                    string MaSV = "";

                    if (row.GetCell(1) != null) MaSV = row.GetCell(1).StringCellValue;

                    ThuTienView usr = new ThuTienView();
                    double _SoTien=0;
                    if (row.GetCell(5) != null) _SoTien = row.GetCell(5).NumericCellValue;

                    usr = _IThutien.GetByMSV(MaSV)
                        .Where(m => m.LoaiKhoanthuID != null && m.LoaiKhoanthuID.Equals(uploadedFile.LoaiKhoanthu))
                        .Where(m => m.KyThanhToan != null && m.KyThanhToan.Equals(uploadedFile.KyThanhtoan))
                        .Where(m=>m.SoTien!=null && Math.Abs(m.SoTien.Value - _SoTien) < 0.00001)
                        .FirstOrDefault();

                    if (usr != null)
                    {
                        //Đã có tên sinh viên này trong khoản thu
                        // Thông báo khoản thu đã có trong cơ sở dữ liệu
                        if (row.GetCell(0) != null) usr.STT = Convert.ToInt16(row.GetCell(0).NumericCellValue);// STT
                        if (row.GetCell(1) != null) usr.MaSinhVien = row.GetCell(1).StringCellValue;
                        if (row.GetCell(2) != null) usr.HoDem = row.GetCell(2).StringCellValue;
                        if (row.GetCell(3) != null) usr.Ten = row.GetCell(3).StringCellValue;
                        if (row.GetCell(4) != null) usr.LopID = row.GetCell(4).StringCellValue;
                        if (row.GetCell(5) != null) usr.SoTien = row.GetCell(5).NumericCellValue;
                        
                        usr.LoaiKhoanthuID = uploadedFile.LoaiKhoanthu;
                        usr.KyThanhToan = uploadedFile.KyThanhtoan;
                        //
                        ThuTien u = _IThutien.GetById(usr.id.Value);
                        if (row.GetCell(6) != null)
                        {                            
                            try
                            {
                                u.TrangThai = Convert.ToInt16(row.GetCell(6).NumericCellValue);
                                _IThutien.Update(u);
                                usr.Ghichu = "Cập nhật thành công";
                                ImportedList.Add(usr);
                            }
                            catch (Exception ex)
                            {
                                usr.Ghichu = "Lỗi: Cập nhật không thành công" + ex.Message;
                                ErrorList.Add(usr);
                            }
                        }
                        else
                        {
                            usr.Ghichu = "Lỗi: Cập nhật không thành công: Cột Trạng thái không có dữ liệu";
                            ErrorList.Add(usr);
                        }
                    }
                    else
                    {
                        // Chua có khoản thu đối với sinh viên
                        // Thêm khoản thu này
                        usr = new ThuTienView();
                        if (row.GetCell(0) != null) usr.STT = Convert.ToInt16(row.GetCell(0).NumericCellValue);// STT
                        if (row.GetCell(1) != null) usr.MaSinhVien = row.GetCell(1).StringCellValue;
                        if (row.GetCell(2) != null) usr.HoDem = row.GetCell(2).StringCellValue;
                        if (row.GetCell(3) != null) usr.Ten = row.GetCell(3).StringCellValue;
                        if (row.GetCell(4) != null) usr.LopID = row.GetCell(4).StringCellValue;
                        if (row.GetCell(5) != null) usr.SoTien = row.GetCell(5).NumericCellValue;

                        usr.LoaiKhoanthuID = uploadedFile.LoaiKhoanthu;
                        usr.KyThanhToan = uploadedFile.KyThanhtoan;
                        usr.Ghichu = "Lỗi: Chưa có khoản thu này trong cơ sở dữ liệu";
                        ErrorList.Add(usr);
                        
                    }
                }
                catch (Exception e)
                {
                    ThuTienView usr = new ThuTienView();
                    if (row.GetCell(0) != null) usr.STT = Convert.ToInt16(row.GetCell(0).NumericCellValue);// STT
                    if (row.GetCell(1) != null) usr.MaSinhVien = row.GetCell(1).StringCellValue;
                    if (row.GetCell(2) != null) usr.HoDem = row.GetCell(2).StringCellValue;
                    if (row.GetCell(3) != null) usr.Ten = row.GetCell(3).StringCellValue;
                    if (row.GetCell(4) != null) usr.LopID = row.GetCell(4).StringCellValue;
                    if (row.GetCell(5) != null) usr.SoTien = row.GetCell(5).NumericCellValue;

                    usr.LoaiKhoanthuID = uploadedFile.LoaiKhoanthu;
                    usr.KyThanhToan = uploadedFile.KyThanhtoan;

                    usr.Ghichu = "Import lỗi:" + e.Message;

                    ErrorList.Add(usr);
                }
            }
            result.ErrorList = ErrorList;
            result.ImportedList = ImportedList;
            result.ExistList = ExistList;

            return Ok(result);

        }
        //
        [HttpPost("ThutienKTXLapDS")]
        public async Task<bool> ThutienKTXLapDS(ThuTienView kt)
        {
            try
            {
                _IThutien.LapDS_KTX(kt);
                return true;
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                return false;
            }

        }
        [HttpDelete("ThutienDelete/{id}")]
        public async Task<bool> ThutienDelete(int id)
        {
            try
            {
                _IThutien.Delete(id);
                return true;
            }
            catch (Exception e)
            {
                return false;
            }
            
        }

    }
}
