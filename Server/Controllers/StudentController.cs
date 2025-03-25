using Microsoft.AspNetCore.Mvc;
using Flic.Server.Interfaces;
using Microsoft.AspNetCore.Cors;
using Flic.Shared.Models;
using Microsoft.AspNetCore.Authorization;
using Sylvan.Data.Excel;
using System.Net.Http.Headers;
using Flic.Shared;
using System.Net;
using Microsoft.VisualBasic;
using System.Collections.Generic;
using NPOI.SS.UserModel;
using NPOI.HSSF.UserModel;
using NPOI.XSSF.UserModel;
using System.Text;
using System;
using System.IO;
using Microsoft.AspNetCore.Mvc.RazorPages;
using static Microsoft.Extensions.Logging.EventSource.LoggingEventSource;
using System.Drawing.Printing;
// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace Flic.Server.Controllers
{
    //[Authorize]
    [Route("api/[controller]")]
    [ApiController]
    
    public class StudentController : ControllerBase
    {
        // GET: api/<StudentController>
        private readonly IStudent _IStudent;
        private readonly IWebHostEnvironment env;
        public StudentController(IStudent iStudent, IWebHostEnvironment env)
        {
            _IStudent = iStudent;
            this.env = env;
        }
        
        [HttpGet("GetStudent")]
        public async Task<StudentSearchOption> Get()
        {
            StudentSearchOption s = new StudentSearchOption();
            return await Task.FromResult(_IStudent.GetStudent(s));

        }

        [HttpGet("GetStudentList/{khoahoc}")]
        public async Task<List<Student>> GetStudentList(string khoahoc=null)
        {            
            return await Task.FromResult(_IStudent.GetStudentList(khoahoc));
        }

        [HttpPost("PostStudentList")]
        public async Task<StudentSearchOption> PostStudentList(StudentSearchOption s)
        {            
            return  await Task.FromResult(_IStudent.GetStudent(s));            
        }

        [HttpGet("StudentGetByID/{id}")]
        public IActionResult StudentGetByID(int id)
        {
            Student user = _IStudent.GetStudent(id);
            if (user != null)
            {
                return Ok(user);
            }
            return NotFound();
        }
        [HttpGet("StudentGetByMSV/{msv}")]
        public IActionResult StudentGetByMSV(string msv)
        {
            Student user = _IStudent.GetStudentByMSV(msv);
            if (user != null)
            {
                return Ok(user);
            }
            return NotFound();
        }
        [HttpPost("StudentAdd")]
        public bool StudentAdd(Student user)
        {
            try
            {
                _IStudent.AddStudent(user);
                return true;
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
            return false;
        }
        [HttpPut("StudentUpdate")]
        public bool StudentUpdate(Student user)
        {
            try
            {
                _IStudent.UpdateStudent(user);
                return true;
            }catch(Exception e)
            {
                Console.WriteLine(e.Message);                
            }
            return false;
        }
        [HttpDelete("StudentDelete/{id}")]
        public bool StudentDelete(int id)
        {
            try
            {
                _IStudent.DeleteStudent(id);
                return true;
            }catch (Exception e)
            {
                Console.WriteLine("Lỗi xóa sinh viên: " +e.Message);
                return false;
            }           
            
        }
        [HttpGet("StudentImport")]
        public IActionResult StudentImport()
        {
            try
            {
                var file = Request.Form.Files[0];
                var folderName = Path.Combine("StaticFiles", "Images");
                var pathToSave = Path.Combine(Directory.GetCurrentDirectory(), folderName);
                if (file.Length > 0)
                {
                    var fileName = ContentDispositionHeaderValue.Parse(file.ContentDisposition).FileName.Trim('"');
                    var fullPath = Path.Combine(pathToSave, fileName);
                    var dbPath = Path.Combine(folderName, fileName);
                    using (var stream = new FileStream(fullPath, FileMode.Create))
                    {
                        file.CopyTo(stream);
                    }
                    return Ok(dbPath);
                }
                else
                {
                    return BadRequest();
                }
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Internal server error: {ex}");
            }
            
        }
        [HttpPost("StudentUploadFile")]
        
        public IActionResult StudentUploadFile(StudentImportView uploadedFile)
        {
            //var path = $"{env.WebRootPath}\\{uploadedFile.FileName}";
            string trustedFileNameForFileStorage;
            trustedFileNameForFileStorage = uploadedFile.FileName;//  Path.GetRandomFileName();
            var untrustedFileName = uploadedFile.FileName;
            var trustedFileNameForDisplay =   WebUtility.HtmlEncode(untrustedFileName);
            StudentImportResult result = new StudentImportResult();

            StringBuilder sb = new StringBuilder();
            List<Student> ImportedList = new List<Student>();
            List<Student> ExistList = new List<Student>();
            List<Student> ErrorList = new List<Student>();

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
            IRow headerRow = sheet.GetRow(0); //Get Header Row
            int cellCount = headerRow.LastCellNum;
            
            for (int j = 0; j < cellCount; j++)
            {
                NPOI.SS.UserModel.ICell cell = headerRow.GetCell(j);
                if (cell == null || string.IsNullOrWhiteSpace(cell.ToString())) continue;            
            }
            
            for (int i = (sheet.FirstRowNum + 1); i <= sheet.LastRowNum; i++) //Read Excel File    
            {
                IRow row = sheet.GetRow(i);
                if (row == null) continue;
                if (row.Cells.All(d => d.CellType == CellType.Blank)) continue;
                
                Student usr = new Student();
                try
                {
                    
                    usr.MaSV = row.GetCell(1).ToString();
                    usr.HoDem = row.GetCell(2).ToString();
                    usr.Ten = row.GetCell(3).ToString();
                    usr.Ngaysinh = row.GetCell(4).ToString();
                    //usr.CCCD = row.GetCell(3).ToString();
                    //usr.DienThoai = row.GetCell(4).ToString();
                    //usr.Email = row.GetCell(5).ToString();
                    usr.LopID = uploadedFile.LopID;
                    usr.NganhID = uploadedFile.NganhID;
                    usr.KhoaID = uploadedFile.KhoaID;
                    usr.KhoahocID = uploadedFile.KhoahocID;
                    usr.Trangthai = "DH";
                    var id = _IStudent.NotExist(usr);
                    if (id <= 0)
                    {
                        _IStudent.AddStudent(usr);
                        ImportedList.Add(usr);
                    }
                    else
                    {
                        usr.id = id;
                        _IStudent.UpdateStudent(usr);
                        ExistList.Add(usr);
                    }
                }
                catch (Exception e)
                {
                    ErrorList.Add(usr);
                }
            }
            result.ErrorList = ErrorList;
            result.ImportedList = ImportedList;
            result.ExistList = ExistList;
            return Ok(result);

        }




    }
}
