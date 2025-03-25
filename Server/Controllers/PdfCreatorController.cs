using DinkToPdf.Contracts;
using DinkToPdf;
using Flic.Shared.Models;
using Microsoft.AspNetCore.Mvc;
using Flic.Server.Data;
using Flic.Server.Interfaces;
using System.Text;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace Flic.Server.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class PdfCreatorController : ControllerBase
    {
        private IConverter _converter;
        readonly ApplicationDbContext _dbContext;
        private readonly IDangkyTH03 _Interface;
        public PdfCreatorController(IConverter converter, ApplicationDbContext dbContext, IDangkyTH03 _Int)
        {
            _converter = converter;
            _dbContext = dbContext;
            _Interface = _Int;
        }
        [HttpGet("CreatePDF")]
        public IActionResult CreatePDF()
        {
            List<DangkyTH03> list = new List<DangkyTH03>();
            list = _dbContext.DangkyTH03s.ToList();
            var globalSettings = new GlobalSettings
            {
                ColorMode = ColorMode.Color,
                Orientation = Orientation.Portrait,
                PaperSize = PaperKind.A4,
                Margins = new MarginSettings { Top = 10 },
                DocumentTitle = "PDF Report",
                Out = @"D:\Employee_Report.pdf"
            };
            var objectSettings = new ObjectSettings
            {
                PagesCount = true,
                HtmlContent = TemplateGenerator.GetHTMLString(list),
                WebSettings = { DefaultEncoding = "utf-8", EnableIntelligentShrinking = false, UserStyleSheet = Path.Combine(Directory.GetCurrentDirectory(), "assets", "styles.css") },
                HeaderSettings = { FontName = "Arial", FontSize = 9, Right = "Page [page] of [toPage]", Line = true },
                FooterSettings = { FontName = "Arial", FontSize = 9, Line = true, Center = "Report Footer" }
            };
            var pdf = new HtmlToPdfDocument()
            {
                GlobalSettings = globalSettings,
                Objects = { objectSettings }
            };
            _converter.Convert(pdf);
            return Ok("Successfully created PDF document.");
        }
        [HttpGet("CreateDonDK/{id}")]
        public IActionResult CreateDonDK(int id)
        {
            DangkyTH03_View tmp = new DangkyTH03_View();
            tmp = _Interface.GetView(id);
            string path = "\\StaticFiles\\PHIEU_" + id.ToString() + ".pdf";
            var globalSettings = new GlobalSettings
            {
                ColorMode = ColorMode.Color,
                Orientation = Orientation.Portrait,
                PaperSize = PaperKind.A4,
                Margins = new MarginSettings { Top = 20, Left=20, Right=20, Bottom=20 },
                DocumentTitle = "PHIẾU ĐĂNG KÝ",
                Out = Directory.GetCurrentDirectory() + path //@"D:\Employee_Report.pdf"
            };
            string template = "";
            
            string FilePath = Directory.GetCurrentDirectory() + "\\Templates\\don.html";
            string EmailTemplateText = System.IO.File.ReadAllText(FilePath);

            var objectSettings = new ObjectSettings
            {
                PagesCount = true,
                HtmlContent = TemplateGenerator.CreatePhieuDK(tmp, EmailTemplateText),
                WebSettings = { DefaultEncoding = "utf-8", EnableIntelligentShrinking = false, UserStyleSheet = Path.Combine(Directory.GetCurrentDirectory(), "assets", "styles.css") },
                HeaderSettings = { FontName = "Arial", FontSize = 9, Right = "", Line = false },
                FooterSettings = { FontName = "Arial", FontSize = 9, Line = false, Center = "" }
            };
            var pdf = new HtmlToPdfDocument()
            {
                GlobalSettings = globalSettings,
                Objects = { objectSettings }
            };
            _converter.Convert(pdf);
            return Ok(path);
        }

        [HttpGet("CreateTheDuthi/{id}")]
        public IActionResult CreateTheDuthi(int id)
        {
            DangkyTH03_View tmp = new DangkyTH03_View();
            tmp = _Interface.GetView(id);
            string path = "\\StaticFiles\\THE_" + id.ToString() + ".pdf";
            var globalSettings = new GlobalSettings
            {
                ColorMode = ColorMode.Color,
                Orientation = Orientation.Portrait,
                PaperSize = PaperKind.A4,
                Margins = new MarginSettings { Top = 20, Left = 20, Right = 15, Bottom = 20 },
                DocumentTitle = "THẺ DỰ THI",
                Out = Directory.GetCurrentDirectory() + path //@"D:\Employee_Report.pdf"
            };
            string template = "";

            string FilePath = Directory.GetCurrentDirectory() + "\\Templates\\theduthi.html";
            string EmailTemplateText = System.IO.File.ReadAllText(FilePath);

            var objectSettings = new ObjectSettings
            {
                PagesCount = true,
                HtmlContent = TemplateGenerator.CreateTheDuthi(tmp, EmailTemplateText),
                WebSettings = { DefaultEncoding = "utf-8", EnableIntelligentShrinking = false, UserStyleSheet = Path.Combine(Directory.GetCurrentDirectory(), "assets", "styles.css") },
                HeaderSettings = { FontName = "Arial", FontSize = 9, Right = "", Line = false },
                FooterSettings = { FontName = "Arial", FontSize = 9, Line = false, Center = "" }
            };
            var pdf = new HtmlToPdfDocument()
            {
                GlobalSettings = globalSettings,
                Objects = { objectSettings }
            };
            _converter.Convert(pdf);
            return Ok(path);
        }

        [HttpGet("CreateAnhPhongthi/{ma}")]
        public IActionResult CreateAnhPhongthi(string ma)
        {
            DangkyTH03_View tmp = new DangkyTH03_View();
            var list = _Interface.GetDSPhongthi(ma);
            string path = "\\StaticFiles\\ANH_" + ma + ".pdf";
            var globalSettings = new GlobalSettings
            {
                ColorMode = ColorMode.Color,
                Orientation = Orientation.Portrait,
                PaperSize = PaperKind.A4,
                Margins = new MarginSettings { Top = 20, Left = 20, Right = 20, Bottom = 20 },
                DocumentTitle = "ẢNH PHÒNG THI",
                Out = Directory.GetCurrentDirectory() + path //@"D:\Employee_Report.pdf"
            };
            string template = "<div class='row'>";
            if(list != null)
            {
                var dsPhongthi = list.Where(m => m.PhongThi != null).DistinctBy(m => m.PhongThi).ToList();
                foreach(var pt in dsPhongthi)
                {
                    var dsCathi = list.Where(m => m.PhongThi != null && m.PhongThi == pt.PhongThi).Where(m => m.CaThi != null).DistinctBy(m => m.CaThi).ToList();
                    foreach(var c in dsCathi)
                    {
                        var dsThisinh = list.Where(m => m.PhongThi != null && m.PhongThi == pt.PhongThi).Where(m => m.CaThi != null && m.CaThi == c.CaThi).ToList();
                        template  += "<div class='container' style='width: 100%;'>";
                        template += "<div style = 'width: 100%;' >";
                        template += "<div style='text-align:center'> DANH SÁCH ẢNH PHÒNG THI</div>";
                        template += "<div style='text-align:center'>KỲ THI CẤP CHỨNG CHỈ ỨNG DỤNG CÔNG NGHỆ THÔNG TIN</div>";
                        template += "<div style='text-align:center'>" + @pt.PhongThi + " " + @c.CaThi + "</div>";
                        template += "</div>";
                        template += "<div style = 'width: 100%;' >";
                        foreach(var ts in dsThisinh)
                        {
                            template += "<div style = 'width: 25%; float: left; box-sizing: border-box' >";
                            template += "<div>";
                            template += "<div>" + ts.SoBD + "</div>";
                            //template += "<div>" + ts.CCCD + "</div>";
                            template += "<div>" + ts.HovaDem + " " + ts.Ten + "</div>";
                            template += "<div>" + ts.NgaySinh + "</div>";
                            template += "</div>";
                            template += "<div style = 'width:100%; height: 150px; border: 1px solid #000;'>";
                            template += "</div>";
                            template += "</div>";

                        }
                        template += "</div>";
                        template += "<div style='clear:both;'>" + "Phòng thi " + @pt.PhongThi + "  Ca: " + @c.CaThi + "có" + dsThisinh.Count + " thí sinh </div>";
                        template += "<div class='row'>";
                        template += "<div class='col4' style='float:right;'>";
                        template += "<div> ..., ngày....tháng....năm..........  </div>";
                        template += "<div>CHỦ TỊCH HỘI ĐỒNG THI</div>";
                        template += "<div>(Ký và ghi rõ họ tên)</div>";
                        template += "</div>";
                        template += "</div>";
                        template += "</div>";
                            
                        }
                    }
                }
            template += "</div>";
            var sb = new StringBuilder();
            sb.Append(template);
            var objectSettings = new ObjectSettings
            {
                PagesCount = true,
                HtmlContent = sb.ToString(),
                WebSettings = { DefaultEncoding = "utf-8", UserStyleSheet = Path.Combine(Directory.GetCurrentDirectory(), "assets", "styles.css") },
                HeaderSettings = { FontName = "Arial", FontSize = 9, Right = "", Line = false },
                FooterSettings = { FontName = "Arial", FontSize = 9, Line = false, Center = "" }
            };
            var pdf = new HtmlToPdfDocument()
            {
                GlobalSettings = globalSettings,
                Objects = { objectSettings }
            };
            _converter.Convert(pdf);
            return Ok(path);
        }
    }
}
