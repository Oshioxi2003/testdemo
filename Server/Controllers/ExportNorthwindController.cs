using ExportOperations;
using Flic.Server.Data;
using Flic.Server.Interfaces;
using Flic.Shared.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Linq;

namespace RadzenBlazorDemos
{
    public partial class ExportNorthwindController : ExportController
    {
        //private readonly NorthwindContext context;
        readonly ApplicationDbContext context;
        private readonly IDangkyTH03 _Interface;
        private readonly IDKHoc _IDangkyHoc;
        public ExportNorthwindController(ApplicationDbContext context, IDangkyTH03 _Int, IDKHoc iDangkyHoc)
        {
            this.context = context;
            _Interface = _Int;
            _IDangkyHoc = iDangkyHoc;
        }

        [HttpGet("/export/students/csv")]
        public FileStreamResult ExportCategoriesToCSV()
        {
            return ToCSV(ApplyQuery(context.Students, Request.Query));
        }

        [HttpGet("/export/students/excel")]
        public FileStreamResult ExportStudentsToExcel()
        {            
            return ToExcel(ApplyQuery(context.Students, Request.Query));
        }
        //
        [HttpGet("/export/students/excel/{makhoahocs}")]
        public FileStreamResult ExportStudentsByKhoaToExcel(string makhoahocs)
        {
            //var student_list = context.Students.Where().ToList();            
            var _khoahoc = makhoahocs.Split(';').ToList();
            var list = context.Students.Where(t => _khoahoc.Contains(t.KhoahocID)).ToList();
            //var query = from t in list select new Student { };
            return ToExcel(ApplyQuery(list.AsQueryable(), Request.Query));
            //return ToExcel(ApplyQuery(context.Students, Request.Query));
        }
        //
        [HttpGet("/export/thutiens/excel/{kythanhtoan}")]
        public FileStreamResult ExportThutiensToExcel(string kythanhtoan)
        {
            var thutien_list = context.ThuTiens.Where(m=>m.KyThanhToan != null && m.KyThanhToan.Equals(kythanhtoan)).ToList();
            var student_list = context.Students.Where(m => m.Trangthai == "DH").ToList();
            var khoaDict = context.Khoas.ToDictionary(m => m.Id, m => m.Name);
            var nganhDict = context.Nganhs.ToDictionary(m => m.Id, m => m.Name);

            var query = (from a in thutien_list
                         join b in student_list on a.SinhVienID equals b.id
                         select new ThuTienView
                         {
                             id = a.id,
                             SinhVienID = a.SinhVienID,
                             MaSinhVien = b.MaSV,
                             HoDem = b.HoDem,
                             Ten = b.Ten,
                             Ngaysinh = b.Ngaysinh,
                             SoCCCD = b.CCCD,
                             LoaiKhoanthuID = a.LoaiKhoanthuID,
                             KhoahocID = b.KhoahocID,
                             KhoaID = b.KhoaID,
                             KhoaTen = khoaDict.ContainsKey(b.KhoaID) ? khoaDict[b.KhoaID] : "-",
                             NganhID = b.NganhID,
                             NganhTen = nganhDict.ContainsKey(b.NganhID) ? nganhDict[b.NganhID] : "-",
                             LopID = b.LopID,
                             KyThanhToan = a.KyThanhToan,
                             SoTien = a.SoTien,
                             NgayTao = a.NgayTao,
                             NgayThanhToan = a.NgayThanhToan,
                             TrangThai = a.TrangThai
                         });
            return ToExcel(ApplyQuery(query.AsQueryable(), Request.Query));
        }
        [HttpGet("/export/DangkyhocToExcel/excel/{makhoahocs}")]
        public FileStreamResult ExportDangkyhocToExcel(string makhoahocs)
        {
            var rs = _IDangkyHoc.GetListView(makhoahocs);
            return ToExcel(ApplyQuery(rs.list.AsQueryable(), Request.Query));
        }
        

        [HttpGet("/export/tinhoc03list/excel/{madotthi}")]
        public FileStreamResult ExportTinhoc03ListToExcel(string madotthi)
        {            
            var ls = _Interface.GetDSPhongthi(madotthi);
            return ToExcel(ApplyQuery(ls.AsQueryable(), Request.Query));
        }
        [HttpGet("/export/tinhoc03dsdk/excel/{madotthi}")]
        public FileStreamResult ExportTinhoc03DSDKToExcel(string madotthi)
        {
            var ls = _Interface.GetDSDangky(madotthi);
            return ToExcel(ApplyQuery(ls.AsQueryable(), Request.Query));
        }
        //Tinhoc03DSPT        
        [HttpGet("/export/tinhoc03dsDuDK/excel/{madotthi}")]
        public FileStreamResult ExportTinhoc03DSDuDKToExcel(string madotthi)
        {
            var ls = _Interface.GetDSDuDK(madotthi);
            return ToExcel(ApplyQuery(ls.AsQueryable(), Request.Query));
        }
        [HttpGet("/export/Tinhoc03DSPT2Excel/excel/{madotthi}")]
        public FileStreamResult Tinhoc03DSPTToExcel(string madotthi)
        {
            
            var ls = _Interface.GetDSPhongthi(madotthi);
            return DSPTToExcel(ls);            
        }

        [HttpGet("/export/Tinhoc03DSLT2Excel/excel/{madotthi}")]
        public FileStreamResult Tinhoc03DSLT2Excel(string madotthi)
        {
           
            var ls = _Interface.GetDSPhongthi(madotthi);
            return DSLythuyetToExcel(ls);
        }
        [HttpGet("/export/Tinhoc03DSTH2Excel/excel/{madotthi}")]
        public FileStreamResult Tinhoc03DSTH2Excel(string madotthi)
        {
           
            var ls = _Interface.GetDSPhongthi(madotthi);
            return DSThuchanhToExcel(ls);
        }
        [HttpGet("/export/Tinhoc03DSTaikhoan/excel/{madotthi}")]
        public FileStreamResult Tinhoc03DSTaikhoan(string madotthi)
        {
           
            var ls = _Interface.GetDSPhongthi(madotthi);
            return DSTaikhoanToExcel(ls);
        }
        [HttpGet("/export/Tinhoc03DSTaikhoanPT/excel/{madotthi}")]
        public FileStreamResult Tinhoc03DSTaikhoanPT(string madotthi)
        {

            var ls = _Interface.GetDSPhongthi(madotthi);
            return DSTKPhongthiToExcel(ls);
        }
        [HttpGet("/export/Tinhoc03DsAnh/excel/{madotthi}")]
        public FileStreamResult Tinhoc03DsAnhPDF(string madotthi)
        {
            var ls = _Interface.GetDSPhongthi(madotthi);
            return DSAnhToExcel(ls);
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="madotthi"></param>
        /// <returns></returns>
        [HttpGet("/export/Tinhoc03DsKQ/excel/{madotthi}")]
        public FileStreamResult Tinhoc03DsKQ(string madotthi)
        {
            var ls = _Interface.GetKetqua(madotthi);
            return Tinhoc03DsKQToExcel(ls);
        }
        
            [HttpGet("/export/Tinhoc03DSCapChungchi/excel/{madotthi}")]
        public FileStreamResult Tinhoc03DSCapChungchi(string madotthi)
        {
            var ls = _Interface.GetSocapCC(madotthi);
            return Tinhoc03DSCapChungchiToExcel(ls);
        }
        ///
        [HttpGet("/export/Tinhoc03DScapCC/excel/{madotthi}")]
        public FileStreamResult Tinhoc03DScapCC(string madotthi)
        {
            var ls = _Interface.GetSocapCC(madotthi);
            return DScapCCToExcel(ls);
        }

        [HttpGet("/export/Tinhoc03SocapCC/excel/{madotthi}")]
        public FileStreamResult Tinhoc03SocapCC(string madotthi)
        {
            var ls = _Interface.GetSocapCC(madotthi);
            return Tinhoc03SoCapChungchiToExcel(ls);
        }

        [HttpGet("/export/Taichinh_DutruKP/excel/{madonvi}")]
        public FileStreamResult Taichinh_DutruKP(string madonvi)
        {
            var ls = context.TAICHINH_DuTruKP.Where(m=>m.MaDonVi.Equals(madonvi)).ToList();
            return Taichinh_DutruKP(ls);
        }
        [HttpGet("/export/Taichinh_TongHopDutruKP/excel")]
        public FileStreamResult Taichinh_TongHopDutruKP()
        {
            var list = context.TAICHINH_DuTruKP.ToList();
            var donviList = context.Khoas.ToList();
            return Taichinh_TongHopDutruKP(donviList, list);
        }
        [HttpGet("/export/Taichinh_TongHopTheoMucChi/excel")]
        public FileStreamResult Taichinh_TongHopTheoMucChi()
        {
            var list = context.TAICHINH_DuTruKP.ToList();
            var mucchiList = context.TAICHINH_MucChi.ToList();
            return Taichinh_TongHopTheoMucChi(mucchiList, list);
        }
        //[HttpGet("/export/customers/csv")]
        //public FileStreamResult ExportCustomersToCSV()
        //{
        //    return ToCSV(ApplyQuery(context.Customers, Request.Query));
        //}

        //[HttpGet("/export/customers/excel")]
        //public FileStreamResult ExportCustomersToExcel()
        //{
        //    return ToExcel(ApplyQuery(context.Customers, Request.Query));
        //}

        //[HttpGet("/export/customercustomerdemos/csv")]
        //public FileStreamResult ExportCustomerCustomerDemosToCSV()
        //{
        //    return ToCSV(ApplyQuery(context.CustomerCustomerDemos, Request.Query));
        //}

        //[HttpGet("/export/Northwind/customercustomerdemos/excel")]
        //public FileStreamResult ExportCustomerCustomerDemosToExcel()
        //{
        //    return ToExcel(ApplyQuery(context.CustomerCustomerDemos, Request.Query));
        //}

        //[HttpGet("/export/Northwind/customerdemographics/csv")]
        //public FileStreamResult ExportCustomerDemographicsToCSV()
        //{
        //    return ToCSV(ApplyQuery(context.CustomerDemographics, Request.Query));
        //}

        //[HttpGet("/export/Northwind/customerdemographics/excel")]
        //public FileStreamResult ExportCustomerDemographicsToExcel()
        //{
        //    return ToExcel(ApplyQuery(context.CustomerDemographics, Request.Query));
        //}

        //[HttpGet("/export/Northwind/employees/csv")]
        //public FileStreamResult ExportEmployeesToCSV()
        //{
        //    return ToCSV(ApplyQuery(context.Employees, Request.Query));
        //}

        //[HttpGet("/export/Northwind/employees/excel")]
        //public FileStreamResult ExportEmployeesToExcel()
        //{
        //    return ToExcel(ApplyQuery(context.Employees, Request.Query));
        //}

        //[HttpGet("/export/Northwind/employeeterritories/csv")]
        //public FileStreamResult ExportEmployeeTerritoriesToCSV()
        //{
        //    return ToCSV(ApplyQuery(context.EmployeeTerritories, Request.Query));
        //}

        //[HttpGet("/export/Northwind/employeeterritories/excel")]
        //public FileStreamResult ExportEmployeeTerritoriesToExcel()
        //{
        //    return ToExcel(ApplyQuery(context.EmployeeTerritories, Request.Query));
        //}

        //[HttpGet("/export/Northwind/orders/csv")]
        //public FileStreamResult ExportOrdersToCSV()
        //{
        //    return ToCSV(ApplyQuery(context.Orders, Request.Query));
        //}

        //[HttpGet("/export/Northwind/orders/excel")]
        //public FileStreamResult ExportOrdersToExcel()
        //{
        //    return ToExcel(ApplyQuery(context.Orders, Request.Query));
        //}

        //[HttpGet("/export/Northwind/orderdetails/csv")]
        //public FileStreamResult ExportOrderDetailsToCSV()
        //{
        //    return ToCSV(ApplyQuery(context.OrderDetails, Request.Query));
        //}

        //[HttpGet("/export/Northwind/orderdetails/excel")]
        //public FileStreamResult ExportOrderDetailsToExcel()
        //{
        //    return ToExcel(ApplyQuery(context.OrderDetails, Request.Query));
        //}

        //[HttpGet("/export/Northwind/products/csv")]
        //public FileStreamResult ExportProductsToCSV()
        //{
        //    return ToCSV(ApplyQuery(context.Products, Request.Query));
        //}

        //[HttpGet("/export/Northwind/products/excel")]
        //public FileStreamResult ExportProductsToExcel()
        //{
        //    return ToExcel(ApplyQuery(context.Products, Request.Query));
        //}

        //[HttpGet("/export/Northwind/regions/csv")]
        //public FileStreamResult ExportRegionsToCSV()
        //{
        //    return ToCSV(ApplyQuery(context.Regions, Request.Query));
        //}

        //[HttpGet("/export/Northwind/regions/excel")]
        //public FileStreamResult ExportRegionsToExcel()
        //{
        //    return ToExcel(ApplyQuery(context.Regions, Request.Query));
        //}

        //[HttpGet("/export/Northwind/suppliers/csv")]
        //public FileStreamResult ExportSuppliersToCSV()
        //{
        //    return ToCSV(ApplyQuery(context.Suppliers, Request.Query));
        //}

        //[HttpGet("/export/Northwind/suppliers/excel")]
        //public FileStreamResult ExportSuppliersToExcel()
        //{
        //    return ToExcel(ApplyQuery(context.Suppliers, Request.Query));
        //}

        //[HttpGet("/export/Northwind/territories/csv")]
        //public FileStreamResult ExportTerritoriesToCSV()
        //{
        //    return ToCSV(ApplyQuery(context.Territories, Request.Query));
        //}

        //[HttpGet("/export/Northwind/territories/excel")]
        //public FileStreamResult ExportTerritoriesToExcel()
        //{
        //    return ToExcel(ApplyQuery(context.Territories, Request.Query));
        //}
    }
}
