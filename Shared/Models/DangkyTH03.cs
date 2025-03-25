using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Flic.Shared.Models
{
    public class ChangeDuDKState
    {
        public int id { get; set; }
        public bool value { get; set; }
    }
    public class DangkyTH03
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int Id { get; set; }
        public string HovaDem { get; set; }
        public string Ten { get; set; }
        public int GioiTinh { get; set; }
        public string NgaySinh { get; set; }        
        public int NoiSinh_Tinh { get; set; }
        public int DanToc { get; set; }
        public string CCCD { get; set; }        
        public string CCCD_NgayCap { get; set; }
        public string CCCD_NoiCap { get; set; }
        public string DienThoai { get; set; }
        public string DiaChi { get; set; }
        public string Email { get; set; }
        public int DKOnThi { get; set; }
        public int? LePhiThi { get; set; }
        public int? LePhiOn { get; set; }
        public string DiaDiemThi { get; set; }
        public string DotThi { get; set; }
        public int Trangthai { get; set; }
        public bool Lock { get; set; }
        public string? MaSinhvien { get; set; }
        public string? KhoahocID { get; set; }
        public string? KhoaID { get; set; }
        public string? NganhID { get; set; }
        public string? LopID { get; set; }
        public bool DuDKThi { get; set; }
        public string? SoBD { get; set; }
        public string? PhongThi { get; set; }
        public string? CaThi { get; set; }
        public string? Taikhoan { get; set; }
        public string? Matkhau { get; set; }
        public string? SoPhach { get; set; }
        public double? DiemLT { get; set; }
        public double? DiemTH { get; set; }
        public string? Ketqua { get; set; }
        public string? SoChungChi { get; set; }
        public string? SoVaoSo { get; set; }
        public DateTime? NgayTao { get; set; }
        public DateTime? NgaySua { get; set; }
        public string? Ghichu { get ; set; } 
        public string? guid { get; set; }
        // Thong tin thanh toan
        public bool? PaymentSuccess { get; set; }
        public string? PaymentMethod { get; set; }
        public string? PaymentOrderDescription { get; set; }
        public string? PaymentOrderId { get; set; }
        public string? PaymentId { get; set; }
        public string? PaymentTransactionId { get; set; }
        public string? PaymentToken { get; set; }
        public string? VnPayResponseCode { get; set; }

    }
    public class DangkyTH03_View
    {
        public int? Id { get; set; } 
        public string? HovaDem { get; set; }
        public string? Ten { get; set; }
        public int? GioiTinh { get; set; }
        public string? NgaySinh { get; set; }
        public int? NoiSinh_Tinh { get; set; }
        public string? NoiSinh_Tinh_Ten { get; set; }
        public int? DanToc { get; set; }
        public string? DanToc_Ten { get; set; }
        public string? CCCD { get; set; }
        public string? CCCD_NgayCap { get; set; }
        public string CCCD_NoiCap { get; set; }
        public string? CCCD_NoiCap_Ten { get; set; }
        public string? DienThoai { get; set; }
        public string? DiaChi { get; set; }
        public string? Email { get; set; }
        public int? DKOnThi { get; set; }
        public double? LePhiThi { get; set; }
        public double? LePhiOn { get; set; }
        public string? DiaDiemThi { get; set; }
        public string? DiaDiemThi_Ten { get; set; }
        public string? DotThi { get; set; }
        public string? DotThi_Ten { get; set; }
        public int? Trangthai { get; set; }
        public string? MaSinhvien { get; set; }
        public string? KhoahocID { get; set; }
        public string? Khoahoc_Ten { get; set; }
        public string? KhoaID { get; set; }
        public string? Khoa_Ten { get; set; }
        public string? NganhID { get; set; }
        public string? Nganh_Ten { get; set; }
        public string? LopID { get; set; }
        public string? Lop_Ten { get; set; }
        public int? stt { get; set; }
        public bool DuDKThi { get; set; }
        public string? SoBD { get; set; }
        public string? PhongThi { get; set; }
        public string? CaThi { get; set; }
        public string? Taikhoan { get; set; }
        public string? Matkhau { get; set; }
        public string? SoPhach { get; set; }
        public double? DiemLT { get; set; }
        public double? DiemTH { get; set; }
        public string? Ketqua { get; set; }
        public string? SoChungChi { get; set; }
        public string? SoVaoSo { get; set; }
        public DateTime? NgayTao { get; set; }
        public DateTime? NgaySua { get; set; }
        public string? Ghichu { get; set; }
        public string? guid { get; set; }

        // Thong tin thanh toan
        public bool? PaymentSuccess { get; set; }
        public string? PaymentMethod { get; set; }
        public string? PaymentOrderDescription { get; set; }
        public string? PaymentOrderId { get; set; }
        public string? PaymentId { get; set; }
        public string? PaymentTransactionId { get; set; }
        public string? PaymentToken { get; set; }
        public string? VnPayResponseCode { get; set; }

    }

    //public class DiemthiImport
    //{        
    //    public string FileName { get; set; }
    //    public byte[] FileContent { get; set; }
    //}

    //public class Tin03ImportDiemResult
    //{
    //    public List<DangkyTH03> ImportedList { get; set; }
    //    public List<DangkyTH03> ErrorList { get; set; }
    //}
}
