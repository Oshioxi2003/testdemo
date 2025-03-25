using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Flic.Shared.Models
{
    public class DKHoc
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int Id { get; set; }
        public string HovaDem { get; set; }
        public string Ten { get; set; }
        public int? GioiTinh { get; set; }
        public string? CCCD { get; set; }
        public string? DienThoai { get; set; }
        public string? DiaChi { get; set; }
        public string? Email { get; set; }        
        
        public string? MaSinhvien { get; set; }
        public string? KhoahocID { get; set; }
        public string? KhoaID { get; set; }
        public string? NganhID { get; set; }
        public string? LopID { get; set; }        
        
        public int CourseId { get; set; }
        public int? Hocphi { get; set; }
        public int? DaThanhtoan { get; set; }
        public DateTime? NgayThanhtoan { get; set; }
        public string? TTGiaodich { get; set; }   
        

        public DateTime? NgayTao { get; set; }
        public DateTime? NgaySua { get; set; }
        public string? Ghichu { get; set; }
        public int Trangthai { get; set; }
        public string? guid { get; set; }
        ///
        public bool? PaymentSuccess { get; set; }
        public string? PaymentMethod { get; set; }
        public string? PaymentOrderDescription { get; set; }
        public string? PaymentOrderId { get; set; }
        public string? PaymentId { get; set; }
        public string? PaymentTransactionId { get; set; }
        public string? PaymentToken { get; set; }
        public string? VnPayResponseCode { get; set; }
        //
        
    }

    public class DKHocView
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int Id { get; set; }
        public string HovaDem { get; set; }
        public string Ten { get; set; }
        public int? GioiTinh { get; set; }
        public string? CCCD { get; set; }
        public string? DienThoai { get; set; }
        public string? DiaChi { get; set; }
        public string? Email { get; set; }

        public string? MaSinhvien { get; set; }
        public string? KhoahocID { get; set; }
        public string? KhoaID { get; set; }
        public string? NganhID { get; set; }
        public string? LopID { get; set; }
        public DateTime? NgayTao { get; set; }
        public DateTime? NgaySua { get; set; }
        public int CourseId { get; set; }
        public string CourseName { get; set; }
        public int? Hocphi { get; set; }
        public int? DaThanhtoan { get; set; }
        public DateTime? NgayThanhtoan { get; set; }
        public string? TTGiaodich { get; set; }
        public int Trangthai { get; set; }        
    }
    public class DKHocQueryResult
    {
        public List<DKHocView> list { get; set; }
        public string Message { get; set; }
    }
}
