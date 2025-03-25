using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Flic.Shared.Models
{
    public class ThuTien
    {
        public int? id { get; set; }
        public int? SinhVienID { get; set; }       
        public string LoaiKhoanthuID { get; set; }       
        public string? KyThanhToan { get; set; }
        public double? SoTien { get; set; }        
        public DateTime? NgayTao { get; set; }
        public DateTime? NgayThanhToan { get; set; } = null;
        public int? TrangThai { get; set; }
        public string? ThanhtoanReqId { get; set; } 
    }
    public class ThuTienView
    {
        public int? id { get; set; }
        public int? SinhVienID { get; set; }
        public string? MaSinhVien { get; set; }
        public string? HoDem { get; set; }
        public string? Ten { get; set; }
        public string? Ngaysinh { get; set; }
        public string? SoCCCD { get; set; }
        public string? LoaiKhoanthuID { get; set; }
        public string? KhoahocID { get; set; }
        public string? KhoaID { get; set; }
        public string? KhoaTen { get; set; }
        public string? NganhID { get; set; }
        public string? NganhTen { get; set; }
        public string? LopID { get; set; }
        public string? KyThanhToan { get; set; }
        public double? SoTien { get; set; }
        public DateTime? NgayTao { get; set; }
        public DateTime? NgayThanhToan { get; set; } = null;
        public int? TrangThai { get; set; }
        public string? ThanhtoanReqId { get; set; }
        public string? Ghichu { get; set; }
        public int? STT { get; set; }

    }
}
