using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Flic.Shared.Models.TaiChinh
{
    public class TAICHINH_DuTruKP
    {
        [Key]
        public int Id { get; set; } //mã dự trù
        public string? MaNhom { get; set; } // Tên mục chi
        public int? MaMucChi { get; set; } // Tên mục chi
        public string? TenMucChi { get; set; }
        public string DienGiai { get; set; } // Diễn giải
        public long SoTien { get; set; } // Số tiền
        public string MaDonVi { get; set; } // Mã đơn vị
        public int Nam {  get; set; }
        public DateTime? NgayTao { get; set; }
        public DateTime? NgaySua { get; set; }
    }
}
