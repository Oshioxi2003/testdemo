using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Flic.Shared.Models
{
    public class Khoanthu
    {
        public int id { get; set; }
        public string MaLoaiKhoanThu { get; set; }        
        public string? KhoahocID { get; set; }
        public string? NganhID { get; set; }
        public string? KyThanhToan { get; set; }
        public double SoTien { get; set; }
    }
}
