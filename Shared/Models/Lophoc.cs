using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Flic.Shared.Models
{
    public class Lophoc
    {
        public int Id { get; set; }
        public string LoaiLop { get; set; }
        public string TenLop { get; set; }
        public string Mota { get; set; }
        public string? ChiTiet { get; set; }
        public string? ImagePath { get; set; }
        public int Hocphi { get; set; }
        public int Trangthai { get; set; }
        public bool? QRActive { get; set; }
        public bool? VNPAYActive { get; set; }
    }
}
