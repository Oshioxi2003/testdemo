using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Flic.Shared.Models
{
    public class SinhvienPhong
    {
        [Key]
        public int Id { get; set; }
        public string PhongId { get; set; }
        public int SinhvienId { get; set; }
        public int Trangthai { get; set; }
    }
    public class SinhvienPhongView:SinhvienPhong
    {        
        public string PhongTen { get; set; }
        public string SinhvienMSV { get; set; }
        public string SinhvienHoDem { get; set; }
        public string SinhvienTen { get; set; }
        public string SinhvienHoTen { get; set; }
        public string SinhvienLop { get; set; }
        
    }
}
