using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Flic.Shared.Models
{
    public class LoaiKhoanthu
    {
        [Key]        
        public string MaLoaiKhoanThu { get; set; }
        public string MoTa { get; set; }
    }
}
