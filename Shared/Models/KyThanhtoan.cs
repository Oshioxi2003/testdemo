using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Flic.Shared.Models
{
    public class KyThanhtoan
    {
        [Key]
        public string Id { get; set; }
        public string? LoaiKhoanthu { get; set; }
        public string? Name { get; set; }
        public int? Trangthai { get; set; }
    }
}
