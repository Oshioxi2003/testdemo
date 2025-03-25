using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Flic.Shared.Models
{
    public class LoaiLophoc
    {
        [Key]
        public string Id { get; set; }
        public string TenLop { get; set; }
        public int Trangthai { get; set; }
        public string? guid { get; set; }
    }
}
