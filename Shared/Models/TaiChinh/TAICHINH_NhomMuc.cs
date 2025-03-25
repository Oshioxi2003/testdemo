using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Flic.Shared.Models.TaiChinh
{
    public class TAICHINH_NhomMuc
    {
        [Key]
        public string MaNhom { get; set; } //mã nhóm
        public string TenNhom { get; set; } // Tên nhóm mục
    }
}
