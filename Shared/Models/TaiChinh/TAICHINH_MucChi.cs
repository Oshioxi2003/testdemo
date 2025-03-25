using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Flic.Shared.Models.TaiChinh
{
    public class TAICHINH_MucChi
    {
        [Key]
        public int Id { get; set; } //mã mục chi
        public string TenMuc { get; set; } // Tên mục chi
        public string NhomMuc { get; set; } // Nhóm mục
        public int DoiTuong { get; set; } // Nhóm đối tương xxx : Khoa Phòng Chung
        public int MaTongHop { get; set; } // Sử dụng để Tổng hợp
    }
}
