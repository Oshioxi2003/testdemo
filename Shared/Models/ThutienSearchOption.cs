using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Flic.Shared.Models
{
    public class ThutienSearchOption
    {
        public string? LoaiKhoanthuID { get; set; }
        public string? KyThanhToan { get; set; }
        public string? KhoahocID { get; set; }
        public string? KhoaID { get; set; }
        public string? NganhID { get; set; }
        public string? LopID { get; set; }
        public string? KeyWord { get; set; }
        public int? Page { get; set; }
        public int? Pagesize { get; set; }
        public int? NumPage { get; set; }
        public List<ThuTienView>? Thutien_list { get; set; }
    }
}
