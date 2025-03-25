using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Flic.Shared.Models
{
    public class StudentSearchOption
    {
        public string? KhoahocID { get; set; }
        public string? KhoaID { get; set; }
        public string? NganhID { get; set; }
        public string? LopID { get; set; }
        public string? KeyWord { get; set; }
        public string?Trangthai { get; set; }
        public int? Page { get; set; }
        public int? Pagesize { get; set; }
        public int? NumPage { get; set; }
        public List<Student>? student_list { get; set; }
    }
}
