using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Flic.Shared.Models
{
    public class StudentStatistic
    {
        public string? KhoahocID { get; set; }
        public string? KhoaID { get; set; }
        public string? NganhID { get; set; }
        public string? LopID { get; set; }
        public int? NumStudent { get; set; }
    }
    public class DashboardResult
    {   
        public List<StudentStatistic>? student_stats { get; set; }
        public List<StudentStatistic>? fees_stats { get; set; }
    }
}
