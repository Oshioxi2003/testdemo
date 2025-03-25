using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Flic.Shared.Models
{
    public class StudentImportView
    {
        public string? KhoahocID { get; set; } 
        public string? KhoaID { get; set; }
        public string? NganhID { get; set; }
        public string? LopID { get; set; }
        public string FileName { get; set; }
        public byte[] FileContent { get; set; }
    }
}
