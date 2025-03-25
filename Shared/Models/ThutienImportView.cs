using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Flic.Shared.Models
{
    public class ThutienImportView
    {
        public string? LoaiKhoanthu { get; set; }
        public string? KyThanhtoan { get; set; }
        public string FileName { get; set; }
        public byte[] FileContent { get; set; }
    }
    public class ThutienImportResult
    {
        public List<ThuTienView> ImportedList { get; set; }
        public List<ThuTienView> ExistList { get; set; }
        public List<ThuTienView> ErrorList { get; set; }
    }
}
