using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Flic.Shared.Models
{
    public class Tinhoc03ImportResult
    {
        public List<DangkyTH03> ImportedList { get; set; }
        public List<DangkyTH03> ExistList { get; set; }
        public List<DangkyTH03> ErrorList { get; set; }
    }
}
