using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Flic.Shared.Models
{
    public class StudentImportResult
    {
        public List<Student> ImportedList { get; set; }
        public List<Student> ExistList { get; set; }
        public List<Student> ErrorList { get; set; }
    }
}
