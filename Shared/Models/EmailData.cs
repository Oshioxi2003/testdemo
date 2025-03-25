using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Flic.Shared.Models
{
    public class EmailData
    {
        public string EmailToId { get; set; }
        public string EmailToName { get; set; }
        public string EmailSubject { get; set; }
        public string EmailBody { get; set; }
    }
}
