using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Flic.Shared.Models
{
    public class Feed
    {
        public string PubDate { get; set; }
    }

    public class DateWiseCount
    {
        public string PubDate { get; set; }
        public double Count { get; set; }
    }
}
