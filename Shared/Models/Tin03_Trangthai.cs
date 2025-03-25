using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Flic.Shared.Models
{
    public class Tin03_Trangthai
    {
        [Key]
        public int Id { get; set; }
        public string Name { get; set; }
    }
}
