using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Flic.Shared.Models
{
    public class Student
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int id { get; set; }
        [Required]
        public string? MaSV { get; set; }
        public string? HoDem { get; set; }
        public string? Ten { get; set; }
        public string? Ngaysinh { get; set; }
        public string? KhoahocID { get; set; }
        public string? KhoaID { get; set; }
        public string? NganhID { get; set; }
        public string? LopID { get; set; }
        public string? Email { get; set; }
        public string? DienThoai { get; set; }
        public string? CCCD { get; set; }
        public string? SoNH { get; set; }
        public string? SoTK { get; set; }
        public string? Doituong { get; set; }
        public string? Trangthai { get; set; }

    }
   
}
