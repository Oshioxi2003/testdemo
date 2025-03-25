using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Flic.Shared.Models
{
    public static class TemplateGenerator
    {
        public static string GetHTMLString(List<DangkyTH03> employees)
        {
            //var employees = DataStorage.GetAllEmployess();
            var sb = new StringBuilder();
            sb.Append(@"
                        <html>
                            <head>
                            </head>
                            <body>
                                <div class='header'><h1>This is the generated PDF report!!!</h1></div>
                                <table align='center'>
                                    <tr>
                                        <th>Name</th>
                                        <th>LastName</th>
                                        <th>Age</th>
                                        <th>Gender</th>
                                    </tr>");
            foreach (var emp in employees)
            {
                sb.AppendFormat(@"<tr>
                                    <td>{0}</td>
                                    <td>{1}</td>
                                    <td>{2}</td>
                                    <td>{3}</td>
                                  </tr>", emp.HovaDem, emp.Ten, emp.NgaySinh, emp.MaSinhvien);
            }
            sb.Append(@"
                                </table>
                            </body>
                        </html>");
            return sb.ToString();
        }
        public static string CreatePhieuDK(DangkyTH03_View item, string template)
        {
            //var employees = DataStorage.GetAllEmployess();
            var sb = new StringBuilder();
            template = template.Replace("{HO_TEN}",item.HovaDem.ToUpper() + " " + item.Ten.ToUpper());
            if (item.GioiTinh==0)
            {
                template = template.Replace("{GIOI_TINH}", "Nữ");
            }
            else
            {
                template = template.Replace("{GIOI_TINH}", "Nam");
            }
            
            template = template.Replace("{NGAY_SINH}", item.NgaySinh);
            template = template.Replace("{NOI_SINH}", item.NoiSinh_Tinh_Ten);
            template = template.Replace("{DAN_TOC}", item.DanToc_Ten);
            template = template.Replace("{SO_CCCD}", item.CCCD);
            template = template.Replace("{NGAY_CAP}", item.CCCD_NgayCap);
            template = template.Replace("{NOI_CAP}", item.CCCD_NoiCap);
            template = template.Replace("{DIEN_THOAI}", item.DienThoai);
            template = template.Replace("{EMAIL}", item.Email);
            template = template.Replace("{DIA_CHI}", item.DiaChi);
                        
            template = template.Replace("{MA_SV}", item.MaSinhvien);

            template = template.Replace("{NGAY_THI}", item.DotThi_Ten);
            template = template.Replace("{DIEM_THI}", item.DiaDiemThi_Ten);

            template = template.Replace("{KHOA_HOC}", item.Khoahoc_Ten);
            template = template.Replace("{NGANH}", item.Nganh_Ten);
            template = template.Replace("{LOP}", item.Lop_Ten);
            template = template.Replace("{NGUOI_THI}", item.HovaDem + " " + item.Ten);

            sb.Append(template);
            return sb.ToString();
        }

        public static string CreateTheDuthi(DangkyTH03_View item, string template)
        {
            //var employees = DataStorage.GetAllEmployess();
            var sb = new StringBuilder();
            template = template.Replace("{HO_TEN}", item.HovaDem.ToUpper() + " " + item.Ten.ToUpper());
            if (item.GioiTinh == 0)
            {
                template = template.Replace("{GIOI_TINH}", "Nữ");
            }
            else
            {
                template = template.Replace("{GIOI_TINH}", "Nam");
            }

            template = template.Replace("{NGAY_SINH}", item.NgaySinh);
            template = template.Replace("{NOI_SINH}", item.NoiSinh_Tinh_Ten);
            template = template.Replace("{DAN_TOC}", item.DanToc_Ten);
            template = template.Replace("{SO_CCCD}", item.CCCD);
            template = template.Replace("{NGAY_CAP}", item.CCCD_NgayCap);
            template = template.Replace("{NOI_CAP}", item.CCCD_NoiCap);
            template = template.Replace("{DIEN_THOAI}", item.DienThoai);
            template = template.Replace("{EMAIL}", item.Email);
            template = template.Replace("{DIA_CHI}", item.DiaChi);

            template = template.Replace("{SO_BD}", item.SoBD);
            template = template.Replace("{PHONG_THI}", item.PhongThi);
            template = template.Replace("{CA_THI}", item.CaThi);
            template = template.Replace("{DIA_DIEM_THI}", item.DiaDiemThi_Ten);


            template = template.Replace("{NGAY_THI}", item.DotThi_Ten);
            template = template.Replace("{DIEM_THI}", item.DiaDiemThi_Ten);

            template = template.Replace("{KHOA_HOC}", item.Khoahoc_Ten);
            template = template.Replace("{NGANH}", item.Nganh_Ten);
            template = template.Replace("{LOP}", item.Lop_Ten);
            template = template.Replace("{NGUOI_THI}", item.HovaDem + " " + item.Ten);

            sb.Append(template);
            return sb.ToString();
        }
    }
}
