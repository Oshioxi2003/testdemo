using DocumentFormat.OpenXml.InkML;
using DocumentFormat.OpenXml.Office2016.Drawing.Command;
using Flic.Server.Data;
using Flic.Server.Interfaces;
using Flic.Shared;
using Flic.Shared.Models;
using Microsoft.EntityFrameworkCore;
using NPOI.SS.Formula.Functions;
using System.Runtime.CompilerServices;

namespace Flic.Server.Services
{
    public class DangkyTH03Service:IDangkyTH03
    {
        readonly ApplicationDbContext _dbContext;
        public DangkyTH03Service(ApplicationDbContext dbContext)
        {
            _dbContext = dbContext;
        }

        public int Add(DangkyTH03 item)
        {
            try
            {
                // Tim xem co bi trung so CCCD voi ma dot thi khong
                // Neu trung la sinh vien dang ky 2 lan thi tra ve gia tri 0

                var it = _dbContext.DangkyTH03s.Where(x=>x.CCCD== item.CCCD && x.DotThi == item.DotThi).FirstOrDefault();
                if (it != null)
                {
                    return 0;
                }
                item.NgayTao = DateTime.Now;
                _dbContext.DangkyTH03s.Add(item);
                _dbContext.SaveChanges();
                return 1;
            }
            catch
            {
                return -1;
            }
        }

        public bool Delete(int id)
        {
            try
            {
                DangkyTH03? item = _dbContext.DangkyTH03s.Find(id);
                if (item != null)
                {
                    _dbContext.DangkyTH03s.Remove(item);
                    _dbContext.SaveChanges();
                    return true;
                }
                else
                {
                    return false;
                }
            }
            catch
            {
                return false;
            }
        }

        public List<DangkyTH03_View> GetListView(string dotthi=null)
        {
            try
            {
                var _madotthi = dotthi.Split(';').ToList();
                var a = _dbContext.DangkyTH03s.Where(t => _madotthi.Contains(t.DotThi)).ToList();
                var _tinh = _dbContext.DMTinhs.ToList().Distinct().ToDictionary(x => x.Id, x => x.Name);
                var _khoahoc = _dbContext.Khoahocs.ToList().Distinct().ToDictionary(x => x.Id, x => x.Name);
                var _khoa = _dbContext.Khoas.ToList().Distinct().ToDictionary(x => x.Id, x => x.Name);
                var _nganh = _dbContext.Nganhs.ToList().Distinct().ToDictionary(x => x.Id, x => x.Name);
                var _lop = _dbContext.Lops.ToList().Distinct().ToDictionary(x => x.Id, x => x.Name);
                var _diemthi = _dbContext.Diemthis.ToList().Distinct().ToDictionary(x => x.Id, x => x.Name);
                var _dotthi = _dbContext.Dotthis.ToList().Distinct().ToDictionary(x => x.Id, x => x.Name);
                var _dantoc = _dbContext.DMDantocs.ToList().Distinct().ToDictionary(x => x.Id, x => x.Name);
                List<DangkyTH03_View> ls = new List<DangkyTH03_View>();
                int index = 1;
                foreach (var item in a)
                {
                    DangkyTH03_View rs = new DangkyTH03_View();
                    rs.Id = item.Id;
                    rs.HovaDem = item.HovaDem;
                    rs.Ten = item.Ten;
                    rs.GioiTinh = item.GioiTinh;
                    rs.NgaySinh = item.NgaySinh;
                    rs.NoiSinh_Tinh = item.NoiSinh_Tinh;

                    rs.DanToc = item.DanToc;
                    rs.CCCD = item.CCCD;
                    rs.CCCD_NgayCap = item.CCCD_NgayCap;
                    rs.CCCD_NoiCap = item.CCCD_NoiCap;
                    rs.DienThoai = item.DienThoai;
                    rs.DiaChi = item.DiaChi;
                    rs.Email = item.Email;
                    rs.DKOnThi = item.DKOnThi;
                    rs.LePhiOn = item.LePhiOn;
                    rs.LePhiThi = item.LePhiThi;
                    rs.DiaDiemThi = item.DiaDiemThi;
                    rs.DotThi = item.DotThi;
                    rs.Trangthai = item.Trangthai;
                    rs.MaSinhvien = item.MaSinhvien;
                    rs.KhoahocID = item.KhoahocID;
                    rs.KhoaID = item.KhoaID;
                    rs.NganhID = item.NganhID;
                    rs.LopID = item.LopID;
                    rs.DuDKThi = item.DuDKThi;
                    rs.PhongThi = item.PhongThi;
                    rs.SoBD = item.SoBD;
                    rs.Ghichu = item.Ghichu;
                    rs.Taikhoan = item.Taikhoan;
                    rs.Matkhau = item.Matkhau;
                    rs.DiemLT = item.DiemLT;
                    rs.DiemTH = item.DiemTH;
                    rs.Ketqua = item.Ketqua;
                    rs.SoChungChi = item.SoChungChi;
                    rs.SoVaoSo = item.SoVaoSo;

                    string str;
                    bool hasValue;
                    if (item.NoiSinh_Tinh != null)
                    {
                        hasValue = _tinh.TryGetValue(item.NoiSinh_Tinh, out str);
                        if (hasValue) rs.NoiSinh_Tinh_Ten = str;
                    }                  

                    if (item.DiaDiemThi != null)
                    {
                        hasValue = _diemthi.TryGetValue(item.DiaDiemThi, out str);
                        if (hasValue) rs.DiaDiemThi_Ten = str;
                    }

                    if (item.DotThi != null)
                    {
                        hasValue = _dotthi.TryGetValue(item.DotThi, out str);
                        if (hasValue) rs.DotThi_Ten = str;
                    }

                    if (item.KhoahocID != null)
                    {
                        hasValue = _khoahoc.TryGetValue(item.KhoahocID, out str);
                        if (hasValue) rs.Khoahoc_Ten = str;
                    }

                    if (item.KhoaID != null)
                    {
                        hasValue = _khoa.TryGetValue(item.KhoaID, out str);
                        if (hasValue) rs.Khoa_Ten = str;
                    }

                    if (item.NganhID != null)
                    {
                        hasValue = _nganh.TryGetValue(item.NganhID, out str);
                        if (hasValue) rs.Nganh_Ten = str;
                    }

                    if (item.LopID != null)
                    {
                        hasValue = _lop.TryGetValue(item.LopID, out str);
                        if (hasValue) rs.Lop_Ten = str;
                    }

                    if (item.DanToc != null)
                    {
                        hasValue = _dantoc.TryGetValue(item.DanToc, out str);
                        if (hasValue) rs.DanToc_Ten = str;
                    }
                    rs.stt = index;
                    index++;
                    ls.Add(rs);
                }
                return ls;
            }
            catch (Exception e)
            {

                Exception myexception = new Exception(e.Message);
                throw myexception;                
            }
        }
        public List<DangkyTH03> Get()
        {
            try
            {
                var a = _dbContext.DangkyTH03s.ToList();                
                return a;
            }
            catch (Exception e)
            {

                Exception myexception = new Exception(e.Message);
                throw myexception;
            }
        }

        public DangkyTH03 Get(int id)
        {
            try
            {
                DangkyTH03? item = _dbContext.DangkyTH03s.Find(id);
                if (item != null)
                {
                    return item;
                }
                else
                {
                    throw new ArgumentNullException();
                }
            }
            catch
            {
                throw new ArgumentNullException();
            }
        }
        
        
        public DangkyTH03_View GetView(int id)
        {
            try
            {
                DangkyTH03? item = _dbContext.DangkyTH03s.Find(id);
                var _tinh = _dbContext.DMTinhs.ToList().Distinct().ToDictionary(x => x.Id, x => x.Name);
                var _khoahoc = _dbContext.Khoahocs.ToList().Distinct().ToDictionary(x => x.Id, x => x.Name);
                var _khoa = _dbContext.Khoas.ToList().Distinct().ToDictionary(x => x.Id, x => x.Name);
                var _nganh = _dbContext.Nganhs.ToList().Distinct().ToDictionary(x => x.Id, x => x.Name);
                var _lop = _dbContext.Lops.ToList().Distinct().ToDictionary(x => x.Id, x => x.Name);
                var _diemthi = _dbContext.Diemthis.ToList().Distinct().ToDictionary(x => x.Id, x => x.Name);
                var _dotthi = _dbContext.Dotthis.ToList().Distinct().ToDictionary(x => x.Id, x => x.Name);
                var _dantoc = _dbContext.DMDantocs.ToList().Distinct().ToDictionary(x => x.Id, x => x.Name);

                if (item != null)
                {
                    DangkyTH03_View rs = new DangkyTH03_View();
                    rs.Id = item.Id;
                    rs.HovaDem = item.HovaDem;
                    rs.Ten = item.Ten;
                    rs.GioiTinh = item.GioiTinh;
                    rs.NgaySinh = item.NgaySinh;
                    rs.NoiSinh_Tinh = item.NoiSinh_Tinh;
                    
                    rs.DanToc = item.DanToc;
                    rs.CCCD = item.CCCD;
                    rs.CCCD_NgayCap = item.CCCD_NgayCap;
                    rs.CCCD_NoiCap = item.CCCD_NoiCap;
                    rs.DienThoai = item.DienThoai;
                    rs.DiaChi = item.DiaChi;
                    rs.Email = item.Email;
                    rs.DKOnThi = item.DKOnThi;
                    rs.LePhiOn = item.LePhiOn;
                    rs.LePhiThi = item.LePhiThi;
                    rs.DiaDiemThi = item.DiaDiemThi;
                    rs.DotThi = item.DotThi;
                    rs.Trangthai = item.Trangthai;
                    rs.MaSinhvien = item.MaSinhvien;
                    rs.KhoahocID = item.KhoahocID;
                    //rs.Khoahoc_Ten = "";
                    rs.KhoaID = item.KhoaID;
                    
                    //rs.Khoa_Ten = "";
                    rs.NganhID = item.NganhID;
                    rs.LopID = item.LopID;
                    rs.DuDKThi = item.DuDKThi;
                    rs.PhongThi = item.PhongThi;
                    rs.SoBD = item.SoBD;
                    rs.Ghichu = item.Ghichu;
                    rs.Taikhoan = item.Taikhoan;
                    rs.Matkhau = item.Matkhau;
                    rs.CaThi = item.CaThi;
                    rs.DiemLT = item.DiemLT;
                    rs.DiemTH = item.DiemTH;
                    rs.Ketqua = item.Ketqua;
                    string str;
                    bool hasValue;
                    if (item.NoiSinh_Tinh != null)
                    {
                        hasValue = _tinh.TryGetValue(item.NoiSinh_Tinh, out str);
                        if (hasValue) rs.NoiSinh_Tinh_Ten = str;
                    }                                      
                    
                    if (item.DiaDiemThi != null)
                    {
                        hasValue = _diemthi.TryGetValue(item.DiaDiemThi, out str);
                        if (hasValue) rs.DiaDiemThi_Ten = str;
                    }
                    
                    if (item.DotThi != null)
                    {
                        hasValue = _dotthi.TryGetValue(item.DotThi, out str);
                        if (hasValue) rs.DotThi_Ten = str;
                    }                    

                    if (item.KhoahocID != null)
                    {
                        hasValue = _khoahoc.TryGetValue(item.KhoahocID, out str);
                        if (hasValue) rs.Khoahoc_Ten = str;
                    }
                    
                    if (item.KhoaID!=null)
                    {
                        hasValue = _khoa.TryGetValue(item.KhoaID, out str);
                        if (hasValue) rs.Khoa_Ten = str;
                    }
                    
                    if (item.NganhID != null)
                    {
                        hasValue = _nganh.TryGetValue(item.NganhID, out str);
                        if (hasValue) rs.Nganh_Ten = str;
                    }
                    
                    if (item.LopID != null)
                    {
                        hasValue = _lop.TryGetValue(item.LopID, out str);
                        if (hasValue) rs.Lop_Ten = str;
                    }
                    
                    if (item.DanToc != null)
                    {
                        hasValue = _dantoc.TryGetValue(item.DanToc, out str);
                        if (hasValue) rs.DanToc_Ten = str;
                    }
                    rs.PaymentSuccess = item.PaymentSuccess;
                    rs.PaymentMethod = item.PaymentMethod;
                    rs.PaymentOrderDescription = item.PaymentOrderDescription;
                    rs.PaymentId = item.PaymentId;
                    rs.PaymentTransactionId = item.PaymentTransactionId;
                    rs.PaymentToken = item.PaymentToken;
                    rs.VnPayResponseCode = item.VnPayResponseCode;

                    return rs;
                }
                else
                {
                    throw new ArgumentNullException();
                }
            }
            catch (Exception ex)
            {
                throw new ArgumentNullException(ex.Message);
            }
        }
        
        public DangkyTH03 GetByCCCD(string cccd)
        {
            try
            {
                DangkyTH03? item = _dbContext.DangkyTH03s.Where(m=>m.CCCD.ToLower().Contains(cccd.ToLower())).FirstOrDefault();                
                return item;
            }
            catch
            {
                throw new ArgumentNullException();
            }
        }
        //
        public DangkyTH03 DangkyTH03Import(string sdb, string cccd, string madotthi)
        {
            try
            {
                DangkyTH03? item = _dbContext.DangkyTH03s
                    .Where(m=>m.DotThi!=null && m.DotThi.ToLower().Equals(madotthi.ToLower()))
                    .Where(m=>m.SoBD!=null && m.SoBD.ToLower().Equals(sdb.ToLower()))
                    .Where(m => m.CCCD.ToLower().Contains(cccd.ToLower())).FirstOrDefault();
                return item;
            }
            catch (Exception e)
            {
                throw new ArgumentNullException(e.Message);
            }
        }
        public DangkyTH03 DangkyTH03Import(string sdb, string madotthi)
        {
            try
            {
                DangkyTH03? item = _dbContext.DangkyTH03s
                    .Where(m => m.DotThi != null && m.DotThi.ToLower().Equals(madotthi.ToLower()))
                    .Where(m => m.SoBD != null && m.SoBD.ToLower().Equals(sdb.ToLower()))
                    .Where(m=>m.Lock!=null && !m.Lock)
                    .FirstOrDefault();
                    
                return item;
            }
            catch (Exception e)
            {
                throw new ArgumentNullException(e.Message);
            }
        }
        //
        public DangkyTH03 DangkyTH03FindPhach(string sp, string madotthi)
        {
            try
            {
                DangkyTH03? item = _dbContext.DangkyTH03s
                    .Where(m => m.DotThi != null && m.DotThi.ToLower().Equals(madotthi.ToLower()))
                    .Where(m => m.SoPhach != null && m.SoPhach.ToLower().Equals(sp.ToLower()))
                    .Where(m => m.Lock != null && !m.Lock)
                    .FirstOrDefault();

                return item;
            }
            catch (Exception e)
            {
                throw new ArgumentNullException(e.Message);
            }
        }
        //
        //
        public List<DangkyTH03> Search(DangkyTH03_View item)
        {
            try
            {
                var ls = _dbContext.DangkyTH03s.ToList();
                if (item.HovaDem != null && item.HovaDem != "") ls = ls.Where(m => m.HovaDem.ToLower().Contains(item.HovaDem.ToLower())).ToList();
                if (item.Ten != null && item.Ten != "") ls = ls.Where(m => m.Ten.ToLower().Contains(item.Ten.ToLower())).ToList();
                if (item.CCCD != null && item.CCCD != "") ls = ls.Where(m => m.CCCD.ToLower().Contains(item.CCCD.ToLower())).ToList();
                if (item.DotThi != null && item.DotThi != "") ls = ls.Where(m => m.DotThi.ToLower().Contains(item.DotThi.ToLower())).ToList();
                if (item.DiaDiemThi != null && item.DiaDiemThi != "") ls = ls.Where(m => m.DiaDiemThi.ToLower().Contains(item.DiaDiemThi.ToLower())).ToList();

                return ls;
            }
            catch (Exception e)
            {

                Exception myexception = new Exception(e.Message);
                throw myexception;
            }
        }
        public int LapDS(LapDSTinhoc item)
        {
            var list = _dbContext.DangkyTH03s.Where(m=>m.DotThi !=null && m.DotThi.Equals(item.MaDotthi)).Where(m=>m.DuDKThi!=null && m.DuDKThi == true).OrderBy(m=>m.Ten).ThenBy(m=>m.HovaDem).ThenBy(m=>m.Id).ToList();
            var Phongthi = item.PhongThi.Split(';');
            int Soluong = item.Soluong;
            string maTaikhoan = item.MaTaikhoan;
            int SBD = 0;
            int SoTS1Ca = item.Soluong * Phongthi.Length;
            int cathi = 1;
            int _phongthi = 0;
            if (list.Count == 0)
            {
                return 0;
            }
            try
            {
                foreach (var ts in list)
                {
                    ts.CaThi = "Ca " + cathi;
                    ts.PhongThi = Phongthi[_phongthi];
                    ts.SoBD = item.MaTaikhoan + (SBD + 1).ToString("D3");
                    ts.Matkhau = RandomPassword.CreateRandomPassword(0, 0, 6, 0);
                    SBD = SBD + 1;
                    if (SBD % Soluong == 0)
                    {
                        if (SBD % SoTS1Ca == 0)
                        {
                            cathi++;
                            _phongthi = 0;
                        }
                        else
                        {
                           _phongthi++;                         
                        }
                    }
                    try
                    {
                        _dbContext.Entry(ts).State = EntityState.Modified;
                        _dbContext.SaveChanges();
                    }
                    catch (Exception e)
                    {
                        throw e;
                    }

                }
                return 1;
            }
            catch (Exception e)
            {
                throw e;
            }
            return 0;
        }

        public List<DangkyTH03_View> GetDSPhongthi(string p)
        {            
            try
            {
                var _madotthi = p.Split(';').ToList();
               
                var list = _dbContext.DangkyTH03s.Where(m => m.DotThi != null && _madotthi.Contains(m.DotThi)).Where(m => m.DuDKThi != null && m.DuDKThi == true).OrderBy(m => m.Ten).ThenBy(m => m.HovaDem).ThenBy(m => m.Id).ToList();
                var _tinh = _dbContext.DMTinhs.ToList().Distinct().ToDictionary(x => x.Id, x => x.Name);
                var _khoahoc = _dbContext.Khoahocs.ToList().Distinct().ToDictionary(x => x.Id, x => x.Name);
                var _khoa = _dbContext.Khoas.ToList().Distinct().ToDictionary(x => x.Id, x => x.Name);
                var _nganh = _dbContext.Nganhs.ToList().Distinct().ToDictionary(x => x.Id, x => x.Name);
                var _lop = _dbContext.Lops.ToList().Distinct().ToDictionary(x => x.Id, x => x.Name);
                var _diemthi = _dbContext.Diemthis.ToList().Distinct().ToDictionary(x => x.Id, x => x.Name);
                var _dotthi = _dbContext.Dotthis.ToList().Distinct().ToDictionary(x => x.Id, x => x.Name);
                var _dantoc = _dbContext.DMDantocs.ToList().Distinct().ToDictionary(x => x.Id, x => x.Name);
                List<DangkyTH03_View> ls = new List<DangkyTH03_View>();
                int index = 1;
                foreach (var item in list)
                {
                    DangkyTH03_View rs = new DangkyTH03_View();
                    rs.Id = item.Id;
                    rs.HovaDem = item.HovaDem;
                    rs.Ten = item.Ten;
                    rs.GioiTinh = item.GioiTinh;
                    rs.NgaySinh = item.NgaySinh;
                    rs.NoiSinh_Tinh = item.NoiSinh_Tinh;

                    rs.DanToc = item.DanToc;
                    rs.CCCD = item.CCCD;
                    rs.CCCD_NgayCap = item.CCCD_NgayCap;
                    rs.CCCD_NoiCap = item.CCCD_NoiCap;
                    rs.DienThoai = item.DienThoai;
                    rs.DiaChi = item.DiaChi;
                    rs.Email = item.Email;
                    rs.DKOnThi = item.DKOnThi;
                    rs.LePhiOn = item.LePhiOn;
                    rs.LePhiThi = item.LePhiThi;
                    rs.DiaDiemThi = item.DiaDiemThi;
                    rs.DotThi = item.DotThi;
                    rs.Trangthai = item.Trangthai;
                    rs.MaSinhvien = item.MaSinhvien;
                    rs.KhoahocID = item.KhoahocID;
                    rs.KhoaID = item.KhoaID;
                    rs.NganhID = item.NganhID;
                    rs.LopID = item.LopID;
                    rs.DuDKThi = item.DuDKThi;
                    rs.PhongThi = item.PhongThi;
                    rs.SoBD = item.SoBD;
                    rs.Ghichu = item.Ghichu;
                    rs.Taikhoan = item.Taikhoan;
                    rs.Matkhau = item.Matkhau;
                    rs.CaThi = item.CaThi;
                    rs.SoPhach = item.SoPhach;
                    rs.NgaySua = item.NgaySua;
                    rs.NgayTao= item.NgayTao;
                    rs.DiemLT = item.DiemLT;
                    rs.DiemTH = item.DiemTH;
                    rs.Ketqua = item.Ketqua;
                    rs.SoChungChi = item.SoChungChi;
                    rs.SoVaoSo = item.SoVaoSo;

                    string str;
                    bool hasValue;
                    if (item.NoiSinh_Tinh != null)
                    {
                        hasValue = _tinh.TryGetValue(item.NoiSinh_Tinh, out str);
                        if (hasValue) rs.NoiSinh_Tinh_Ten = str;
                    }

                    if (item.DiaDiemThi != null)
                    {
                        hasValue = _diemthi.TryGetValue(item.DiaDiemThi, out str);
                        if (hasValue) rs.DiaDiemThi_Ten = str;
                    }

                    if (item.DotThi != null)
                    {
                        hasValue = _dotthi.TryGetValue(item.DotThi, out str);
                        if (hasValue) rs.DotThi_Ten = str;
                    }

                    if (item.KhoahocID != null)
                    {
                        hasValue = _khoahoc.TryGetValue(item.KhoahocID, out str);
                        if (hasValue) rs.Khoahoc_Ten = str;
                    }

                    if (item.KhoaID != null)
                    {
                        hasValue = _khoa.TryGetValue(item.KhoaID, out str);
                        if (hasValue) rs.Khoa_Ten = str;
                    }

                    if (item.NganhID != null)
                    {
                        hasValue = _nganh.TryGetValue(item.NganhID, out str);
                        if (hasValue) rs.Nganh_Ten = str;
                    }

                    if (item.LopID != null)
                    {
                        hasValue = _lop.TryGetValue(item.LopID, out str);
                        if (hasValue) rs.Lop_Ten = str;
                    }

                    if (item.DanToc != null)
                    {
                        hasValue = _dantoc.TryGetValue(item.DanToc, out str);
                        if (hasValue) rs.DanToc_Ten = str;
                    }
                    rs.stt = index;
                    index++;
                    ls.Add(rs);
                }
                return ls;
            }
            catch (Exception e)
            {

                Exception myexception = new Exception(e.Message);
                throw myexception;
            }
        }

        public List<DangkyTH03_View> GetDSDangky(string p)
        {
            try
            {
                var _madotthi = p.Split(';').ToList();
               
                var list = _dbContext.DangkyTH03s.Where(m => m.DotThi != null && _madotthi.Contains(m.DotThi)).OrderBy(m => m.Ten).ThenBy(m => m.HovaDem).ThenBy(m => m.Id).ToList();
                var _tinh = _dbContext.DMTinhs.ToList().Distinct().ToDictionary(x => x.Id, x => x.Name);
                var _khoahoc = _dbContext.Khoahocs.ToList().Distinct().ToDictionary(x => x.Id, x => x.Name);
                var _khoa = _dbContext.Khoas.ToList().Distinct().ToDictionary(x => x.Id, x => x.Name);
                var _nganh = _dbContext.Nganhs.ToList().Distinct().ToDictionary(x => x.Id, x => x.Name);
                var _lop = _dbContext.Lops.ToList().Distinct().ToDictionary(x => x.Id, x => x.Name);
                var _diemthi = _dbContext.Diemthis.ToList().Distinct().ToDictionary(x => x.Id, x => x.Name);
                var _dotthi = _dbContext.Dotthis.ToList().Distinct().ToDictionary(x => x.Id, x => x.Name);
                var _dantoc = _dbContext.DMDantocs.ToList().Distinct().ToDictionary(x => x.Id, x => x.Name);
                List<DangkyTH03_View> ls = new List<DangkyTH03_View>();
                int index = 1;
                foreach (var item in list)
                {
                    DangkyTH03_View rs = new DangkyTH03_View();
                    rs.Id = item.Id;
                    rs.HovaDem = item.HovaDem;
                    rs.Ten = item.Ten;
                    rs.GioiTinh = item.GioiTinh;
                    rs.NgaySinh = item.NgaySinh;
                    rs.NoiSinh_Tinh = item.NoiSinh_Tinh;

                    rs.DanToc = item.DanToc;
                    rs.CCCD = item.CCCD;
                    rs.CCCD_NgayCap = item.CCCD_NgayCap;
                    rs.CCCD_NoiCap = item.CCCD_NoiCap;
                    rs.DienThoai = item.DienThoai;
                    rs.DiaChi = item.DiaChi;
                    rs.Email = item.Email;
                    rs.DKOnThi = item.DKOnThi;
                    rs.LePhiOn = item.LePhiOn;
                    rs.LePhiThi = item.LePhiThi;
                    rs.DiaDiemThi = item.DiaDiemThi;
                    rs.DotThi = item.DotThi;
                    rs.Trangthai = item.Trangthai;
                    rs.MaSinhvien = item.MaSinhvien;
                    rs.KhoahocID = item.KhoahocID;
                    rs.KhoaID = item.KhoaID;
                    rs.NganhID = item.NganhID;
                    rs.LopID = item.LopID;
                    rs.DuDKThi = item.DuDKThi;
                    rs.PhongThi = item.PhongThi;
                    rs.SoBD = item.SoBD;
                    rs.Ghichu = item.Ghichu;
                    rs.Taikhoan = item.Taikhoan;
                    rs.Matkhau = item.Matkhau;
                    rs.CaThi = item.CaThi;
                    rs.NgayTao = item.NgayTao;
                    rs.NgaySua = item.NgaySua;
                    rs.DiemLT = item.DiemLT;
                    rs.DiemTH = item.DiemTH;
                    rs.Ketqua = item.Ketqua;
                    string str;
                    bool hasValue;
                    if (item.NoiSinh_Tinh != null)
                    {
                        hasValue = _tinh.TryGetValue(item.NoiSinh_Tinh, out str);
                        if (hasValue) rs.NoiSinh_Tinh_Ten = str;
                    }

                    if (item.DiaDiemThi != null)
                    {
                        hasValue = _diemthi.TryGetValue(item.DiaDiemThi, out str);
                        if (hasValue) rs.DiaDiemThi_Ten = str;
                    }

                    if (item.DotThi != null)
                    {
                        hasValue = _dotthi.TryGetValue(item.DotThi, out str);
                        if (hasValue) rs.DotThi_Ten = str;
                    }

                    if (item.KhoahocID != null)
                    {
                        hasValue = _khoahoc.TryGetValue(item.KhoahocID, out str);
                        if (hasValue) rs.Khoahoc_Ten = str;
                    }

                    if (item.KhoaID != null)
                    {
                        hasValue = _khoa.TryGetValue(item.KhoaID, out str);
                        if (hasValue) rs.Khoa_Ten = str;
                    }

                    if (item.NganhID != null)
                    {
                        hasValue = _nganh.TryGetValue(item.NganhID, out str);
                        if (hasValue) rs.Nganh_Ten = str;
                    }

                    if (item.LopID != null)
                    {
                        hasValue = _lop.TryGetValue(item.LopID, out str);
                        if (hasValue) rs.Lop_Ten = str;
                    }

                    if (item.DanToc != null)
                    {
                        hasValue = _dantoc.TryGetValue(item.DanToc, out str);
                        if (hasValue) rs.DanToc_Ten = str;
                    }
                    rs.stt = index;
                    index++;
                    ls.Add(rs);
                }
                return ls;
            }
            catch (Exception e)
            {

                Exception myexception = new Exception(e.Message);
                throw myexception;
            }
        }
        //
        public List<DangkyTH03_View> GetDSDuDK(string p)
        {
            try
            {
                var _madotthi = p.Split(';').ToList();

                var list = _dbContext.DangkyTH03s.Where(m => m.DotThi != null && _madotthi.Contains(m.DotThi))
                    .Where(m=>m.DuDKThi !=null && m.DuDKThi)
                    .OrderBy(m => m.Ten).ThenBy(m => m.HovaDem).ThenBy(m => m.Id).ToList();
                var _tinh = _dbContext.DMTinhs.ToList().Distinct().ToDictionary(x => x.Id, x => x.Name);
                var _khoahoc = _dbContext.Khoahocs.ToList().Distinct().ToDictionary(x => x.Id, x => x.Name);
                var _khoa = _dbContext.Khoas.ToList().Distinct().ToDictionary(x => x.Id, x => x.Name);
                var _nganh = _dbContext.Nganhs.ToList().Distinct().ToDictionary(x => x.Id, x => x.Name);
                var _lop = _dbContext.Lops.ToList().Distinct().ToDictionary(x => x.Id, x => x.Name);
                var _diemthi = _dbContext.Diemthis.ToList().Distinct().ToDictionary(x => x.Id, x => x.Name);
                var _dotthi = _dbContext.Dotthis.ToList().Distinct().ToDictionary(x => x.Id, x => x.Name);
                var _dantoc = _dbContext.DMDantocs.ToList().Distinct().ToDictionary(x => x.Id, x => x.Name);
                List<DangkyTH03_View> ls = new List<DangkyTH03_View>();
                int index = 1;
                foreach (var item in list)
                {
                    DangkyTH03_View rs = new DangkyTH03_View();
                    rs.Id = item.Id;
                    rs.HovaDem = item.HovaDem;
                    rs.Ten = item.Ten;
                    rs.GioiTinh = item.GioiTinh;
                    rs.NgaySinh = item.NgaySinh;
                    rs.NoiSinh_Tinh = item.NoiSinh_Tinh;

                    rs.DanToc = item.DanToc;
                    rs.CCCD = item.CCCD;
                    rs.CCCD_NgayCap = item.CCCD_NgayCap;
                    rs.CCCD_NoiCap = item.CCCD_NoiCap;
                    rs.DienThoai = item.DienThoai;
                    rs.DiaChi = item.DiaChi;
                    rs.Email = item.Email;
                    rs.DKOnThi = item.DKOnThi;
                    rs.LePhiOn = item.LePhiOn;
                    rs.LePhiThi = item.LePhiThi;
                    rs.DiaDiemThi = item.DiaDiemThi;
                    rs.DotThi = item.DotThi;
                    rs.Trangthai = item.Trangthai;
                    rs.MaSinhvien = item.MaSinhvien;
                    rs.KhoahocID = item.KhoahocID;
                    rs.KhoaID = item.KhoaID;
                    rs.NganhID = item.NganhID;
                    rs.LopID = item.LopID;
                    rs.DuDKThi = item.DuDKThi;
                    rs.PhongThi = item.PhongThi;
                    rs.SoBD = item.SoBD;
                    rs.Ghichu = item.Ghichu;
                    rs.Taikhoan = item.Taikhoan;
                    rs.Matkhau = item.Matkhau;
                    rs.CaThi = item.CaThi;
                    rs.NgayTao = item.NgayTao;
                    rs.NgaySua = item.NgaySua;
                    rs.DiemLT = item.DiemLT;
                    rs.DiemTH = item.DiemTH;
                    rs.Ketqua = item.Ketqua;
                    string str;
                    bool hasValue;
                    if (item.NoiSinh_Tinh != null)
                    {
                        hasValue = _tinh.TryGetValue(item.NoiSinh_Tinh, out str);
                        if (hasValue) rs.NoiSinh_Tinh_Ten = str;
                    }

                    if (item.DiaDiemThi != null)
                    {
                        hasValue = _diemthi.TryGetValue(item.DiaDiemThi, out str);
                        if (hasValue) rs.DiaDiemThi_Ten = str;
                    }

                    if (item.DotThi != null)
                    {
                        hasValue = _dotthi.TryGetValue(item.DotThi, out str);
                        if (hasValue) rs.DotThi_Ten = str;
                    }

                    if (item.KhoahocID != null)
                    {
                        hasValue = _khoahoc.TryGetValue(item.KhoahocID, out str);
                        if (hasValue) rs.Khoahoc_Ten = str;
                    }

                    if (item.KhoaID != null)
                    {
                        hasValue = _khoa.TryGetValue(item.KhoaID, out str);
                        if (hasValue) rs.Khoa_Ten = str;
                    }

                    if (item.NganhID != null)
                    {
                        hasValue = _nganh.TryGetValue(item.NganhID, out str);
                        if (hasValue) rs.Nganh_Ten = str;
                    }

                    if (item.LopID != null)
                    {
                        hasValue = _lop.TryGetValue(item.LopID, out str);
                        if (hasValue) rs.Lop_Ten = str;
                    }

                    if (item.DanToc != null)
                    {
                        hasValue = _dantoc.TryGetValue(item.DanToc, out str);
                        if (hasValue) rs.DanToc_Ten = str;
                    }
                    rs.stt = index;
                    index++;
                    ls.Add(rs);
                }
                return ls;
            }
            catch (Exception e)
            {

                Exception myexception = new Exception(e.Message);
                throw myexception;
            }
        }
        //
        public List<DangkyTH03_View> GetKetqua(string p)
        {
            try
            {
                var _madotthi = p;
                var list = _dbContext.DangkyTH03s
                    .Where(m => m.DotThi != null && _madotthi.Contains(m.DotThi))
                    .Where(m=>m.DuDKThi!=null && m.DuDKThi)                    
                    .OrderBy(m => m.SoBD)
                    .ToList();
                var _dantoc = _dbContext.DMDantocs.ToList().Distinct().ToDictionary(x => x.Id, x => x.Name);
                var _tinh = _dbContext.DMTinhs.ToList().Distinct().ToDictionary(x => x.Id, x => x.Name);
                List<DangkyTH03_View> ls = new List<DangkyTH03_View>();
                int index = 1;
                foreach (var item in list)
                {
                    DangkyTH03_View rs = new DangkyTH03_View();
                    rs.Id = item.Id;
                    rs.HovaDem = item.HovaDem;
                    rs.Ten = item.Ten;
                    rs.GioiTinh = item.GioiTinh;
                    rs.NgaySinh = item.NgaySinh;
                    rs.NoiSinh_Tinh = item.NoiSinh_Tinh;

                    rs.DanToc = item.DanToc;
                    rs.Trangthai = item.Trangthai;
                    rs.SoBD = item.SoBD;
                    rs.Ghichu = item.Ghichu;
                    rs.DiemLT = item.DiemLT;
                    rs.DiemTH = item.DiemTH;
                    rs.Ketqua = item.Ketqua;
                    rs.LopID = item.LopID;
                    rs.CCCD = item.CCCD;
                    string str;
                    bool hasValue;
                    if (item.NoiSinh_Tinh != null)
                    {
                        hasValue = _tinh.TryGetValue(item.NoiSinh_Tinh, out str);
                        if (hasValue) rs.NoiSinh_Tinh_Ten = str;
                    }
                    if (item.DanToc != null)
                    {
                        hasValue = _dantoc.TryGetValue(item.DanToc, out str);
                        if (hasValue) rs.DanToc_Ten = str;
                    }
                    rs.stt = index;
                    index++;
                    ls.Add(rs);
                }
                return ls;
            }
            catch (Exception e)
            {

                Exception myexception = new Exception(e.Message);
                throw myexception;
            }
        }
        //        
        public List<DangkyTH03_View> GetSocapCC(string p)
        {
            try
            {
                var _madotthi = p;                
                var list = _dbContext.DangkyTH03s
                    .Where(m => m.DotThi != null && _madotthi.Contains(m.DotThi))
                    .Where(m => m.DiemLT != null && m.DiemLT >=5)
                    .Where(m => m.DiemTH != null && m.DiemTH >= 5)
                    .OrderBy(m => m.SoBD)
                    .ToList();                
                var _dantoc = _dbContext.DMDantocs.ToList().Distinct().ToDictionary(x => x.Id, x => x.Name);
                var _tinh = _dbContext.DMTinhs.ToList().Distinct().ToDictionary(x => x.Id, x => x.Name);
                List<DangkyTH03_View> ls = new List<DangkyTH03_View>();
                int index = 1;
                foreach (var item in list)
                {
                    DangkyTH03_View rs = new DangkyTH03_View();
                    rs.Id = item.Id;
                    rs.HovaDem = item.HovaDem;
                    rs.Ten = item.Ten;
                    rs.GioiTinh = item.GioiTinh;
                    rs.NgaySinh = item.NgaySinh;
                    rs.NoiSinh_Tinh = item.NoiSinh_Tinh;

                    rs.DanToc = item.DanToc;                    
                    rs.Trangthai = item.Trangthai;                    
                    rs.SoBD = item.SoBD;
                    rs.Ghichu = item.Ghichu;                    
                    rs.DiemLT = item.DiemLT;
                    rs.DiemTH = item.DiemTH;
                    rs.Ketqua = item.Ketqua;
                    rs.LopID = item.LopID;
                    rs.CCCD = item.CCCD;
                    string str;
                    bool hasValue;
                    if (item.NoiSinh_Tinh != null)
                    {
                        hasValue = _tinh.TryGetValue(item.NoiSinh_Tinh, out str);
                        if (hasValue) rs.NoiSinh_Tinh_Ten = str;
                    }
                    if (item.DanToc != null)
                    {
                        hasValue = _dantoc.TryGetValue(item.DanToc, out str);
                        if (hasValue) rs.DanToc_Ten = str;
                    }
                    rs.stt = index;
                    index++;
                    ls.Add(rs);
                }
                return ls;
            }
            catch (Exception e)
            {

                Exception myexception = new Exception(e.Message);
                throw myexception;
            }
        }

        public bool Update(DangkyTH03 item)
        {
            try
            {
                item.NgaySua = DateTime.Now;
                _dbContext.Entry(item).State = EntityState.Modified;
                _dbContext.SaveChanges();
                return true;
            }
            catch
            {
                return false;
            }
        }

        public bool UpdateDiemthi(DangkyTH03 item)
        {
            try
            {
                var u = _dbContext.DangkyTH03s
                    .Where(x=>x.SoBD !=null && x.SoBD.Equals(item.SoBD))
                    .Where(x => x.CCCD != null && x.CCCD.Equals(item.CCCD))
                    .Where(x => x.HovaDem != null && x.HovaDem.Equals(item.HovaDem))
                    .Where(x => x.Ten != null && x.Ten.Equals(item.Ten))
                    .Where(x => x.NgaySinh != null && x.NgaySinh.Equals(item.NgaySinh))
                    .Where(x => x.DotThi != null && x.DotThi.Equals(item.DotThi))
                    .ToList();
                if (u != null && u.Count == 1)
                {
                    u[0].DiemLT = item.DiemLT;
                    u[0].DiemTH = item.DiemTH;
                    u[0].NgaySua = DateTime.Now;

                    _dbContext.Entry(u[0]).State = EntityState.Modified;
                    _dbContext.SaveChanges();
                    return true;
                }                
                return false;
            }
            catch
            {
                return false;
            }
        }

        public bool ChangeDuDKState(ChangeDuDKState it)
        {
            try
            {
                DangkyTH03 item = _dbContext.DangkyTH03s.Find(it.id);
                if (item != null)
                {
                    item.DuDKThi = !item.DuDKThi; //it.value;
                    _dbContext.Entry(item).State = EntityState.Modified;
                    _dbContext.SaveChanges();
                    return true;
                }
                return false;
            }
            catch
            {
                return false;
            }
        }
    }
}

