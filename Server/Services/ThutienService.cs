using Flic.Server.Interfaces;
using Flic.Shared.Models;
using Flic.Server.Data;
using Microsoft.EntityFrameworkCore;

namespace Flic.Server.Services
{
    public class ThutienService:IThutien
    {
        readonly ApplicationDbContext _dbContext;
        public ThutienService(ApplicationDbContext dbContext)
        {
            _dbContext = dbContext;
        }

        public bool Add(ThuTien item)
        {
            try
            {
                _dbContext.ThuTiens.Add(item);
                _dbContext.SaveChanges();
                return true;
            }
            catch
            {
                return false;
            }
        }

        public bool Delete(int id)
        {
            try
            {
                ThuTien? item = _dbContext.ThuTiens.Find(id);
                if (item != null && item.TrangThai  == 0) // Chi xoa nhung ban ghi chua thanh toan
                {
                    _dbContext.ThuTiens.Remove(item);
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
        public ThuTien GetById(int id)
        {
            try
            {
                return _dbContext.ThuTiens.Find(id);                
            }
            catch
            {
                throw;
            }
        }

        public ThuTienView Get(int id)
        {
            try
            {
                ThuTien? item = _dbContext.ThuTiens.Find(id);
                Student sv = _dbContext.Students.Find(item.SinhVienID);
                

                if (item != null && sv !=null)
                {
                    ThuTienView outItem = new ThuTienView();
                    outItem.id =  item.id;
                    outItem.SinhVienID = item.SinhVienID;
                    outItem.MaSinhVien = sv.MaSV;
                    outItem.HoDem = sv.HoDem;
                    outItem.Ten = sv.Ten;
                    outItem.Ngaysinh = sv.Ngaysinh;
                    outItem.SoCCCD = sv.CCCD;
                    outItem.LoaiKhoanthuID = item.LoaiKhoanthuID;
                    outItem.KhoahocID = sv.KhoahocID;
                    outItem.KhoaID = sv.KhoaID;
                    outItem.KhoaTen = _dbContext.Khoas.Find(sv.KhoaID) != null ? _dbContext.Khoas.Find(sv.KhoaID).Name : "";
                    outItem.NganhID = sv.NganhID;
                    outItem.NganhTen = _dbContext.Nganhs.Find(sv.NganhID) != null ? _dbContext.Nganhs.Find(sv.NganhID).Name : "";
                    outItem.LopID = sv.LopID;
                    outItem.KyThanhToan = item.KyThanhToan;
                    outItem.SoTien = item.SoTien;
                    outItem.NgayTao = item.NgayTao;
                    outItem.NgayThanhToan = item.NgayThanhToan;
                    outItem.TrangThai = item.TrangThai;

                    return outItem;
                }
                else
                {
                    throw new ArgumentNullException();
                }
            }
            catch
            {
                throw;
            }
        }

        public List<ThuTien> GetByStudentId(int stdId)
        {
            try
            {
                var thutien_list = _dbContext.ThuTiens.Where(m=>m.SinhVienID == stdId).ToList();
                //var student_list = _dbContext.Students.Where(m => (m.MaSV != null && m.MaSV == msv)).ToList();
                //var khoaDict = _dbContext.Khoas.ToDictionary(m => m.Id, m => m.Name);
                //var nganhDict = _dbContext.Nganhs.ToDictionary(m => m.Id, m => m.Name);

                return thutien_list;
            }
            catch (Exception e)
            {

                Exception myexception = new Exception(e.Message);
                throw myexception;
            }
        }

        public List<ThuTienView> GetByMSV(string msv)
        {
            try
            {
                var thutien_list = _dbContext.ThuTiens.ToList();
                var student_list = _dbContext.Students.Where(m => (m.MaSV != null && m.MaSV.Equals(msv))).ToList();
                var khoaDict = _dbContext.Khoas.ToDictionary(m => m.Id, m => m.Name);
                var nganhDict = _dbContext.Nganhs.ToDictionary(m => m.Id, m => m.Name);
                                
                var query = (from a in thutien_list
                             join b in student_list on a.SinhVienID equals b.id
                             select new ThuTienView
                             {
                                 id = a.id,
                                 SinhVienID = a.SinhVienID,
                                 MaSinhVien = b.MaSV,
                                 HoDem = b.HoDem,
                                 Ten = b.Ten,
                                 Ngaysinh = b.Ngaysinh,
                                 SoCCCD = b.CCCD,
                                 LoaiKhoanthuID = a.LoaiKhoanthuID,
                                 KhoahocID = b.KhoahocID,
                                 KhoaID = b.KhoaID,
                                 KhoaTen = khoaDict.ContainsKey(b.KhoaID) ? khoaDict[b.KhoaID] : "-",
                                 NganhID = b.NganhID,
                                 NganhTen = nganhDict.ContainsKey(b.NganhID) ? nganhDict[b.NganhID] : "-",
                                 LopID = b.LopID,
                                 KyThanhToan = a.KyThanhToan,
                                 SoTien = a.SoTien,
                                 NgayTao = a.NgayTao,
                                 NgayThanhToan = a.NgayThanhToan,
                                 TrangThai = a.TrangThai
                             }).ToList();

                
                return query;
            }
            catch (Exception e)
            {

                Exception myexception = new Exception(e.Message);
                throw myexception;
            }
        }

        public List<ThuTienView> Get()
        {
            try
            {
                var thutien_list = _dbContext.ThuTiens.ToList();
                var student_list = _dbContext.Students.Where(m=>m.Trangthai =="DH").ToList();
                var khoaDict = _dbContext.Khoas.ToDictionary(m => m.Id, m => m.Name);
                var nganhDict = _dbContext.Nganhs.ToDictionary(m => m.Id, m => m.Name);                

                var query = (from a in thutien_list
                             join b in student_list on a.SinhVienID equals b.id
                             select new ThuTienView
                             {
                                 id = a.id,
                                 SinhVienID = a.SinhVienID,
                                 MaSinhVien = b.MaSV,
                                 HoDem = b.HoDem,
                                 Ten = b.Ten,
                                 Ngaysinh = b.Ngaysinh,
                                 SoCCCD = b.CCCD,
                                 LoaiKhoanthuID = a.LoaiKhoanthuID,
                                 KhoahocID = b.KhoahocID,
                                 KhoaID = b.KhoaID,
                                 KhoaTen = khoaDict.ContainsKey(b.KhoaID) ? khoaDict[b.KhoaID] : "-",
                                 NganhID = b.NganhID,
                                 NganhTen = nganhDict.ContainsKey(b.NganhID) ? nganhDict[b.NganhID] : "-",
                                 LopID = b.LopID,
                                 KyThanhToan = a.KyThanhToan,
                                 SoTien = a.SoTien,
                                 NgayTao = a.NgayTao,
                                 NgayThanhToan = a.NgayThanhToan,
                                 TrangThai = a.TrangThai
                             }).ToList();
               
                return query;
            }
            catch (Exception e)
            {

                Exception myexception = new Exception(e.Message);
                throw myexception;
            }
        }
        public List<ThuTienView> GetByKyThanhtoan(string loaikhoanthu, string kythanhtoan)
        {
            try
            {
                var thutien_list = _dbContext.ThuTiens
                    .Where(m=>m.LoaiKhoanthuID!=null && m.LoaiKhoanthuID.Equals(loaikhoanthu))
                    .Where(m=>m.KyThanhToan!=null && m.KyThanhToan.Equals(kythanhtoan))
                    .ToList();
                var student_list = _dbContext.Students.Where(m => m.Trangthai == "DH").ToList();
                var khoaDict = _dbContext.Khoas.ToDictionary(m => m.Id, m => m.Name);
                var nganhDict = _dbContext.Nganhs.ToDictionary(m => m.Id, m => m.Name);

                var query = (from a in thutien_list
                             join b in student_list on a.SinhVienID equals b.id
                             select new ThuTienView
                             {
                                 id = a.id,
                                 SinhVienID = a.SinhVienID,
                                 MaSinhVien = b.MaSV,
                                 HoDem = b.HoDem,
                                 Ten = b.Ten,
                                 Ngaysinh = b.Ngaysinh,
                                 SoCCCD = b.CCCD,
                                 LoaiKhoanthuID = a.LoaiKhoanthuID,
                                 KhoahocID = b.KhoahocID,
                                 KhoaID = b.KhoaID,
                                 KhoaTen = khoaDict.ContainsKey(b.KhoaID) ? khoaDict[b.KhoaID] : "-",
                                 NganhID = b.NganhID,
                                 NganhTen = nganhDict.ContainsKey(b.NganhID) ? nganhDict[b.NganhID] : "-",
                                 LopID = b.LopID,
                                 KyThanhToan = a.KyThanhToan,
                                 SoTien = a.SoTien,
                                 NgayTao = a.NgayTao,
                                 NgayThanhToan = a.NgayThanhToan,
                                 TrangThai = a.TrangThai
                             }).ToList();

                return query;
            }
            catch (Exception e)
            {

                Exception myexception = new Exception(e.Message);
                throw myexception;
            }
        }
        public ThutienSearchOption GetThutiens(ThutienSearchOption op)
        {
            try
            {
                var thutien_list = _dbContext.ThuTiens.ToList();
                var student_list = _dbContext.Students.ToList();
                var khoaDict = _dbContext.Khoas.ToDictionary(m=>m.Id,m=>m.Name);
                var nganhDict = _dbContext.Nganhs.ToDictionary(m=>m.Id, m=>m.Name);

                if (op.LoaiKhoanthuID != null && op.LoaiKhoanthuID != "")
                {
                    thutien_list = thutien_list.Where(m => m.LoaiKhoanthuID == op.LoaiKhoanthuID).ToList();
                }

                if (op.KhoahocID != null && op.KhoahocID!="")
                {
                    student_list = student_list.Where(m => m.KhoahocID == op.KhoahocID).ToList();
                }

                if (op.KhoaID != null && op.KhoaID != "")
                {
                    student_list = student_list.Where(m => m.KhoaID == op.KhoaID).ToList();
                }

                if (op.NganhID != null && op.NganhID != "")
                {
                    student_list = student_list.Where(m => m.NganhID == op.NganhID).ToList();
                }

                if (op.LopID != null && op.LopID != "")
                {
                    student_list = student_list.Where(m => m.LopID == op.LopID).ToList();
                }
                if (op.KeyWord != null && op.KeyWord != "")
                {
                    string k = op.KeyWord.ToUpper();
                    student_list = student_list.Where(m => (m.HoDem != null && m.HoDem.ToUpper().Contains(k))
                    || (m.Ten != null && m.Ten.ToUpper().Contains(k))
                    || (m.MaSV != null && m.MaSV.Contains(k))
                    
                    ).ToList();
                }
                
                var query = (from a in thutien_list
                             join b in student_list on a.SinhVienID equals b.id                           
                             select new ThuTienView {
                                 id = a.id,
                                 SinhVienID=a.SinhVienID,
                                MaSinhVien= b.MaSV,
                                HoDem=b.HoDem,
                                Ten=b.Ten,
                                Ngaysinh=b.Ngaysinh,
                                SoCCCD=b.CCCD,
                                LoaiKhoanthuID=a.LoaiKhoanthuID,
                                KhoahocID=b.KhoahocID,
                                KhoaID=b.KhoaID,
                                KhoaTen = khoaDict.ContainsKey(b.KhoaID) ? khoaDict[b.KhoaID]:"-",
                                NganhID=b.NganhID,
                                 NganhTen = nganhDict.ContainsKey(b.NganhID) ? nganhDict[b.NganhID]:"-",
                                LopID=b.LopID,
                                KyThanhToan=a.KyThanhToan,
                                SoTien=a.SoTien,
                                NgayTao=a.NgayTao,
                                NgayThanhToan=a.NgayThanhToan,
                                TrangThai=a.TrangThai
                             }).ToList();

                if (op.Pagesize != -1)
                {
                    if (op.Page == null) op.Page = 1;
                    if (op.Pagesize == null) op.Pagesize = 60;
                    var count = query.Count();
                    op.NumPage = count / op.Pagesize + (count % op.Pagesize != 0 ? 1 : 0);
                    int skip = (op.Page.Value - 1) * op.Pagesize.Value;
                    int pSize = op.Pagesize.Value;

                    query = query.Skip(skip).Take(pSize).ToList();
                }
                

                op.Thutien_list = query;
                return op;
            }
            catch (Exception e)
            {

                Exception myexception = new Exception(e.Message);
                throw myexception;
            }
        }

        public List<ThuTienView> GetThutienExport(ThutienSearchOption op)
        {
            try
            {
                var thutien_list = _dbContext.ThuTiens.ToList();
                var student_list = _dbContext.Students.ToList();
                var khoaDict = _dbContext.Khoas.ToDictionary(m => m.Id, m => m.Name);
                var nganhDict = _dbContext.Nganhs.ToDictionary(m => m.Id, m => m.Name);

                if (op.LoaiKhoanthuID != null && op.LoaiKhoanthuID != "")
                {
                    thutien_list = thutien_list.Where(m => m.LoaiKhoanthuID == op.LoaiKhoanthuID).ToList();
                }

                if (op.KhoahocID != null && op.KhoahocID != "")
                {
                    student_list = student_list.Where(m => m.KhoahocID == op.KhoahocID).ToList();
                }

                if (op.KhoaID != null && op.KhoaID != "")
                {
                    student_list = student_list.Where(m => m.KhoaID == op.KhoaID).ToList();
                }

                if (op.NganhID != null && op.NganhID != "")
                {
                    student_list = student_list.Where(m => m.NganhID == op.NganhID).ToList();
                }

                if (op.LopID != null && op.LopID != "")
                {
                    student_list = student_list.Where(m => m.LopID == op.LopID).ToList();
                }
                if (op.KeyWord != null && op.KeyWord != "")
                {
                    string k = op.KeyWord.ToUpper();
                    student_list = student_list.Where(m => (m.HoDem != null && m.HoDem.ToUpper().Contains(k))
                    || (m.Ten != null && m.Ten.ToUpper().Contains(k))
                    || (m.MaSV != null && m.MaSV.Contains(k))

                    ).ToList();
                }

                var query = (from a in thutien_list
                             join b in student_list on a.SinhVienID equals b.id
                             select new ThuTienView
                             {
                                 id = a.id,
                                 SinhVienID = a.SinhVienID,
                                 MaSinhVien = b.MaSV,
                                 HoDem = b.HoDem,
                                 Ten = b.Ten,
                                 Ngaysinh = b.Ngaysinh,
                                 SoCCCD = b.CCCD,
                                 LoaiKhoanthuID = a.LoaiKhoanthuID,
                                 KhoahocID = b.KhoahocID,
                                 KhoaID = b.KhoaID,
                                 KhoaTen = khoaDict.ContainsKey(b.KhoaID) ? khoaDict[b.KhoaID] : "-",
                                 NganhID = b.NganhID,
                                 NganhTen = nganhDict.ContainsKey(b.NganhID) ? nganhDict[b.NganhID] : "-",
                                 LopID = b.LopID,
                                 KyThanhToan = a.KyThanhToan,
                                 SoTien = a.SoTien,
                                 NgayTao = a.NgayTao,
                                 NgayThanhToan = a.NgayThanhToan,
                                 TrangThai = a.TrangThai
                             }).ToList();                
                return query;
            }
            catch (Exception e)
            {

                Exception myexception = new Exception(e.Message);
                throw myexception;
            }
        }
        public bool Update(ThuTien item)
        {
            try
            {
                _dbContext.Entry(item).State = EntityState.Modified;
                _dbContext.SaveChanges();
                return true;
            }
            catch
            {
                return false;
            }
        }
        //Thêm khoản thu cho sinh viên
        //Input: Loại khoản thu, Kỳ thanh toán, mã sinh viên, số tiền
        public bool AddFromView(ThuTienView item)
        {
            try
            {
                Student sv = _dbContext.Students
                    .Where(m=>m.MaSV!=null && m.MaSV.Equals(item.MaSinhVien))
                    .FirstOrDefault();
                if (sv!=null)
                {
                    ThuTien newThutien = _dbContext.ThuTiens
                        .Where(m => m.SinhVienID != null && m.SinhVienID.Equals(sv.id))
                        .Where(m => m.LoaiKhoanthuID != null && m.LoaiKhoanthuID.Equals(item.LoaiKhoanthuID))
                        .Where(m => m.KyThanhToan != null && m.KyThanhToan.Equals(item.KyThanhToan))
                        .FirstOrDefault();
                    if (newThutien == null)
                    {
                        //Chưa có khoản thu trong cơ sở dữ liệu
                        newThutien = new ThuTien();
                        newThutien.SinhVienID = sv.id;
                        newThutien.LoaiKhoanthuID = item.LoaiKhoanthuID;
                        newThutien.KyThanhToan = item.KyThanhToan;
                        newThutien.SoTien = item.SoTien;
                        newThutien.NgayTao = DateTime.Now;
                        newThutien.TrangThai = 0; // Chưa thanh toán

                        _dbContext.ThuTiens.Add(newThutien);
                        _dbContext.SaveChanges();
                        return true;
                    }
                    else
                    {
                        //Đã có khoản thu trong cơ sở dữ liệu
                        return false;
                    }
                    
                }else
                {
                    return false;
                }
                
            }
            catch
            {
                //Không tìm thấy sinh viên
                return false;
            }
        }
        // Cập nhật trạng thái của một khoản thu sinh viên
        //Sử dụng khi thu tiền mặt sinh viên
        public bool UpdateFromView(ThuTienView item)
        {
            try
            {
                ThuTien sv = _dbContext.ThuTiens.Find(item.id);
                    
                if (sv != null)
                {                    
                    //sv.SoTien = item.SoTien;
                    sv.TrangThai = item.TrangThai;                    
                    _dbContext.Entry(sv).State = EntityState.Modified;
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
        public bool ThanhtoanByID(int id)
        {
            try
            {
                ThuTien item = _dbContext.ThuTiens.Find(id);
                if (item != null)
                {
                    item.NgayThanhToan = DateTime.Now;
                    item.TrangThai = 1; //0 chưa thanh toán; 1 đã thanh toán
                    _dbContext.Entry(item).State = EntityState.Modified;
                    _dbContext.SaveChanges();
                    return true;
                }
                
            }
            catch
            {
                return false;
            }
            return false;
        }

        public bool LapDS(ThuTienView item)
        {
            try
            {
                var SvList = _dbContext.Students.ToList();
                if (item.KhoahocID != null && item.KhoahocID != "")
                    SvList = SvList.Where(m => (m.KhoahocID != null && m.KhoahocID == item.KhoahocID)).ToList();
                if(item.NganhID!=null && item.NganhID!="")
                    SvList = SvList.Where(m => (m.NganhID != null && m.NganhID == item.NganhID)).ToList();
                
                if (SvList != null)
                {
                    foreach (var sv  in SvList)
                    {
                        ThuTien newItem = new ThuTien();
                        newItem.SinhVienID = sv.id;
                        //newItem.MaSinhVien = sv.MaSV;
                        //newItem.HoDem = sv.HoDem;
                        //newItem.Ten = sv.Ten;
                        //newItem.Ngaysinh = sv.Ngaysinh;
                        //newItem.SoCCCD = sv.CCCD;
                        //newItem.KhoahocID = sv.KhoahocID;
                        //newItem.NganhID = sv.NganhID;
                        //newItem.LopID = sv.LopID;
                        
                        newItem.LoaiKhoanthuID = item.LoaiKhoanthuID;
                        newItem.KyThanhToan = item.KyThanhToan;
                        newItem.SoTien = item.SoTien;
                        newItem.TrangThai = 0;
                        newItem.NgayTao = DateTime.Now;
                        _dbContext.ThuTiens.Add(newItem);
                        _dbContext.SaveChanges();
                    }
                }
                //_dbContext.SaveChanges();
                return true;
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                return false;
            }
        }
        public bool LapDS_KTX(ThuTienView item)
        {
            try
            {
                var SvList = _dbContext.SinhvienPhongs.Where(m=>m.Trangthai==1).ToList();               

                if (SvList != null)
                {
                    foreach (var sv in SvList)
                    {
                        var t = _dbContext.ThuTiens.Where(m => m.SinhVienID == sv.SinhvienId)
                            .Where(m => m.LoaiKhoanthuID == item.LoaiKhoanthuID)
                            .Where(m => m.KyThanhToan == item.KyThanhToan).FirstOrDefault();
                        if (t == null)
                        {
                            ThuTien newItem = new ThuTien();
                            newItem.SinhVienID = sv.SinhvienId;
                            newItem.LoaiKhoanthuID = item.LoaiKhoanthuID;
                            newItem.KyThanhToan = item.KyThanhToan;
                            newItem.SoTien = item.SoTien;
                            newItem.TrangThai = 0;
                            newItem.NgayTao = DateTime.Now;
                            _dbContext.ThuTiens.Add(newItem);
                            _dbContext.SaveChanges();
                        }                        
                    }
                }
                //_dbContext.SaveChanges();
                return true;
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                return false;
            }
        }
        public bool ThanhtoanByMSV(string msv)
        {
            var item = _dbContext.Students.Where(m => (m.MaSV != null && m.MaSV == msv)).FirstOrDefault();
            if (item != null)
            {
                try
                {
                    var tt = _dbContext.ThuTiens.Where(m=>(m.SinhVienID !=null  && m.SinhVienID.Value == item.id)).FirstOrDefault();
                    if (tt != null)
                    {
                        _dbContext.Entry(tt).State = EntityState.Modified;
                        _dbContext.SaveChanges();
                        return true;
                    }                    
                }
                catch (Exception e)
                {
                    return false;
                }
            }
            return false;
        }
    }
}
