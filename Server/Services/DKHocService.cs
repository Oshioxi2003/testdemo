using Flic.Server.Data;
using Flic.Server.Interfaces;
using Flic.Shared.Models;
using Microsoft.EntityFrameworkCore;
using System.Collections.Generic;
using System.Linq.Dynamic.Core;
using System.Reflection;

namespace Flic.Server.Services
{
    public class DKHocService:IDKHoc
    {
        readonly ApplicationDbContext _dbContext;
        private ILogger _Logger;
        public DKHocService(ApplicationDbContext dbContext, ILogger logger)
        {
            _dbContext = dbContext;
            _Logger = logger;
        }

        public int Add(DKHoc item)
        {            
            try
            {
                Guid g = Guid.NewGuid();
                Lophoc lh = _dbContext.Lophocs.Find(item.CourseId);
                if (lh != null)
                {
                    item.Hocphi = lh.Hocphi;
                }
                var a = _dbContext.DKHocs.Where(x => x.CCCD!=null && x.CCCD.Equals(item.CCCD))
                    .Where(x=>x.CourseId!=null && x.CourseId.Equals(item.CourseId))
                    .FirstOrDefault();
                if (a!=null)
                {
                    throw new InvalidOperationException("Bị trùng thông tin");
                }
                item.guid = g.ToString();
                item.NgayTao = DateTime.Now;
                _dbContext.DKHocs.Add(item);
                _dbContext.SaveChanges();
                //DKHoc a = _dbContext.DKHocs.Where(m=>m.guid.Equals(g)).FirstOrDefault();
                return item.Id;
            }
            catch (Exception e)
            {
                _Logger.LogError("Lỗi - " + e.Message);
                throw new InvalidOperationException(e.Message);
            }
        }

        public void Delete(int id)
        {
            try
            {
                DKHoc? item = _dbContext.DKHocs.Find(id);
                if (item != null)
                {
                    _dbContext.DKHocs.Remove(item);
                    _dbContext.SaveChanges();
                }
                else
                {
                    _Logger.LogError("Lỗi - không tìm thấy ID:" + id.ToString());
                    throw new ArgumentNullException();
                }
            }
            catch (Exception e)
            {
                _Logger.LogError("Lỗi - " + e.Message);
                throw new ArgumentNullException();
            }
        }

        public DKHoc Get(int id)
        {
            try
            {
                DKHoc? item = _dbContext.DKHocs.Find(id);
                if (item != null)
                {
                    return item;
                }
                else
                {
                    _Logger.LogError("Lỗi - không tìm thấy ID:" + id.ToString());
                    throw new ArgumentNullException();
                }
            }
            catch (ArgumentException e) 
            {
                _Logger.LogError("Lỗi - " + e.Message);
                throw new Exception(e.Message);
            }
        }

        public List<DKHoc> GetByCCCD(string cccd)
        {
            try
            {
                List<DKHoc> items = _dbContext.DKHocs.Where(m => m.CCCD!=null && m.CCCD.Equals(cccd)).ToList();
                if (items != null)
                {
                    return items;
                }
                else
                {
                    _Logger.LogError("Lỗi Không tìm thấy bản ghi :" + cccd);
                    throw new Exception("Không tìm thấy bản ghi :" + cccd);
                }
            }
            catch (Exception ex)
            {
                _Logger.LogError("Lõi khi tìm thấy bản ghi :" + cccd + " Err:" + ex.Message);
                throw new Exception("Lõi khi tìm thấy bản ghi :" + cccd + " Err:" + ex.Message);
            }
        }
        public List<DKHoc> GetByMobile(string mobile)
        {
            try
            {
                List<DKHoc> items = _dbContext.DKHocs.Where(m => m.DienThoai != null && m.DienThoai.Equals(mobile)).ToList();
                if (items != null)
                {
                    return items;
                }
                else
                {
                    _Logger.LogError("Lõi khi tìm thấy bản ghi có số mobile:" + mobile);
                    throw new Exception("Không tìm thấy bản ghi :" + mobile);
                }
            }
            catch (Exception ex)
            {
                _Logger.LogError("Lỗi :" + ex.Message);
                throw new Exception("Lõi khi tìm thấy bản ghi :" + mobile + " Err:" + ex.Message);
            }
        }
        public List<DKHoc> GetByEmail(string email)
        {
            try
            {
                List<DKHoc> items = _dbContext.DKHocs.Where(m => m.Email != null && m.Email.Equals(email)).ToList();
                if (items != null)
                {
                    return items;
                }
                else
                {
                    _Logger.LogError("Lỗi không tìm thấy email :" + email);
                    throw new Exception("Không tìm thấy bản ghi :" + email);
                }
            }
            catch (Exception ex)
            {
                _Logger.LogError("Lỗi :" + ex.Message);
                throw new Exception("Lõi khi tìm thấy bản ghi :" + email + " Err:" + ex.Message);
            }
        }

        public DKHoc GetGuid(string gid)
        {
            try
            {
                DKHoc? item = _dbContext.DKHocs.Where(m=>m.guid.Equals(gid)).FirstOrDefault();
                if (item != null)
                {
                    return item;
                }
                else
                {
                    _Logger.LogError("Lỗi không tìm thấy bản ghi:" + gid);
                    throw new Exception("Không tìm thấy bản ghi :" + gid);
                }
            }
            catch (Exception ex) 
            {
                _Logger.LogError("Lỗi :" + ex.Message);
                throw new Exception("Lõi khi tìm thấy bản ghi :" + gid + " Err:" + ex.Message);
            }
        }

        public List<DKHoc> Get()
        {
            try
            {
                return _dbContext.DKHocs.ToList();
            }
            catch (Exception ex)
            {
                _Logger.LogError("Lỗi :" + ex.Message);
                Exception myexception = new Exception(ex.Message);
                throw myexception;
            }
        }
        public DKHocQueryResult GetListView(string khoahocs)
        {
            List<DKHocView> list = new List<DKHocView>();
            try
            {
                var _maKhoaHoc = khoahocs.Split(';').ToList();
                var a = _dbContext.DKHocs.Where(t => _maKhoaHoc.Contains(t.CourseId.ToString())).ToList();
                var _khoahoc = _dbContext.Khoahocs.ToList().Distinct().ToDictionary(x => x.Id, x => x.Name);                
                var _nganh = _dbContext.Nganhs.ToList().Distinct().ToDictionary(x => x.Id, x => x.Name);
                var _lop = _dbContext.Lops.ToList().Distinct().ToDictionary(x => x.Id, x => x.Name);
                var _lophocs = _dbContext.Lophocs.ToList().Distinct().ToDictionary(x => x.Id, x => x.TenLop);

                foreach (var item in a)
                {
                    var rs = new DKHocView();
                    rs.Id = item.Id;
                    rs.CCCD = item.CCCD;
                    rs.DiaChi = item.DiaChi;
                    rs.Hocphi = item.Hocphi;
                    rs.CourseId = item.CourseId;
                    rs.CourseName = "";
                    string str;
                    bool hasValue;
                    if (item.CourseId != null)
                    {
                        hasValue = _lophocs.TryGetValue(item.CourseId, out str);
                        if (hasValue) rs.CourseName = str;
                    }
                    rs.DienThoai= item.DienThoai;
                    rs.Email = item.Email;
                    rs.DaThanhtoan = item.DaThanhtoan;  
                    rs.GioiTinh= item.GioiTinh;
                    rs.HovaDem = item.HovaDem;
                    rs.Ten = item.Ten;
                    rs.Trangthai= item.Trangthai;
                    rs.MaSinhvien = item.MaSinhvien;
                    rs.KhoahocID = item.KhoahocID;
                    rs.NganhID = item.NganhID;
                    rs.LopID= item.LopID;
                    rs.NgayTao = item.NgayTao;
                    rs.NgaySua= item.NgaySua;
                    list.Add(rs);
                }
                    return new DKHocQueryResult { list = list, Message="SUCCESS" };
            }catch(Exception ex)
            {
                _Logger.LogError("Lỗi :" + ex.Message);
                return new DKHocQueryResult { list = list, Message = "ERROR: " + ex.Message };
            }
            
        }
        public List<DKHoc> GetActive()
        {
            try
            {
                return _dbContext.DKHocs.Where(m=>m.Trangthai == 1).ToList();
            }
            catch (Exception ex)
            {
                _Logger.LogError("Lỗi :" + ex.Message);
                Exception myexception = new Exception(ex.Message);
                throw myexception;
            }
        }
        public List<DKHoc> GetInActive()
        {
            try
            {
                return _dbContext.DKHocs.Where(m => m.Trangthai == 0).ToList();
            }
            catch (Exception ex)
            {
                _Logger.LogError("Lỗi :" + ex.Message);
                Exception myexception = new Exception(ex.Message);
                throw myexception;
            }
        }
        public int Update(DKHoc item)
        {
            try
            {
                _dbContext.Entry(item).State = EntityState.Modified;
                _dbContext.SaveChanges();
                return item.Id;
            }
            catch (Exception ex)
            {
                _Logger.LogError("Lỗi :" + ex.Message);
                throw new InvalidOperationException(ex.Message);
            }
        }
    }
}
