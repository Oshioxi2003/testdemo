using Flic.Server.Data;
using Flic.Server.Interfaces;
using Flic.Shared.Models;
using MathNet.Numerics.LinearAlgebra.Factorization;
using Microsoft.EntityFrameworkCore;

namespace Flic.Server.Services
{
    public class SinhvienPhongService : ISinhvienPhong
    {
        readonly ApplicationDbContext _dbContext;
        public SinhvienPhongService(ApplicationDbContext dbContext)
        {
            _dbContext = dbContext;
        }
        public bool Add(SinhvienPhong item)
        {          
            try
            {
                var t = _dbContext.SinhvienPhongs.Where(m => m.SinhvienId == item.SinhvienId).Where(m => m.PhongId == item.PhongId).FirstOrDefault();
                if (t == null)
                {
                    _dbContext.SinhvienPhongs.Add(item);
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
        public bool Delete(int id)
        {          
            try
            {
                SinhvienPhong? item = _dbContext.SinhvienPhongs.Find(id);
                if (item != null)
                {
                    _dbContext.SinhvienPhongs.Remove(item);
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
        public List<SinhvienPhongView> Get()
        {                      
            try
            {
                List<SinhvienPhong> svp_lst =  _dbContext.SinhvienPhongs.Where(m=>m.Trangthai ==1 ).ToList();
                List<Student> std_lst = _dbContext.Students.Where(m => m.Trangthai == "DH").ToList();
                var rs = (from a in svp_lst 
                          join b in std_lst on a.SinhvienId equals b.id
                         select new SinhvienPhongView
                         {
                             Id = a.Id,
                             SinhvienId = a.SinhvienId,
                             PhongId = a.PhongId,
                             SinhvienMSV = b.MaSV,
                             SinhvienHoDem = b.HoDem,
                             SinhvienTen = b.Ten,
                             SinhvienHoTen = b.HoDem + " " + b.Ten,
                             SinhvienLop = b.LopID,
                             Trangthai = a.Trangthai
                         }).ToList();
                return rs;
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                return new List<SinhvienPhongView>();
            }
            return new List<SinhvienPhongView>();
        }
        public SinhvienPhongView Get(int id)
        {
            try
            {
                var svp =  _dbContext.SinhvienPhongs.Find(id);
                var std = _dbContext.Students.Find(svp.SinhvienId);
                if (std != null && svp!=null)
                {
                    SinhvienPhongView rs = new SinhvienPhongView();
                    rs.Id = svp.Id;
                    rs.SinhvienId = svp.SinhvienId;
                    rs.PhongId= svp.PhongId;
                    rs.SinhvienMSV = std.MaSV;
                    rs.SinhvienHoDem = std.HoDem;
                    rs.SinhvienHoTen = std.HoDem + " " + std.Ten;
                    rs.SinhvienTen = std.Ten;
                    rs.SinhvienLop = std.LopID;
                    rs.Trangthai = svp.Trangthai;
                    return rs;
                }
            }
            catch
            {
                return new SinhvienPhongView();
            }
            return new SinhvienPhongView();
        }
       
        public bool Update(SinhvienPhong item)
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
    }
}
