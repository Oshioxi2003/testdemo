using Flic.Server.Data;
using Flic.Server.Interfaces;
using Flic.Shared.Models;
using Microsoft.EntityFrameworkCore;

namespace Flic.Server.Services
{
    public class KhoanthuService:IKhoanthu
    {
        readonly ApplicationDbContext _dbContext;
        public KhoanthuService(ApplicationDbContext dbContext)
        {
            _dbContext = dbContext;
        }

        public bool Add(Khoanthu item)
        {
            try
            {
                _dbContext.Khoanthus.Add(item);
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
                Khoanthu? item = _dbContext.Khoanthus.Find(id);
                if (item != null)
                {
                    _dbContext.Khoanthus.Remove(item);
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

        public Khoanthu Get(int id)
        {
            try
            {
                Khoanthu? item = _dbContext.Khoanthus.Find(id);
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
                throw;
            }
        }
        public Khoanthu GetByItem(Khoanthu item)
        {
            var ls = _dbContext.Khoanthus.Where(m => (m.MaLoaiKhoanThu != null) && (m.MaLoaiKhoanThu == item.MaLoaiKhoanThu)).ToList();
            if (item.NganhID != null && item.NganhID !="")
            {
                ls = ls.Where(m => (m.NganhID != null && m.NganhID == item.NganhID)).ToList();
            }else
            {
                ls = ls.Where(m => m.NganhID == null).ToList();
            }
            if (item.KhoahocID != null && item.KhoahocID !="")
            {
                ls = ls.Where(m => (m.KhoahocID != null && m.KhoahocID == item.KhoahocID)).ToList();
            }else
            {
                ls = ls.Where(m => m.KhoahocID == null).ToList();
            }

            if (item.KyThanhToan != null && item.KyThanhToan !="")
            {
                ls = ls.Where(m => (m.KyThanhToan != null && m.KyThanhToan == item.KyThanhToan)).ToList();
            }else
            {
                ls = ls.Where(m => m.KyThanhToan == null).ToList();
            }

            var  obj = ls.OrderByDescending(m =>m.id).FirstOrDefault();

            return obj;
        }
        public List<Khoanthu> Get()
        {
            try
            {
                return _dbContext.Khoanthus.ToList();
            }
            catch (Exception e)
            {

                Exception myexception = new Exception(e.Message);
                throw myexception;
            }
        }

        public bool Update(Khoanthu item)
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
