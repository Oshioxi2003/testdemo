using Flic.Server.Data;
using Flic.Server.Interfaces;
using Flic.Shared.Models;
using Microsoft.EntityFrameworkCore;

namespace Flic.Server.Services
{
    public class KyThanhtoanService:IKyThanhtoan
    {
        readonly ApplicationDbContext _dbContext;
        public KyThanhtoanService(ApplicationDbContext dbContext)
        {
            _dbContext = dbContext;
        }

        public bool Add(KyThanhtoan item)
        {
            try
            {
                _dbContext.KyThanhtoans.Add(item);
                _dbContext.SaveChanges();
                return true;
            }
            catch
            {
                return false;
            }
        }

        public bool Delete(string id)
        {
            try
            {
                KyThanhtoan? item = _dbContext.KyThanhtoans.Find(id);
                if (item != null)
                {
                    _dbContext.KyThanhtoans.Remove(item);
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

        public KyThanhtoan Get(string id)
        {
            try
            {
                KyThanhtoan? item = _dbContext.KyThanhtoans.Find(id);
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

        public List<KyThanhtoan> Get()
        {
            try
            {
                return _dbContext.KyThanhtoans.ToList();
            }
            catch (Exception e)
            {

                Exception myexception = new Exception(e.Message);
                throw myexception;
            }
        }

        public List<KyThanhtoan> GetByKhoanthu(string kt)
        {
            try
            {
                return _dbContext.KyThanhtoans
                    .Where(m=>m.LoaiKhoanthu!=null && m.LoaiKhoanthu.Equals(kt))
                    .OrderByDescending(m=>m.Id)
                    .ToList();
            }
            catch (Exception e)
            {

                Exception myexception = new Exception(e.Message);
                throw myexception;
            }
        }


        public bool Update(KyThanhtoan item)
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
