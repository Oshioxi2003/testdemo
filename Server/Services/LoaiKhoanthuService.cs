using Flic.Server.Data;
using Flic.Server.Interfaces;
using Flic.Shared.Models;
using Microsoft.EntityFrameworkCore;

namespace Flic.Server.Services
{
    
    public class LoaiKhoanthuService : ILoaiKhoanthu
    {
        readonly ApplicationDbContext _dbContext;
        public LoaiKhoanthuService(ApplicationDbContext dbContext)
        {
            _dbContext = dbContext;
        }

        public bool Add(LoaiKhoanthu item)
        {
            try
            {
                _dbContext.LoaiKhoanthus.Add(item);
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
                LoaiKhoanthu? item = _dbContext.LoaiKhoanthus.Find(id);
                if (item != null)
                {
                    _dbContext.LoaiKhoanthus.Remove(item);
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

        public LoaiKhoanthu Get(string id)
        {
            try
            {
                LoaiKhoanthu? item = _dbContext.LoaiKhoanthus.Find(id);
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

        public List<LoaiKhoanthu> Get()
        {
            try
            {
                return _dbContext.LoaiKhoanthus.ToList();
            }
            catch (Exception e)
            {

                Exception myexception = new Exception(e.Message);
                throw myexception;
            }
        }

        public bool Update(LoaiKhoanthu item)
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
