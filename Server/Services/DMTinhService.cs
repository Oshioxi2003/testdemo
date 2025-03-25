using Flic.Server.Data;
using Flic.Server.Interfaces;
using Flic.Shared.Models;
using Microsoft.EntityFrameworkCore;

namespace Flic.Server.Services
{
    public class DMTinhService:IDMTinh
    {
        readonly ApplicationDbContext _dbContext;
        public DMTinhService(ApplicationDbContext dbContext) {
            _dbContext = dbContext;
        }

        public bool Add(DMTinh item)
        {
            try
            {
                _dbContext.DMTinhs.Add(item);
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
                DMTinh? item = _dbContext.DMTinhs.Find(id);
                if (item != null)
                {
                    _dbContext.DMTinhs.Remove(item);
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

        public List<DMTinh> Get()
        {
            try
            {
                return _dbContext.DMTinhs.ToList();
            }
            catch (Exception e)
            {

                Exception myexception = new Exception(e.Message);
                throw myexception;
            }
        }

        public DMTinh Get(int id)
        {
            try
            {
                DMTinh? item = _dbContext.DMTinhs.Find(id);
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

        public bool Update(DMTinh item)
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
