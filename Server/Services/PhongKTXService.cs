using Flic.Server.Data;
using Flic.Server.Interfaces;
using Flic.Shared.Models;
using Microsoft.EntityFrameworkCore;

namespace Flic.Server.Services
{
    public class PhongKTXService : IPhongKTX
    {
        readonly ApplicationDbContext _dbContext;
        public PhongKTXService(ApplicationDbContext dbContext)
        {
            _dbContext = dbContext;
        }
        public bool Add(PhongKTX item)
        {
            try
            {
                _dbContext.PhongKTXs.Add(item);
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
                PhongKTX? item = _dbContext.PhongKTXs.Find(id);
                if (item != null)
                {
                    _dbContext.PhongKTXs.Remove(item);
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

        public List<PhongKTX> Get()
        {
            try
            {
                return _dbContext.PhongKTXs.Where(m => m.Trangthai == 1).ToList();
            }
            catch
            {
                return new List<PhongKTX>();
            }
        }

        public PhongKTX Get(string id)
        {
            try
            {
                return _dbContext.PhongKTXs.Find(id);
            }
            catch
            {
                return new PhongKTX();
            }
        }

        public bool Update(PhongKTX item)
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
