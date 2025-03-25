using Flic.Server.Data;
using Flic.Server.Interfaces;
using Flic.Shared.Models;
using Microsoft.EntityFrameworkCore;

namespace Flic.Server.Services
{
    public class DotthiService:IDotthi
    {
        readonly ApplicationDbContext _dbContext;
        public DotthiService(ApplicationDbContext dbContext)
        {
            _dbContext = dbContext;
        }

        public bool Add(Dotthi item)
        {
            try
            {
                _dbContext.Dotthis.Add(item);
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
                Dotthi? item = _dbContext.Dotthis.Find(id);
                if (item != null)
                {
                    _dbContext.Dotthis.Remove(item);
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

        public List<Dotthi> Get()
        {
            try
            {
                return _dbContext.Dotthis.OrderByDescending(m=>m.Id).ToList();
            }
            catch (Exception e)
            {

                Exception myexception = new Exception(e.Message);
                throw myexception;
            }
        }

        public Dotthi Get(string id)
        {
            try
            {
                Dotthi? item = _dbContext.Dotthis.Find(id);
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

        public bool Update(Dotthi item)
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
