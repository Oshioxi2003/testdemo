using Flic.Server.Data;
using Flic.Server.Interfaces;
using Flic.Shared.Models;
using Microsoft.EntityFrameworkCore;

namespace Flic.Server.Services
{
    public class DMDantocService: IDMDantoc
    {
        readonly ApplicationDbContext _dbContext;
        public DMDantocService(ApplicationDbContext dbContext)
        {
            _dbContext = dbContext;
        }
        
        public bool Add(DMDantoc item)
        {
            try
            {
                _dbContext.DMDantocs.Add(item);
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
                DMDantoc? item = _dbContext.DMDantocs.Find(id);
                if (item != null)
                {
                    _dbContext.DMDantocs.Remove(item);
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

        public List<DMDantoc> Get()
        {
            try
            {
                return _dbContext.DMDantocs.ToList();
            }
            catch (Exception e)
            {

                Exception myexception = new Exception(e.Message);
                throw myexception;
            }
        }

        public DMDantoc Get(int id)
        {
            try
            {
                DMDantoc? item = _dbContext.DMDantocs.Find(id);
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

        public bool Update(DMDantoc item)
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
