using Flic.Server.Data;
using Flic.Server.Interfaces;
using Flic.Shared.Models;
using Microsoft.EntityFrameworkCore;




namespace Flic.Server.Services
{
    public class LopService : ILop 
    {
        readonly ApplicationDbContext _dbContext;
        public LopService(ApplicationDbContext dbContext)
        {
            _dbContext = dbContext;
        }

        public void Add(Lop item)
        {
            try
            {
                _dbContext.Lops.Add(item);
                _dbContext.SaveChanges();
            }
            catch
            {
                throw;
            }
        }

        public void Delete(string id)
        {
            try
            {
                Lop? item = _dbContext.Lops.Find(id);
                if (item != null)
                {
                    _dbContext.Lops.Remove(item);
                    _dbContext.SaveChanges();
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

        public Lop Get(string id)
        {
            try
            {
                Lop? item = _dbContext.Lops.Find(id);
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

        public List<Lop> Get()
        {
            try
            {
                return _dbContext.Lops.ToList();
            }
            catch (Exception e)
            {

                Exception myexception = new Exception(e.Message);
                throw myexception;
            }
        }

        public void Update(Lop item)
        {
            try
            {
                _dbContext.Entry(item).State = EntityState.Modified;
                _dbContext.SaveChanges();
            }
            catch
            {
                throw;
            }
        }
    }
}
