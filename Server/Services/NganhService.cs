using Flic.Server.Data;
using Flic.Server.Interfaces;
using Flic.Shared.Models;
using Microsoft.EntityFrameworkCore;



namespace Flic.Server.Services
{
    public class NganhService : INganh
    {
        readonly ApplicationDbContext _dbContext;
        public NganhService(ApplicationDbContext dbContext)
        {
            _dbContext = dbContext;
        }

        public void Add(Nganh item)
        {
            try
            {
                _dbContext.Nganhs.Add(item);
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
                Nganh? khoa = _dbContext.Nganhs.Find(id);
                if (khoa != null)
                {
                    _dbContext.Nganhs.Remove(khoa);
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

        public Nganh Get(string id)
        {
            try
            {
                Nganh? item = _dbContext.Nganhs.Find(id);
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

        public List<Nganh> Get()
        {
            try
            {
                return _dbContext.Nganhs.ToList();
            }
            catch (Exception e)
            {

                Exception myexception = new Exception(e.Message);
                throw myexception;
            }
        }

        public void Update(Nganh item)
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
