using Flic.Server.Data;
using Flic.Server.Interfaces;
using Flic.Shared.Models;
using Microsoft.EntityFrameworkCore;



namespace Flic.Server.Services
{
    public class KhoahocService : IKhoahoc
    {
        readonly ApplicationDbContext _dbContext;
        public KhoahocService(ApplicationDbContext dbContext)
        {
            _dbContext = dbContext;
        }

        public void Add(Khoahoc khoa)
        {
            try
            {
                _dbContext.Khoahocs.Add(khoa);
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
                Khoahoc? khoa = _dbContext.Khoahocs.Find(id);
                if (khoa != null)
                {
                    _dbContext.Khoahocs.Remove(khoa);
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

        public Khoahoc Get(string id)
        {
            try
            {
                Khoahoc? item = _dbContext.Khoahocs.Find(id);
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

        public List<Khoahoc> Get()
        {
            try
            {
                return _dbContext.Khoahocs.ToList();
            }
            catch (Exception e)
            {

                Exception myexception = new Exception(e.Message);
                throw myexception;
            }
        }

        public void Update(Khoahoc item)
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
