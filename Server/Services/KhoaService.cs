using Flic.Server.Interfaces;
using Flic.Shared.Models;
using Flic.Server.Data;
using Microsoft.EntityFrameworkCore;

namespace Flic.Server.Services
{
    public class KhoaService : IKhoa
    {
        readonly ApplicationDbContext _dbContext;
        public KhoaService(ApplicationDbContext dbContext)
        {
            _dbContext = dbContext;
        }

        public void Add(Khoa khoa)
        {
            try
            {
                _dbContext.Khoas.Add(khoa);
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
                Khoa? khoa = _dbContext.Khoas.Find(id);
                if (khoa != null)
                {
                    _dbContext.Khoas.Remove(khoa);
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

        public Khoa Get(string id)
        {
            try
            {
                Khoa? item = _dbContext.Khoas.Find(id);
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

        public List<Khoa> Get()
        {
            try
            {
                return _dbContext.Khoas.ToList();
            }
            catch (Exception e)
            {

                Exception myexception = new Exception(e.Message);
                throw myexception;
            }
        }

        public void Update(Khoa item)
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
