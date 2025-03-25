using Flic.Server.Data;
using Flic.Server.Interfaces;
using Flic.Shared.Models;
using Microsoft.EntityFrameworkCore;

namespace Flic.Server.Services
{
    public class Tin03TrangthaiService:ITin03Trangthai
    {
        readonly ApplicationDbContext _dbContext;
        public Tin03TrangthaiService(ApplicationDbContext dbContext)
        {
            _dbContext = dbContext;
        }

        public bool Add(Tin03_Trangthai item)
        {
            try
            {
                _dbContext.Tin03_Trangthais.Add(item);
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
                Tin03_Trangthai? item = _dbContext.Tin03_Trangthais.Find(id);
                if (item != null)
                {
                    _dbContext.Tin03_Trangthais.Remove(item);
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

        public List<Tin03_Trangthai> Get()
        {
            try
            {
                return _dbContext.Tin03_Trangthais.ToList();
            }
            catch (Exception e)
            {

                Exception myexception = new Exception(e.Message);
                throw myexception;
            }
        }

        public Tin03_Trangthai Get(int id)
        {
            try
            {
                Tin03_Trangthai ? item = _dbContext.Tin03_Trangthais.Find(id);
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

        public bool Update(Tin03_Trangthai item)
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
