using Flic.Server.Data;
using Flic.Server.Interfaces;
using Flic.Shared.Models;
using Microsoft.EntityFrameworkCore;

namespace Flic.Server.Services
{
    public class DiemthiService:IDiemthi
    {
        readonly ApplicationDbContext _dbContext;
        public DiemthiService(ApplicationDbContext dbContext)
        {
            _dbContext = dbContext;
        }

        public bool Add(Diemthi item)
        {
            try
            {
                _dbContext.Diemthis.Add(item);
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
                Diemthi? item = _dbContext.Diemthis.Find(id);
                if (item != null)
                {
                    _dbContext.Diemthis.Remove(item);
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

        public List<Diemthi> Get()
        {
            try
            {
                return _dbContext.Diemthis.ToList();
            }
            catch (Exception e)
            {

                Exception myexception = new Exception(e.Message);
                throw myexception;
            }
        }

        public Diemthi Get(string id)
        {
            try
            {
                Diemthi? item = _dbContext.Diemthis.Find(id);
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

        public bool Update(Diemthi item)
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
