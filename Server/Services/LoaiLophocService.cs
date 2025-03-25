using Flic.Server.Data;
using Flic.Server.Interfaces;
using Flic.Shared.Models;
using Microsoft.EntityFrameworkCore;

namespace Flic.Server.Services
{
    public class LoaiLophocService : ILoaiLophoc
    {
        readonly ApplicationDbContext _dbContext;
        public LoaiLophocService(ApplicationDbContext dbContext)
        {
            _dbContext = dbContext;
        }
        public string Add(LoaiLophoc item)
        {
            try
            {
                Guid g = Guid.NewGuid();                
                item.guid = g.ToString();
                _dbContext.LoaiLophocs.Add(item);
                _dbContext.SaveChanges();                
                return item.Id;
            }
            catch (Exception e)
            {
                throw new InvalidOperationException(e.Message);
            }
        }

        public string Delete(string id)
        {
            try
            {
                LoaiLophoc item = _dbContext.LoaiLophocs.Find(id);
                if (item != null)
                {
                    _dbContext.LoaiLophocs.Remove(item);
                    _dbContext.SaveChanges();
                    return item.Id;
                }
                else
                {
                    throw new InvalidOperationException("Xóa bản ghi không thành công!");
                }
            }
            catch (Exception e)
            {
                throw new InvalidOperationException(e.Message);
            }
        }

        public List<LoaiLophoc> Get()
        {
            try
            {
                return _dbContext.LoaiLophocs.ToList();
            }
            catch (Exception e)
            {

                Exception myexception = new Exception(e.Message);
                throw myexception;
            }
        }

        public LoaiLophoc Get(string id)
        {
            try
            {
                LoaiLophoc? item = _dbContext.LoaiLophocs.Find(id);
                if (item != null)
                {
                    return item;
                }
                else
                {
                    throw new ArgumentNullException("Không tìm thấy bản ghi!");
                }
            }
            catch (Exception ex)
            {
                throw new ArgumentNullException(ex.Message);
            }
        }

        public List<LoaiLophoc> GetActive()
        {
            try
            {
                return _dbContext.LoaiLophocs.Where(m => m.Trangthai == 1).ToList();
            }
            catch (Exception e)
            {

                Exception myexception = new Exception(e.Message);
                throw myexception;
            }
        }

        public LoaiLophoc GetGuid(string gid)
        {
            try
            {
                return _dbContext.LoaiLophocs.Where(m => m.guid.Equals(gid)).FirstOrDefault();
            }
            catch (Exception e)
            {

                Exception myexception = new Exception(e.Message);
                throw myexception;
            }
        }

        public List<LoaiLophoc> GetInActive()
        {
            try
            {
                return _dbContext.LoaiLophocs.Where(m => m.Trangthai == 0).ToList();
            }
            catch (Exception e)
            {

                Exception myexception = new Exception(e.Message);
                throw myexception;
            }
        }

        public string Update(LoaiLophoc item)
        {
            try
            {
                _dbContext.Entry(item).State = EntityState.Modified;
                _dbContext.SaveChanges();
                return item.Id;
            }
            catch (Exception e)
            {
                throw new InvalidOperationException(e.Message);
            }
        }
    }
}
