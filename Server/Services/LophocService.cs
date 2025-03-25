using Flic.Server.Data;
using Flic.Server.Interfaces;
using Flic.Shared.Models;
using Microsoft.EntityFrameworkCore;

namespace Flic.Server.Services
{
    public class LophocService: ILophoc
    {
        readonly ApplicationDbContext _dbContext;
        public LophocService(ApplicationDbContext dbContext)
        {
            _dbContext = dbContext;
        }

        public string Add(Lophoc item)
        {
            try
            {
                _dbContext.Lophocs.Add(item);
                _dbContext.SaveChanges();
                return "Success:" + item.Id.ToString();
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }
        }

        public string Delete(int id)
        {
            try
            {
                Lophoc? item = _dbContext.Lophocs.Find(id);
                if (item != null)
                {
                    _dbContext.Lophocs.Remove(item);
                    _dbContext.SaveChanges();
                    return "Success";
                }
                else
                {
                    throw new ArgumentNullException();
                }
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }
        }

        public Lophoc Get(int id)
        {
            try
            {
                Lophoc? item = _dbContext.Lophocs.Find(id);
                if (item != null)
                {
                    return item;
                }
                else
                {
                    throw new ArgumentNullException();
                }
            }
            catch (Exception ex) 
            {
                throw new Exception(ex.Message);
            }
        }

        public List<Lophoc> Get()
        {
            try
            {
                return _dbContext.Lophocs.ToList();
            }
            catch (Exception e)
            {

                Exception myexception = new Exception(e.Message);
                throw myexception;
            }
        }
        public List<Lophoc> GetActive()
        {
            try
            {
                return _dbContext.Lophocs.Where(m=>m.Trangthai ==1 ).ToList();
            }
            catch (Exception e)
            {

                Exception myexception = new Exception(e.Message);
                throw myexception;
            }
        }
        public List<Lophoc> GetInActive()
        {
            try
            {
                return _dbContext.Lophocs.Where(m => m.Trangthai == 0).ToList();
            }
            catch (Exception e)
            {

                Exception myexception = new Exception(e.Message);
                throw myexception;
            }
        }
        public List<Lophoc> GetListByLoaiLop(string loaiLop)
        {
            try
            {
                List<string> _loaiLop = new List<string> (loaiLop.Split(';'));
                return _dbContext.Lophocs.Where(m => m.Trangthai == 1).Where(m => m.LoaiLop!=null && _loaiLop.Contains(m.LoaiLop)).ToList();
            }
            catch (Exception e)
            {

                Exception myexception = new Exception(e.Message);
                throw myexception;
            }
        }
        public string Update(Lophoc item)
        {
            try
            {
                _dbContext.Entry(item).State = EntityState.Modified;
                _dbContext.SaveChanges();
                return "Success";
            }
            catch (Exception ex) 
            {
                throw new Exception (ex.Message);
            }
        }
    }
}
