using Flic.Server.Data;
using Flic.Server.Interfaces;
using Flic.Shared.Models;
using Microsoft.EntityFrameworkCore;

namespace Flic.Server.Services
{
    public class ArticleService:IArticle
    {
        readonly ApplicationDbContext _dbContext;
        public ArticleService(ApplicationDbContext dbContext)
        {
            _dbContext = dbContext;
        }

        public void Add(Article item)
        {
            try
            {
                _dbContext.Articles.Add(item);
                _dbContext.SaveChanges();
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                throw;
            }
        }

        public void Delete(int id)
        {
            try
            {
                Article? item = _dbContext.Articles.Find(id);
                if (item != null)
                {
                    _dbContext.Articles.Remove(item);
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

        public Article Get(int id)
        {
            try
            {
                Article? item = _dbContext.Articles.Find(id);
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
        public List<Article> GetBySection(int Id, int limit)
        {
            try
            {   
                return _dbContext.Articles.Where(m => m.SectionId != null && m.SectionId == Id).OrderByDescending(m => m.CreateDate).Take(limit).ToList();                                
            }
            catch (Exception e)
            {

                Exception myexception = new Exception(e.Message);
                throw myexception;
            }
        }
        public List<Article> GetBySection(int Id)
        {
            try
            {                
                return _dbContext.Articles.Where(m => m.SectionId != null && m.SectionId == Id).OrderByDescending(m => m.CreateDate).ToList();                

            }
            catch (Exception e)
            {

                Exception myexception = new Exception(e.Message);
                throw myexception;
            }
        }
        public List<Article> Get()
        {
            try
            {
                return _dbContext.Articles.OrderByDescending(m => m.CreateDate).ToList();
            }
            catch (Exception e)
            {

                Exception myexception = new Exception(e.Message);
                throw myexception;
            }
        }

        public void Update(Article item)
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
