using Flic.Server.Data;
using Flic.Server.Interfaces;
using Flic.Shared.Models;
using Microsoft.EntityFrameworkCore;

namespace Flic.Server.Services
{
    public class SectionService:ISection
    {
        readonly ApplicationDbContext _dbContext;
        public SectionService(ApplicationDbContext dbContext)
        {
            _dbContext = dbContext;
        }

        public void Add(Section item)
        {
            try
            {
                _dbContext.Sections.Add(item);
                _dbContext.SaveChanges();
            }
            catch
            {
                throw;
            }
        }

        public void Delete(int id)
        {
            try
            {
                Section? item = _dbContext.Sections.Find(id);
                if (item != null)
                {
                    _dbContext.Sections.Remove(item);
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

        public Section Get(int id)
        {
            try
            {
                Section? item = _dbContext.Sections.Find(id);
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

        public List<Section> Get()
        {
            try
            {
                return _dbContext.Sections.ToList();
            }
            catch (Exception e)
            {

                Exception myexception = new Exception(e.Message);
                throw myexception;
            }
        }

        public void Update(Section item)
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
