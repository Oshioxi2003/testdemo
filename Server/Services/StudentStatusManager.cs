using Flic.Server.Data;
using Flic.Server.Interfaces;
using Flic.Shared.Models;
using Microsoft.EntityFrameworkCore;

namespace Flic.Server.Services
{
    public class StudentStatusManager : IStudentStatus
    {
        readonly ApplicationDbContext _dbContext;
        public StudentStatusManager(ApplicationDbContext dbContext)
        {
            _dbContext = dbContext;
        }
        public bool Add(StudentStatus item)
        {
            try
            {
                _dbContext.StudentStatuses.Add(item);
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
                StudentStatus? item = _dbContext.StudentStatuses.Find(id);
                if (item != null)
                {
                    _dbContext.StudentStatuses.Remove(item);
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

        public List<StudentStatus> Get()
        {
            try
            {
                return _dbContext.StudentStatuses.ToList();                
            }
            catch
            {
                throw;
            }
        }

        public StudentStatus Get(string id)
        {
            try
            {
                StudentStatus item = _dbContext.StudentStatuses.Find(id);
                return item;
            }
            catch (Exception e)
            {
                throw;
            }
        }

        public bool Update(StudentStatus item)
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
