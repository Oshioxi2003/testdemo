using Flic.Server.Interfaces;
using Flic.Shared.Models;
using Flic.Server.Data;
using Microsoft.EntityFrameworkCore;
using NPOI.HSSF.Record.Chart;

namespace Flic.Server.Services
{
    public class StudentManager : IStudent
    {
        readonly ApplicationDbContext _dbContext;
        public StudentManager(ApplicationDbContext dbContext)
        {
            _dbContext = dbContext;
        }

        public string AddStudent(Student user)
        {
            try
            {
                _dbContext.Students.Add(user);
                _dbContext.SaveChanges();
                return "TRUE";
            }
            catch (Exception ex)
            {
                return ex.Message;
            }
        }

        public string DeleteStudent(int id)
        {
            try
            {
                Student? user = _dbContext.Students.Find(id);
                if (user != null)
                {
                    _dbContext.Students.Remove(user);
                    _dbContext.SaveChanges();
                    return "TRUE";
                }
                else
                {
                    //throw new ArgumentNullException();
                    return "ERROR: Can not find user Id " + id.ToString();
                }
            }
            catch
            {
                return "ERROR: Can not DELETE user Id " + id.ToString();
            }
        }

        public Student GetStudent(int id)
        {
            try
            {
                Student? user = _dbContext.Students.Find(id);
                if (user != null)
                {
                    return user;
                }
                else
                {
                    return user;
                }
            }
            catch
            {
                throw new ArgumentNullException();
            }
        }
        public Student GetStudentByMSV(string id)
        {            
            return _dbContext.Students.Where(m=>m.MaSV == id).FirstOrDefault();                
        }
        public StudentSearchOption GetStudent(StudentSearchOption op)
        {
            try
            {
                var list= _dbContext.Students.ToList();
                if (op.KhoahocID != null && op.KhoahocID != "")
                {
                    list = list.Where(m => m.KhoahocID == op.KhoahocID).ToList();
                }
                if (op.KhoaID != null && op.KhoaID != "" )
                {
                    list = list.Where(m => m.KhoaID == op.KhoaID).ToList();
                }
                if (op.NganhID != null && op.NganhID !="")
                {
                    list = list.Where(m => m.NganhID == op.NganhID).ToList();
                }
                if (op.LopID != null && op.LopID !="")
                {
                    list = list.Where(m => m.LopID == op.LopID).ToList();
                }
                if (op.Trangthai != null && op.Trangthai != "")
                {
                    list = list.Where(m => m.Trangthai == op.Trangthai).ToList();
                }
                if (op.KeyWord != null && op.KeyWord != "")
                {
                    string k = op.KeyWord.ToUpper();
                    list = list.Where(m => (m.HoDem!=null && m.HoDem.ToUpper().Contains(k))
                    || ( m.Ten!=null && m.Ten.ToUpper().Contains(k) )
                    || ( m.MaSV!=null &&  m.MaSV.Contains(k))
                    || ( m.CCCD!=null && m.CCCD.Contains(k) )
                    || ( m.DienThoai!=null && m.DienThoai.Contains(k) )
                    || ( m.Email!=null && m.Email.ToUpper().Contains(k))
                    ).ToList();
                }
                if (op.Page == null) op.Page = 1;
                if (op.Pagesize != -1)
                {
                    if (op.Pagesize == null) op.Pagesize = 60;
                    var count = list.Count();
                    op.NumPage = count / op.Pagesize + (count % op.Pagesize != 0 ? 1 : 0);
                    int skip = (op.Page.Value - 1) * op.Pagesize.Value;
                    int pSize = op.Pagesize.Value;

                    list = list.Skip(skip).Take(pSize).ToList();
                }
                
                op.student_list = list;
                return op;
            }
            catch (Exception e)                        
            {
                
                Exception myexception = new Exception(e.Message);
                throw myexception;
            }
        }
        public List<Student> GetStudentList(string khoahoc = null)
        {
            try
            {
                var _khoahoc = khoahoc.Split(';').ToList();
                var list = _dbContext.Students.Where(t => _khoahoc.Contains(t.KhoahocID)).ToList();

                return list;
            }
            catch (Exception e)
            {

                Exception myexception = new Exception(e.Message);
                throw myexception;
            }
        }
        public string UpdateStudent(Student user)
        {
            try
            {
                _dbContext.Entry(user).State = EntityState.Modified;
                _dbContext.SaveChanges();
                return "TRUE";
            }
            catch (Exception e)
            {
                return "ERROR: Can not update user Id " + user.id.ToString() + " " + e.Message;
            }
        }
        public int NotExist(Student usr)
        {
            var u = _dbContext.Students.Where(m => m.MaSV != null && usr.MaSV != null && m.MaSV == usr.MaSV).FirstOrDefault();
            if (u == null)
            {
                return -1;
            }
            return u.id;
        }
    }
}
