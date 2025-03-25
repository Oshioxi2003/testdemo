using Flic.Shared.Models;

namespace Flic.Server.Interfaces
{
    public interface IStudent
    {
        public StudentSearchOption GetStudent(StudentSearchOption op);
        public List<Student> GetStudentList(string khoahoc=null);
        public string AddStudent(Student user);
        public string UpdateStudent(Student user);
        public Student GetStudent(int id);
        public Student GetStudentByMSV(string id);
        public string DeleteStudent(int id);
        public int NotExist(Student usr);
    }
}
