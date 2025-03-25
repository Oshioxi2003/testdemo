using Flic.Shared.Models;

namespace Flic.Server.Interfaces
{
    public interface IStudentStatus
    {
        public List<StudentStatus> Get();
        public bool Add(StudentStatus item);
        public bool Update(StudentStatus item);
        public StudentStatus Get(string id);
        public bool Delete(string id);
    }
}
