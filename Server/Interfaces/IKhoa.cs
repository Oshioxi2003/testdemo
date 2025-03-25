using Flic.Shared.Models;

namespace Flic.Server.Interfaces
{
    public interface IKhoa
    {
        public List<Khoa> Get();
        public void Add(Khoa khoa);
        public void Update(Khoa khoa);
        public Khoa Get(string id);
        public void Delete(string id);
    }
}
