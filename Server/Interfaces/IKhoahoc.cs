using Flic.Shared.Models;

namespace Flic.Server.Interfaces
{
    public interface IKhoahoc
    {
        public List<Khoahoc> Get();
        public void Add(Khoahoc khoa);
        public void Update(Khoahoc khoa);
        public Khoahoc Get(string id);
        public void Delete(string id);
    }
}
