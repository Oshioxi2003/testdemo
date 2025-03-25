using Flic.Shared.Models;

namespace Flic.Server.Interfaces
{
    public interface ILop
    {
        public List<Lop> Get();
        public void Add(Lop item);
        public void Update(Lop item);
        public Lop Get(string id);
        public void Delete(string id);
    }
}
