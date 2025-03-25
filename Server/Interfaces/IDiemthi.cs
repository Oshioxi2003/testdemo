using Flic.Shared.Models;

namespace Flic.Server.Interfaces
{
    public interface IDiemthi
    {
        public List<Diemthi> Get();
        public bool Add(Diemthi item);
        public bool Update(Diemthi item);
        public Diemthi Get(string id);
        public bool Delete(string id);
    }
}
