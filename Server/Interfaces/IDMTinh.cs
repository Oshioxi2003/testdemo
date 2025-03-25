using Flic.Shared.Models;

namespace Flic.Server.Interfaces
{
    public interface IDMTinh
    {
        public List<DMTinh> Get();
        public bool Add(DMTinh item);
        public bool Update(DMTinh item);
        public DMTinh Get(int id);
        public bool Delete(int id);
    }
}
