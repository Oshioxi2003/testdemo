using Flic.Shared.Models;

namespace Flic.Server.Interfaces
{
    public interface IDotthi
    {
        public List<Dotthi> Get();
        public bool Add(Dotthi item);
        public bool Update(Dotthi item);
        public Dotthi Get(string id);
        public bool Delete(string id);
    }
}
