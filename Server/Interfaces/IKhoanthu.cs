using Flic.Shared.Models;

namespace Flic.Server.Interfaces
{
    public interface IKhoanthu
    {
        public List<Khoanthu> Get();
        public bool Add(Khoanthu item);
        public bool Update(Khoanthu item);
        public Khoanthu Get(int id);
        public Khoanthu GetByItem(Khoanthu item);
        public bool Delete(int id);
    }
}
