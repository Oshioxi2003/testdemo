using Flic.Shared.Models;

namespace Flic.Server.Interfaces
{    
    public interface IPhongKTX
    {
        public List<PhongKTX> Get();
        public bool Add(PhongKTX item);
        public bool Update(PhongKTX item);
        public PhongKTX Get(string id);
        public bool Delete(string id);
    }
}
