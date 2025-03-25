using Flic.Shared.Models;

namespace Flic.Server.Interfaces
{
    public interface ITin03Trangthai
    {
        public List<Tin03_Trangthai> Get();
        public bool Add(Tin03_Trangthai item);
        public bool Update(Tin03_Trangthai item);
        public Tin03_Trangthai Get(int id);
        public bool Delete(int id);
    }
}
