using Flic.Shared.Models;

namespace Flic.Server.Interfaces
{    
    public interface ILoaiKhoanthu
    {
        public List<LoaiKhoanthu> Get();
        public bool Add(LoaiKhoanthu item);
        public bool Update(LoaiKhoanthu item);
        public LoaiKhoanthu Get(string id);
        public bool Delete(string id);
    }
}
