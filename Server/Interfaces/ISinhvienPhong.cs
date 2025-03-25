using Flic.Shared.Models;

namespace Flic.Server.Interfaces
{   
    public interface ISinhvienPhong
    {
        public List<SinhvienPhongView> Get();
        public bool Add(SinhvienPhong item);
        public bool Update(SinhvienPhong item);
        public SinhvienPhongView Get(int id);
        public bool Delete(int id);
    }
}
