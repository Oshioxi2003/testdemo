using Flic.Shared.Models;

namespace Flic.Server.Interfaces
{    
    public interface ILophoc
    {
        public List<Lophoc> Get();
        public List<Lophoc> GetActive();
        public List<Lophoc> GetInActive();
        public List<Lophoc> GetListByLoaiLop(string loaiLop);
        
        public string Add(Lophoc item);
        public string Update(Lophoc item);
        public Lophoc Get(int id);
        public string Delete(int id);
    }
}
