using Flic.Shared.Models;

namespace Flic.Server.Interfaces
{
    public interface ILoaiLophoc
    {
        public List<LoaiLophoc> Get();
        public List<LoaiLophoc> GetActive();
        public List<LoaiLophoc> GetInActive();
        public string Add(LoaiLophoc item);
        public string Update(LoaiLophoc item);
        public LoaiLophoc Get(string id);
        public LoaiLophoc GetGuid(string gid);
        public string Delete(string id);
    }
}
