using Flic.Shared.Models;

namespace Flic.Server.Interfaces
{
    
    public interface IKyThanhtoan
    {
        public List<KyThanhtoan> Get();
        public List<KyThanhtoan> GetByKhoanthu(string kt);
        public bool Add(KyThanhtoan item);
        public bool Update(KyThanhtoan item);
        public KyThanhtoan Get(string id);
        public bool Delete(string id);
    }
}
