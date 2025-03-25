using Flic.Shared.Models;

namespace Flic.Server.Interfaces
{
    public interface IDKHoc
    {
        public List<DKHoc> Get();
        public DKHocQueryResult GetListView(string khoahocs);
        public List<DKHoc> GetActive();
        public List<DKHoc> GetInActive();
        public int Add(DKHoc item);
        public int Update(DKHoc item);
        public DKHoc Get(int id);
        public List<DKHoc> GetByCCCD(string cccd);
        public List<DKHoc> GetByMobile(string mobile);
        public List<DKHoc> GetByEmail(string email);

        public DKHoc GetGuid(string gid);
        public void Delete(int id);
    }
}
