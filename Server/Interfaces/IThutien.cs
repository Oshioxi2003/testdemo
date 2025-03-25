using Flic.Shared.Models;

namespace Flic.Server.Interfaces
{
    public interface IThutien
    {
        public List<ThuTienView> Get();
        public List<ThuTienView> GetByKyThanhtoan(string loaikhoanthu, string kythanhtoan);
        public ThutienSearchOption GetThutiens(ThutienSearchOption op);
        public List<ThuTienView> GetThutienExport(ThutienSearchOption op);
        public bool Add(ThuTien item);
        public bool Update(ThuTien item);
        public bool AddFromView(ThuTienView item);
        public bool UpdateFromView(ThuTienView item);
        public bool ThanhtoanByID(int id);
        public bool LapDS(ThuTienView item);
        public bool LapDS_KTX(ThuTienView item);
        public ThuTienView Get(int id);
        public ThuTien GetById(int id);
        public List<ThuTien> GetByStudentId(int stdId);
        public List<ThuTienView> GetByMSV(string msv);
        public bool ThanhtoanByMSV(string msv);
        public bool Delete(int id);
    }
}
