using Flic.Shared.Models;

namespace Flic.Server.Interfaces
{
    public interface IDangkyTH03
    {
        public List<DangkyTH03> Get();
        public List<DangkyTH03_View> GetListView(string dotthi=null);
        public List<DangkyTH03> Search(DangkyTH03_View item);
        public int Add(DangkyTH03 item);
        public int LapDS(LapDSTinhoc item);
        public List<DangkyTH03_View> GetDSPhongthi(string p);
        public List<DangkyTH03_View> GetDSDangky(string p);
        public List<DangkyTH03_View> GetDSDuDK(string p);
        public List<DangkyTH03_View> GetKetqua(string p);
        public List<DangkyTH03_View> GetSocapCC(string p);


        public bool Update(DangkyTH03 item);
        public bool UpdateDiemthi(DangkyTH03 item);
        public bool ChangeDuDKState(ChangeDuDKState item);
        public DangkyTH03 Get(int id);
        public DangkyTH03_View GetView(int id);
        public DangkyTH03 GetByCCCD(string cccd);
        public DangkyTH03 DangkyTH03Import(string sdb,  string madotthi);
        public DangkyTH03 DangkyTH03Import(string sdb, string cccd, string madotthi);
        public DangkyTH03 DangkyTH03FindPhach(string sp, string madotthi);
        public bool Delete(int id);
    }
}
