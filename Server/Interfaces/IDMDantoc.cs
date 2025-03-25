using Flic.Shared.Models;

namespace Flic.Server.Interfaces
{
    public interface IDMDantoc
    {
        public List<DMDantoc> Get();
        public bool Add(DMDantoc item);
        public bool Update(DMDantoc item);
        public DMDantoc Get(int id);
        public bool Delete(int id);
    }
}
