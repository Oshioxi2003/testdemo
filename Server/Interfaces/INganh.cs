using Flic.Shared.Models;


namespace Flic.Server.Interfaces
{
    public interface INganh
    {
        public List<Nganh> Get();
        public void Add(Nganh item);
        public void Update(Nganh item);
        public Nganh Get(string id);
        public void Delete(string id);
    }
}
