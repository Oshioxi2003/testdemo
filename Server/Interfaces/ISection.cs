using Flic.Shared.Models;

namespace Flic.Server.Interfaces
{
    public interface ISection
    {
        public List<Section> Get();
        public void Add(Section item);
        public void Update(Section item);
        public Section Get(int id);
        public void Delete(int id);
    }
}
