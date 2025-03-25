using Flic.Shared.Models;

namespace Flic.Server.Interfaces
{
    public interface IArticle
    {
        public List<Article> Get();
        public List<Article> GetBySection(int Id, int limit );
        public List<Article> GetBySection(int Id);
        public void Add(Article item);
        public void Update(Article item);
        public Article Get(int id);
        public void Delete(int id);
    }
}
