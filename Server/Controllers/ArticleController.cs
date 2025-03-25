using Flic.Server.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Flic.Shared.Models;
using DinkToPdf.EventDefinitions;

namespace Flic.Server.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ArticleController : Controller
    {
        private readonly IArticle _Interface;
        public ArticleController(IArticle _Int)
        {
            _Interface = _Int;
        }

        [HttpGet("ArticleGetList")]
        public async Task<List<Article>> ArticleGetList()
        {            
            return await Task.FromResult(_Interface.Get());
        }

        [HttpGet("ArticleGetListBySection/{Id}/")]
        public async Task<List<Article>> ArticleGetListBySection(int Id)
        {
            return await Task.FromResult(_Interface.GetBySection(Id));
        }
        [HttpGet("ArticleGetListBySection/{Id}/{limit}")]
        public async Task<List<Article>> ArticleGetListBySectionLimit(int Id, int limit)
        {
            return await Task.FromResult(_Interface.GetBySection(Id, limit));
        }
        [HttpGet("ArticleGetByID/{id}")]
        public IActionResult ArticleGetByID(int id)
        {
            Article item = _Interface.Get(id);
            if (item != null)
            {
                return Ok(item);
            }
            return NotFound();
        }
        //[Authorize]
        [HttpPost("ArticleAdd")]
        public async Task<IActionResult> ArticleAdd(Article item)
        {
            try
            {
                _Interface.Add(item);
                return Ok(item);
            }
            catch (Exception e)
            {
                //return BadRequest();
                return BadRequest(e.Message + " - " + e.InnerException);            
            }
        }
        [Authorize]
        [HttpPut("ArticleUpdate")]
        public void ArticleUpdate(Article item)
        {
            _Interface.Update(item);
        }
        [Authorize]
        [HttpDelete("ArticleDelete/{id}")]
        public bool ArticleDelete(int id)
        {
            try
            {
                _Interface.Delete(id);
                return true;
            }
            catch (Exception e)
            {
                Console.WriteLine("ERROR: Delete Lop ID " + id + " " + e.Message);
                return false;
            }

        }
    }
}
