using Microsoft.AspNetCore.Mvc;
using System;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace Flic.Server.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UploadController : ControllerBase
    {
        private readonly IWebHostEnvironment environment;

        public UploadController(IWebHostEnvironment environment)
        {
            this.environment = environment;
        }

        // GET: api/<UploadController>
        [HttpGet]
        public IEnumerable<string> Get()
        {
            return new string[] { "value1", "value2" };
        }

        // GET api/<UploadController>/5
        [HttpGet("{id}")]
        public string Get(int id)
        {
            return "value";
        }

        // POST api/<UploadController>
        [HttpPost]
        public void Post([FromBody] string value)
        {
        }
        
        [HttpPost("image")]
        public IActionResult Image(IFormFile file)
        {
            try
            {
                // Used for demo purposes only
                //DeleteOldFiles();

                var fileName = $"img-{DateTime.Today.ToString("yyyy-MM-dd")}-{Guid.NewGuid()}{Path.GetExtension(file.FileName)}";

                var folderName = Path.Combine("StaticFiles", "Images");
                var pathToSave = Path.Combine(Directory.GetCurrentDirectory(), folderName);
                var filePath = Path.Combine(pathToSave, fileName);

                using (var stream = new FileStream(filePath, FileMode.Create))
                {
                    // Save the file
                    file.CopyTo(stream);

                    // Return the URL of the file
                    var url = Url.Content($"~/{folderName}/{fileName}");

                    return Ok(new { Url = url });
                }
            }
            catch (Exception ex)
            {
                return StatusCode(500, ex.Message);
            }
        }
        [HttpPost("single")]
        public IActionResult Single(IFormFile file)
        {
            try
            {
                // Put your code here
                var fileName = $"{DateTime.Today.ToString("yyyy-MM-dd")}-{Guid.NewGuid()}{Path.GetExtension(file.FileName)}";

                var folderName = Path.Combine("StaticFiles", "Images");
                var pathToSave = Path.Combine(Directory.GetCurrentDirectory(), folderName);
                var filePath = Path.Combine(pathToSave, fileName);

                using (var stream = new FileStream(filePath, FileMode.Create))
                {
                    // Save the file
                    file.CopyTo(stream);

                    // Return the URL of the file
                    var url = Url.Content($"~/{folderName}/{fileName}");

                    return Ok(new { Url = url });
                }
                //return Ok(new { Completed = true });
            }
            catch (Exception ex)
            {
                return StatusCode(500, ex.Message);
            }
        }
        [HttpPost("multiple")]
        public IActionResult Multiple(IFormFile[] files)
        {
            try
            {
                // Put your code here
                return StatusCode(200);
            }
            catch (Exception ex)
            {
                return StatusCode(500, ex.Message);
            }
        }

        [HttpPost("{id}")]
        public IActionResult Post(IFormFile[] files, int id)
        {
            try
            {
                // Put your code here
                return StatusCode(200);
            }
            catch (Exception ex)
            {
                return StatusCode(500, ex.Message);
            }
        }

        [HttpPost("specific")]
        public IActionResult Specific(IFormFile myName)
        {
            try
            {
                // Put your code here
                return Ok(new { Completed = true });
            }
            catch (Exception ex)
            {
                return StatusCode(500, ex.Message);
            }
        }
        // PUT api/<UploadController>/5
        [HttpPut("{id}")]
        public void Put(int id, [FromBody] string value)
        {
        }

        // DELETE api/<UploadController>/5
        [HttpDelete("{id}")]
        public void Delete(int id)
        {
        }
    }
}
