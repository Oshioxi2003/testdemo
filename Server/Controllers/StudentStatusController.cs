using Flic.Server.Interfaces;
using Flic.Shared.Models;
using Microsoft.AspNetCore.Mvc;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace Flic.Server.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class StudentStatusController : ControllerBase
    {
        private readonly IStudentStatus _IStudentStatus;
        public StudentStatusController(IStudentStatus IStudentStatus)
        {
            _IStudentStatus = IStudentStatus;
        }
        [HttpGet("StudentStatusGetList")]
        public async Task<List<StudentStatus>> StudentStatusGetList()
        {
            return await Task.FromResult(_IStudentStatus.Get());
        }
        [HttpGet("StudentStatusGetByID/{id}")]
        public IActionResult StudentStatusGetByID(string id)
        {
            StudentStatus item = _IStudentStatus.Get(id);
            if (item != null)
            {
                return Ok(item);
            }
            return NotFound();
        }
        [HttpPost("StudentStatusAdd")]
        public async Task<IActionResult> StudentStatusAdd(StudentStatus item)
        {
            try
            {
                _IStudentStatus.Add(item);
                return Ok(item);
            }
            catch (Exception e)
            {
                return BadRequest();
            }
        }
        [HttpPut("StudentStatusUpdate")]
        public bool StudentStatusUpdate(StudentStatus item)
        {
            try
            {
                _IStudentStatus.Update(item);
                return true;
            }
            catch (Exception e)
            {
                Console.WriteLine("Error update Khoa " + e.Message);
                return false;
            }

        }
        [HttpDelete("StudentStatusDelete/{id}")]
        public bool StudentStatusDelete(string id)
        {
            try
            {
                _IStudentStatus.Delete(id);
                return true;
            }
            catch (Exception e)
            {
                Console.WriteLine("Delete Khoa ID" + id.ToString() + " Error: " + e.Message);
                return false;
            }

        }
    }
}
