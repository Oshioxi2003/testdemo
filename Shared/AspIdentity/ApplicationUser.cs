using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Flic.Shared.AspIdentity
{
    public class ApplicationUser : IdentityUser
    {
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public int UsernameChangeLimit { get; set; } = 10;
        public byte[] ProfilePicture { get; set; }
    }
}
