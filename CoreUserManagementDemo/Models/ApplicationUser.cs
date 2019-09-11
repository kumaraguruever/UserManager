using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Threading.Tasks;

namespace CoreUserManagementDemo.Models
{
    [Table("AspNetUsers")]
    public class ApplicationUser : IdentityUser
    {
        public string EmailAddress2 { get; set; }
    }
}
