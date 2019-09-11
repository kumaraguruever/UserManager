using System.ComponentModel.DataAnnotations;

namespace CoreUserManagementDemo.Models.Account
{
    public class ExternalLoginViewModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }
}
