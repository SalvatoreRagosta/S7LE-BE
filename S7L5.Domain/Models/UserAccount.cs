using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace PizzeriaImpulsMVC.Domain.Models
{
    public class UserAccount : IdentityUser
    {
        [Required]
        [MaxLength(50)]
        public string FirstName { get; set; }

        [Required]
        [MaxLength(50)]
        public string LastName { get; set; }

        [Required]
        public DateOnly DateOfBirth { get; set; }

        public DateTime RegistrationDate { get; set; }

        public bool IsActive { get; set; }

        public int UserAddressId { get; set; }

        public UserAddress UserAddress { get; set; }
    }
}
