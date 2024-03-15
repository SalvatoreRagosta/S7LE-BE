using System.ComponentModel.DataAnnotations;

namespace PizzeriaImpulsMVC.Domain.Models
{
    public class UserAddress
    {
        public int Id { get; set; }

        [Required]
        [MaxLength(50)]
        public string Country { get; set; }

        [Required]
        [MaxLength(50)]
        public string City { get; set; }

        [Required]
        [MaxLength(50)]
        public string Street { get; set; }

        [Required]
        public int HomeNumber { get; set; }

        [Required]
        public int ApartmentNumber { get; set; }

        public UserAccount UserAccount { get; set; }
    }
}
