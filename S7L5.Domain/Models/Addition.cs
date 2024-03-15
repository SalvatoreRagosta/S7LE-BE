using System.ComponentModel.DataAnnotations;

namespace PizzeriaImpulsMVC.Domain.Models
{
    public class Addition
    {
        public int Id { get; set; }

        [Required]
        [MaxLength(50)]
        public string? Name { get; set; }

        [Required]
        public int Price { get; set; }

        [MaxLength(50)]
        public string? ImgPath { get; set; }
    }
}
