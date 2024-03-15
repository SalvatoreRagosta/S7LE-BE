using System.ComponentModel.DataAnnotations;

namespace PizzeriaImpulsMVC.Domain.Models
{
    public class Drink
    {
        public int Id { get; set; }

        [Required]
        [MaxLength(50)]
        public string? Name { get; set; }

        [Required]
        public int Price { get; set; }

        [Required]
        public decimal Size { get; set; }

        [MaxLength(50)]
        public string? ImgPath { get; set; }
    }
}
