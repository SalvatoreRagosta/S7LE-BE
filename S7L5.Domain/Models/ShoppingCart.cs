using System.ComponentModel.DataAnnotations;

namespace PizzeriaImpulsMVC.Domain.Models;

public class ShoppingCart
{
    [Key]
    public int RecordId { get; set; }

    public int CartId { get; set; }
    [Required]
    public string UserId { get; set; }

    [Required]
    public int ProductId { get; set; }

    [Required]
    [MaxLength(50)]
    public string ProductName { get; set; }

    public decimal? ProductSize { get; set; }

    [Required]
    public int ProductCount { get; set; }

    [Required]
    [MaxLength(50)]
    public string ProductType { get; set; }

    [Required]
    public decimal UnitPrice { get; set; }

    [Required]
    public decimal Price { get; set; }

    [Required]
    public DateTime CreatedAt { get; set; }
    
}