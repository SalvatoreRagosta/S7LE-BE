using System.ComponentModel.DataAnnotations;

namespace PizzeriaImpulsMVC.Domain.Models;

public class OrderDetail
{
    public int Id { get; set; }

    public int OrderId { get; set; }

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